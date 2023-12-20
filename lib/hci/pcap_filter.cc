/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hci/pcap_filter.h"

#include <packet_runtime.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include "log.h"
#include "packets/hci_packets.h"

using namespace bluetooth::hci;

namespace rootcanal {

static pdl::packet::slice create_packet_view(
    std::vector<uint8_t> const& packet) {
  // Wrap the reference to the packet in a shared_ptr with created
  // a no-op deleter. The packet view will be short lived so there is no
  // risk of the reference leaking.
  return pdl::packet::slice(std::shared_ptr<std::vector<uint8_t> const>(
      &packet, [](std::vector<uint8_t> const* /* ptr */) {}));
}

static std::vector<uint8_t> FilterHciAcl(std::vector<uint8_t> const& packet);
static std::vector<uint8_t> FilterHciSco(std::vector<uint8_t> const& packet);
static std::vector<uint8_t> FilterHciIso(std::vector<uint8_t> const& packet);

std::vector<uint8_t> PcapFilter::FilterHciPacket(
    std::vector<uint8_t> const& packet, uint8_t idc) {
  switch (idc) {
    case 0x1:
      return FilterHciCommand(packet);
    case 0x2:
      return FilterHciAcl(packet);
    case 0x3:
      return FilterHciSco(packet);
    case 0x4:
      return FilterHciEvent(packet);
    case 0x5:
      return FilterHciIso(packet);
    default:
      break;
  }
  return std::vector<uint8_t>(packet);
}

std::vector<uint8_t> PcapFilter::FilterHciCommand(
    std::vector<uint8_t> const& packet) {
  auto command = CommandView::Create(create_packet_view(packet));
  ASSERT(command.IsValid());
  switch (command.GetOpCode()) {
    case OpCode::WRITE_LOCAL_NAME:
      return FilterWriteLocalName(command);
    case OpCode::WRITE_EXTENDED_INQUIRY_RESPONSE:
      return FilterWriteExtendedInquiryResponse(command);
    case OpCode::LE_SET_ADVERTISING_DATA:
      return FilterLeSetAdvertisingData(command);
    case OpCode::LE_SET_SCAN_RESPONSE_DATA:
      return FilterLeSetScanResponseData(command);
    case OpCode::LE_SET_EXTENDED_ADVERTISING_DATA:
      return FilterLeSetExtendedAdvertisingData(command);
    case OpCode::LE_SET_EXTENDED_SCAN_RESPONSE_DATA:
      return FilterLeSetExtendedScanResponseData(command);
    case OpCode::LE_SET_PERIODIC_ADVERTISING_DATA:
      return FilterLeSetPeriodicAdvertisingData(command);
    default:
      break;
  }
  return std::vector<uint8_t>(packet);
}

std::vector<uint8_t> PcapFilter::FilterHciEvent(
    std::vector<uint8_t> const& packet) {
  auto event = EventView::Create(create_packet_view(packet));
  ASSERT(event.IsValid());
  switch (event.GetEventCode()) {
    case EventCode::LE_META_EVENT: {
      auto le_meta_event = LeMetaEventView::Create(event);
      ASSERT(le_meta_event.IsValid());
      switch (le_meta_event.GetSubeventCode()) {
        case SubeventCode::ADVERTISING_REPORT:
          return FilterLeAdvertisingReport(le_meta_event);
        case SubeventCode::EXTENDED_ADVERTISING_REPORT:
          return FilterLeExtendedAdvertisingReport(le_meta_event);
        default:
          break;
      }
      break;
    }
    case EventCode::COMMAND_COMPLETE: {
      auto command_complete = CommandCompleteView::Create(event);
      ASSERT(command_complete.IsValid());
      switch (command_complete.GetCommandOpCode()) {
        case OpCode::READ_LOCAL_NAME:
          return FilterReadLocalNameComplete(command_complete);
        case OpCode::READ_EXTENDED_INQUIRY_RESPONSE:
          return FilterReadExtendedInquiryResponseComplete(command_complete);
        default:
          break;
      }
      break;
    }
    case EventCode::REMOTE_NAME_REQUEST_COMPLETE:
      return FilterRemoteNameRequestComplete(event);
    case EventCode::EXTENDED_INQUIRY_RESULT:
      return FilterExtendedInquiryResult(event);
    default:
      break;
  }
  return std::vector<uint8_t>(packet);
}

static std::vector<uint8_t> FilterHciAcl(std::vector<uint8_t> const& packet) {
  auto acl = AclView::Create(create_packet_view(packet));
  std::vector<uint8_t> payload;
  payload.resize(acl.GetPayload().size());
  ASSERT(acl.IsValid());
  return AclBuilder::Create(acl.GetHandle(), acl.GetPacketBoundaryFlag(),
                            acl.GetBroadcastFlag(), std::move(payload))
      ->SerializeToBytes();
}

static std::vector<uint8_t> FilterHciSco(std::vector<uint8_t> const& packet) {
  auto sco = ScoView::Create(create_packet_view(packet));
  std::vector<uint8_t> data;
  data.resize(sco.GetData().size());
  ASSERT(sco.IsValid());
  return ScoBuilder::Create(sco.GetHandle(), sco.GetPacketStatusFlag(), data)
      ->SerializeToBytes();
}

static std::vector<uint8_t> FilterHciIso(std::vector<uint8_t> const& packet) {
  auto iso = IsoView::Create(create_packet_view(packet));
  std::vector<uint8_t> payload;
  payload.resize(iso.GetPayload().size());
  ASSERT(iso.IsValid());
  return IsoBuilder::Create(iso.GetConnectionHandle(), iso.GetPbFlag(),
                            iso.GetTsFlag(), std::move(payload))
      ->SerializeToBytes();
}

// Replace device names in GAP entries.
// TODO: extended advertising reports can be chunked across multiple
// events, and a single GAP data entry can be segmented in two.
// The filter should account for that and keep a state for partial
// GAP entries.
void PcapFilter::FilterGapData(uint8_t* gap_data, size_t gap_data_len) {
  size_t offset = 0;
  while ((offset + 2) <= gap_data_len) {
    size_t length = gap_data[offset];
    GapDataType data_type = static_cast<GapDataType>(gap_data[offset + 1]);

    // Truncated entry.
    if ((offset + length + 1) > gap_data_len) {
      break;
    }

    // Empty entry.
    if (length == 0) {
      offset += 1;
      continue;
    }

    // Apply the filter to entries that contain user data.
    switch (data_type) {
      case GapDataType::COMPLETE_LOCAL_NAME:
      case GapDataType::SHORTENED_LOCAL_NAME: {
        auto start_pos = gap_data + offset + 1;
        auto end_pos = gap_data + offset + length;
        std::vector<uint8_t> new_name =
            ChangeDeviceName(std::vector<uint8_t>{start_pos, end_pos});
        std::copy(new_name.begin(), new_name.end(), start_pos);
        break;
      }
      default:
        break;
    }

    offset += length + 1;
  }
}

void PcapFilter::FilterGapData(std::vector<uint8_t>& gap_data) {
  FilterGapData(gap_data.data(), gap_data.size());
}

// Replace the local device name.
std::vector<uint8_t> PcapFilter::FilterWriteLocalName(CommandView& command) {
  auto parameters = WriteLocalNameView::Create(command);
  ASSERT(parameters.IsValid());

  std::array<uint8_t, 248> local_name =
      ChangeDeviceName(parameters.GetLocalName());
  return WriteLocalNameBuilder::Create(local_name)->SerializeToBytes();
}

// Replace the device names in the GAP entries of the extended inquiry response.
std::vector<uint8_t> PcapFilter::FilterWriteExtendedInquiryResponse(
    CommandView& command) {
  auto parameters = WriteExtendedInquiryResponseView::Create(command);
  ASSERT(parameters.IsValid());

  std::array<uint8_t, 240> extended_inquiry_response =
      parameters.GetExtendedInquiryResponse();
  FilterGapData(extended_inquiry_response.data(),
                extended_inquiry_response.size());
  return WriteExtendedInquiryResponseBuilder::Create(
             parameters.GetFecRequired(), extended_inquiry_response)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the advertising data.
std::vector<uint8_t> PcapFilter::FilterLeSetAdvertisingData(
    CommandView& command) {
  auto parameters = LeSetAdvertisingDataView::Create(command);
  ASSERT(parameters.IsValid());

  std::vector<uint8_t> advertising_data = parameters.GetAdvertisingData();
  FilterGapData(advertising_data);
  return LeSetAdvertisingDataBuilder::Create(advertising_data)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the scan response data.
std::vector<uint8_t> PcapFilter::FilterLeSetScanResponseData(
    CommandView& command) {
  auto parameters = LeSetScanResponseDataView::Create(command);
  ASSERT(parameters.IsValid());

  std::vector<uint8_t> advertising_data = parameters.GetAdvertisingData();
  FilterGapData(advertising_data);
  return LeSetScanResponseDataBuilder::Create(advertising_data)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the extended advertising data.
std::vector<uint8_t> PcapFilter::FilterLeSetExtendedAdvertisingData(
    CommandView& command) {
  auto parameters = LeSetExtendedAdvertisingDataView::Create(command);
  ASSERT(parameters.IsValid());

  std::vector<uint8_t> advertising_data = parameters.GetAdvertisingData();
  FilterGapData(advertising_data);
  return LeSetExtendedAdvertisingDataBuilder::Create(
             parameters.GetAdvertisingHandle(), parameters.GetOperation(),
             parameters.GetFragmentPreference(), advertising_data)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the extended scan response
// data.
std::vector<uint8_t> PcapFilter::FilterLeSetExtendedScanResponseData(
    CommandView& command) {
  auto parameters = LeSetExtendedScanResponseDataView::Create(command);
  ASSERT(parameters.IsValid());

  std::vector<uint8_t> advertising_data = parameters.GetScanResponseData();
  FilterGapData(advertising_data);
  return LeSetExtendedScanResponseDataBuilder::Create(
             parameters.GetAdvertisingHandle(), parameters.GetOperation(),
             parameters.GetFragmentPreference(), advertising_data)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the periodic advertising
// data.
std::vector<uint8_t> PcapFilter::FilterLeSetPeriodicAdvertisingData(
    bluetooth::hci::CommandView& command) {
  auto parameters = LeSetPeriodicAdvertisingDataView::Create(command);
  ASSERT(parameters.IsValid());

  std::vector<uint8_t> advertising_data = parameters.GetAdvertisingData();
  FilterGapData(advertising_data);
  return LeSetPeriodicAdvertisingDataBuilder::Create(
             parameters.GetAdvertisingHandle(), parameters.GetOperation(),
             advertising_data)
      ->SerializeToBytes();
}

// Replace the local device name in the read local name complete event.
std::vector<uint8_t> PcapFilter::FilterReadLocalNameComplete(
    bluetooth::hci::CommandCompleteView& command_complete) {
  auto parameters = ReadLocalNameCompleteView::Create(command_complete);
  ASSERT(parameters.IsValid());

  std::array<uint8_t, 248> local_name = parameters.GetLocalName();
  if (parameters.GetStatus() == ErrorCode::SUCCESS) {
    local_name = ChangeDeviceName(local_name);
  }

  return ReadLocalNameCompleteBuilder::Create(
             parameters.GetNumHciCommandPackets(), parameters.GetStatus(),
             local_name)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the extended inquiry response.
std::vector<uint8_t> PcapFilter::FilterReadExtendedInquiryResponseComplete(
    bluetooth::hci::CommandCompleteView& command_complete) {
  auto parameters =
      ReadExtendedInquiryResponseCompleteView::Create(command_complete);
  ASSERT(parameters.IsValid());

  std::array<uint8_t, 240> extended_inquiry_response =
      parameters.GetExtendedInquiryResponse();
  if (parameters.GetStatus() == ErrorCode::SUCCESS) {
    FilterGapData(extended_inquiry_response.data(),
                  extended_inquiry_response.size());
  }

  return ReadExtendedInquiryResponseCompleteBuilder::Create(
             parameters.GetNumHciCommandPackets(), parameters.GetStatus(),
             parameters.GetFecRequired(), extended_inquiry_response)
      ->SerializeToBytes();
}

// Replace the remote device name in the remote name request complete event.
std::vector<uint8_t> PcapFilter::FilterRemoteNameRequestComplete(
    bluetooth::hci::EventView& event) {
  auto parameters = RemoteNameRequestCompleteView::Create(event);
  ASSERT(parameters.IsValid());

  std::array<uint8_t, 248> remote_name = parameters.GetRemoteName();
  if (parameters.GetStatus() == ErrorCode::SUCCESS) {
    remote_name = ChangeDeviceName(remote_name);
  }

  return RemoteNameRequestCompleteBuilder::Create(
             parameters.GetStatus(), parameters.GetBdAddr(), remote_name)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries in the extended inquiry result.
std::vector<uint8_t> PcapFilter::FilterExtendedInquiryResult(
    bluetooth::hci::EventView& event) {
  auto parameters = ExtendedInquiryResultView::Create(event);
  ASSERT(parameters.IsValid());

  std::array<uint8_t, 240> extended_inquiry_response =
      parameters.GetExtendedInquiryResponse();
  FilterGapData(extended_inquiry_response.data(),
                extended_inquiry_response.size());
  return ExtendedInquiryResultBuilder::Create(
             parameters.GetAddress(), parameters.GetPageScanRepetitionMode(),
             parameters.GetClassOfDevice(), parameters.GetClockOffset(),
             parameters.GetRssi(), extended_inquiry_response)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries in the advertising report.
std::vector<uint8_t> PcapFilter::FilterLeAdvertisingReport(
    bluetooth::hci::LeMetaEventView& event) {
  auto parameters = LeAdvertisingReportView::Create(event);
  ASSERT(parameters.IsValid());

  std::vector<LeAdvertisingResponse> responses = parameters.GetResponses();
  for (auto& response : responses) {
    FilterGapData(response.advertising_data_);
  }

  return LeAdvertisingReportBuilder::Create(responses)->SerializeToBytes();
}

// Replace the device names in the GAP entries in the extended advertising
// report.
std::vector<uint8_t> PcapFilter::FilterLeExtendedAdvertisingReport(
    bluetooth::hci::LeMetaEventView& event) {
  auto parameters = LeExtendedAdvertisingReportView::Create(event);
  ASSERT(parameters.IsValid());

  std::vector<LeExtendedAdvertisingResponse> responses =
      parameters.GetResponses();
  for (auto& response : responses) {
    FilterGapData(response.advertising_data_);
  }

  return LeExtendedAdvertisingReportBuilder::Create(responses)
      ->SerializeToBytes();
}

// Generate a device name of the specified length.
// device_nr is a unique identifier used for the generation.
// padded indicates if the name should be padded to length with
// spaces.
static std::vector<uint8_t> generate_device_name(size_t device_nr,
                                                 size_t device_name_len,
                                                 bool padded) {
  std::vector<uint8_t> output;
  output.resize(device_name_len + 1);
  int written_len = std::snprintf(reinterpret_cast<char*>(output.data()),
                                  output.size(), "#%02zu device", device_nr);
  // Remove the null terminator, not used for the device name
  // since it is framed in most cases.
  output.resize(device_name_len);
  // Pad the device name with spaces.
  if (padded && written_len >= 0 && written_len < (int)output.size()) {
    std::memset(&output[written_len], ' ', output.size() - written_len);
  }
  return output;
}

std::vector<uint8_t> PcapFilter::ChangeDeviceName(
    std::vector<uint8_t> const& device_name) {
  for (auto const& [old_device_name, new_device_name] : device_name_map) {
    if (old_device_name == device_name) {
      return std::vector<uint8_t>(new_device_name);
    }
  }

  std::vector<uint8_t> new_device_name =
      generate_device_name(device_name_map.size(), device_name.size(), true);
  device_name_map.push_back(std::pair{
      std::vector<uint8_t>(device_name),
      new_device_name,
  });
  return new_device_name;
}

std::array<uint8_t, 248> PcapFilter::ChangeDeviceName(
    std::array<uint8_t, 248> const& device_name) {
  for (auto const& [old_device_name, new_device_name] : device_name_map) {
    if (std::equal(old_device_name.begin(), old_device_name.end(),
                   device_name.begin(), device_name.end())) {
      std::array<uint8_t, 248> out_device_name{};
      std::copy(new_device_name.begin(), new_device_name.end(),
                out_device_name.begin());
      return out_device_name;
    }
  }

  std::vector<uint8_t> new_device_name =
      generate_device_name(device_name_map.size(), device_name.size(), false);
  std::array<uint8_t, 248> out_device_name{};
  std::copy(new_device_name.begin(), new_device_name.end(),
            out_device_name.begin());
  device_name_map.push_back(std::pair{
      std::vector<uint8_t>(device_name.begin(), device_name.end()),
      std::move(new_device_name),
  });
  return out_device_name;
}

}  // namespace rootcanal
