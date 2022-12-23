/******************************************************************************
 *
 *  Copyright 2022 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include <hci/hci_packets.h>
#include <hci/pcap_filter.h>
#include <packet/raw_builder.h>

using namespace bluetooth::hci;
using namespace bluetooth::packet;

namespace rootcanal {

static PacketView<kLittleEndian> create_packet_view(
    std::vector<uint8_t> const& packet) {
  // Wrap the reference to the packet in a shared_ptr with created
  // a no-op deleter. The packet view will be short lived so there is no
  // risk of the reference leaking.
  return PacketView<kLittleEndian>(std::shared_ptr<std::vector<uint8_t> const>(
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
    case OpCode::LE_MULTI_ADVT: {
      auto le_multi_advt_command =
          LeMultiAdvtView::Create(LeAdvertisingCommandView::Create(command));
      ASSERT(le_multi_advt_command.IsValid());
      switch (le_multi_advt_command.GetSubCmd()) {
        case SubOcf::SET_DATA:
          return FilterLeMultiAdvtSetData(le_multi_advt_command);
        case SubOcf::SET_SCAN_RESP:
          return FilterLeMultiAdvtSetScanResp(le_multi_advt_command);
        default:
          break;
      }
      break;
    }
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
                            acl.GetBroadcastFlag(),
                            std::make_unique<RawBuilder>(payload))
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
                            iso.GetTsFlag(),
                            std::make_unique<RawBuilder>(payload))
      ->SerializeToBytes();
}

// Replace device names in GAP entries.
void PcapFilter::FilterGapData(std::vector<GapData>& gap_data) {
  for (GapData& entry : gap_data) {
    switch (entry.data_type_) {
      case GapDataType::COMPLETE_LOCAL_NAME:
      case GapDataType::SHORTENED_LOCAL_NAME:
        entry.data_ = ChangeDeviceName(entry.data_);
        break;
      default:
        break;
    }
  }
}

void PcapFilter::FilterLengthAndData(
    std::vector<bluetooth::hci::LengthAndData>& gap_data) {
  for (LengthAndData& entry : gap_data) {
    if (entry.data_.empty()) {
      continue;
    }
    switch (GapDataType(entry.data_[0])) {
      case GapDataType::COMPLETE_LOCAL_NAME:
      case GapDataType::SHORTENED_LOCAL_NAME: {
        std::vector<uint8_t> device_name(entry.data_.begin() + 1,
                                         entry.data_.end());
        device_name = ChangeDeviceName(device_name);
        entry.data_.insert(device_name.begin(), device_name.end(),
                           entry.data_.begin() + 1);
        break;
      }
      default:
        break;
    }
  }
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

  std::vector<GapData> extended_inquiry_response =
      parameters.GetExtendedInquiryResponse();
  FilterGapData(extended_inquiry_response);
  return WriteExtendedInquiryResponseBuilder::Create(
             parameters.GetFecRequired(), extended_inquiry_response)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the advertising data.
std::vector<uint8_t> PcapFilter::FilterLeSetAdvertisingData(
    CommandView& command) {
  auto parameters = LeSetAdvertisingDataView::Create(
      LeAdvertisingCommandView::Create(command));
  ASSERT(parameters.IsValid());

  std::vector<GapData> advertising_data = parameters.GetAdvertisingData();
  FilterGapData(advertising_data);
  return LeSetAdvertisingDataBuilder::Create(advertising_data)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the scan response data.
std::vector<uint8_t> PcapFilter::FilterLeSetScanResponseData(
    CommandView& command) {
  auto parameters = LeSetScanResponseDataView::Create(
      LeAdvertisingCommandView::Create(command));
  ASSERT(parameters.IsValid());

  std::vector<GapData> advertising_data = parameters.GetAdvertisingData();
  FilterGapData(advertising_data);
  return LeSetScanResponseDataBuilder::Create(advertising_data)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the extended advertising data.
std::vector<uint8_t> PcapFilter::FilterLeSetExtendedAdvertisingData(
    CommandView& command) {
  auto parameters = LeSetExtendedAdvertisingDataView::Create(
      LeAdvertisingCommandView::Create(command));
  ASSERT(parameters.IsValid());

  std::vector<GapData> advertising_data = parameters.GetAdvertisingData();
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
  auto parameters = LeSetExtendedScanResponseDataView::Create(
      LeAdvertisingCommandView::Create(command));
  ASSERT(parameters.IsValid());

  std::vector<GapData> advertising_data = parameters.GetScanResponseData();
  FilterGapData(advertising_data);
  return LeSetExtendedScanResponseDataBuilder::Create(
             parameters.GetAdvertisingHandle(), parameters.GetOperation(),
             parameters.GetFragmentPreference(), advertising_data)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the periodic scan response
// data.
std::vector<uint8_t> PcapFilter::FilterLeSetPeriodicAdvertisingData(
    bluetooth::hci::CommandView& command) {
  auto parameters = LeSetPeriodicAdvertisingDataView::Create(
      LeAdvertisingCommandView::Create(command));
  ASSERT(parameters.IsValid());

  std::vector<GapData> scan_response_data = parameters.GetScanResponseData();
  FilterGapData(scan_response_data);
  return LeSetPeriodicAdvertisingDataBuilder::Create(
             parameters.GetAdvertisingHandle(), parameters.GetOperation(),
             scan_response_data)
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the advertising data.
std::vector<uint8_t> PcapFilter::FilterLeMultiAdvtSetData(
    bluetooth::hci::LeMultiAdvtView& command) {
  auto parameters = LeMultiAdvtSetDataView::Create(command);
  ASSERT(parameters.IsValid());

  std::vector<GapData> advertising_data = parameters.GetAdvertisingData();
  FilterGapData(advertising_data);
  return LeMultiAdvtSetDataBuilder::Create(advertising_data,
                                           parameters.GetAdvertisingInstance())
      ->SerializeToBytes();
}

// Replace the device names in the GAP entries of the scan response data.
std::vector<uint8_t> PcapFilter::FilterLeMultiAdvtSetScanResp(
    bluetooth::hci::LeMultiAdvtView& command) {
  auto parameters = LeMultiAdvtSetScanRespView::Create(command);
  ASSERT(parameters.IsValid());

  std::vector<GapData> advertising_data = parameters.GetAdvertisingData();
  FilterGapData(advertising_data);
  return LeMultiAdvtSetScanRespBuilder::Create(
             advertising_data, parameters.GetAdvertisingInstance())
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

  std::vector<GapData> extended_inquiry_response =
      parameters.GetExtendedInquiryResponse();
  if (parameters.GetStatus() == ErrorCode::SUCCESS) {
    FilterGapData(extended_inquiry_response);
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

  std::vector<GapData> extended_inquiry_response =
      parameters.GetExtendedInquiryResponse();
  FilterGapData(extended_inquiry_response);

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
    FilterLengthAndData(response.advertising_data_);
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
    FilterLengthAndData(response.advertising_data_);
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
