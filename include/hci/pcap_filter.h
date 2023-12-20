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

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "packets/hci_packets.h"

namespace rootcanal {

// Filter to remove user information from packets added to a PCAP trace.
// This is necessary in order to ensure no identifyiable information
// remains in traces uploaded in debug traces.
//
// The packets are transformed using the following rules:
//
// - HCI command / event packets:
//   + Re-map device names to random names of the same length.
//    The device addresses are already provided by RootCanal.
//
// - HCI ACL / SCO / ISO packets:
//   + Wipe the packet payload with zeros.
//     The ACL data is usually of no consequence for debugging
//     RootCanal issues, and can be safely removed.

class PcapFilter final {
 public:
  PcapFilter() = default;

  // Main function to filter out user data in HCI packets.
  std::vector<uint8_t> FilterHciPacket(std::vector<uint8_t> const& packet,
                                       uint8_t idc);

  std::vector<uint8_t> FilterHciCommand(std::vector<uint8_t> const& packet);
  std::vector<uint8_t> FilterHciEvent(std::vector<uint8_t> const& packet);

  // Specific filters for HCI commands.
  std::vector<uint8_t> FilterWriteLocalName(
      bluetooth::hci::CommandView& command);
  std::vector<uint8_t> FilterWriteExtendedInquiryResponse(
      bluetooth::hci::CommandView& command);
  std::vector<uint8_t> FilterLeSetAdvertisingData(
      bluetooth::hci::CommandView& command);
  std::vector<uint8_t> FilterLeSetScanResponseData(
      bluetooth::hci::CommandView& command);
  std::vector<uint8_t> FilterLeSetExtendedAdvertisingData(
      bluetooth::hci::CommandView& command);
  std::vector<uint8_t> FilterLeSetExtendedScanResponseData(
      bluetooth::hci::CommandView& command);
  std::vector<uint8_t> FilterLeSetPeriodicAdvertisingData(
      bluetooth::hci::CommandView& command);

  // Specific filters for HCI events.
  std::vector<uint8_t> FilterReadLocalNameComplete(
      bluetooth::hci::CommandCompleteView& command_complete);
  std::vector<uint8_t> FilterReadExtendedInquiryResponseComplete(
      bluetooth::hci::CommandCompleteView& command_complete);
  std::vector<uint8_t> FilterRemoteNameRequestComplete(
      bluetooth::hci::EventView& event);
  std::vector<uint8_t> FilterExtendedInquiryResult(
      bluetooth::hci::EventView& event);
  std::vector<uint8_t> FilterLeAdvertisingReport(
      bluetooth::hci::LeMetaEventView& event);
  std::vector<uint8_t> FilterLeExtendedAdvertisingReport(
      bluetooth::hci::LeMetaEventView& event);

  // Specific filter for any Gap data array.
  // The Gap data entries are modified in place.
  void FilterGapData(uint8_t* gap_data, size_t gap_data_len);
  void FilterGapData(std::vector<uint8_t>& gap_data);

  // Helpers to replace local names.
  std::array<uint8_t, 248> ChangeDeviceName(
      std::array<uint8_t, 248> const& device_name);
  std::vector<uint8_t> ChangeDeviceName(
      std::vector<uint8_t> const& device_name);

 private:
  // Map device names to anonymous replacements.
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      device_name_map{};
};

}  // namespace rootcanal
