/*
 * Copyright 2015 The Android Open Source Project
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
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "hci/address.h"
#include "hci/hci_packets.h"

namespace rootcanal {
using bluetooth::hci::HciVersion;
using bluetooth::hci::LmpVersion;

// Local controller information.
//
// Provide the Informational Parameters returned by HCI commands
// in the range of the same name (cf. [4] E.7.4).
// The informational parameters are fixed by the manufacturer of the Bluetooth
// hardware. These parameters provide information about the BR/EDR Controller
// and the capabilities of the Link Manager and Baseband in the BR/EDR
// Controller. The Host device cannot modify any of these parameters.
struct ControllerProperties {
 public:
  explicit ControllerProperties(const std::string& filename = "");
  ~ControllerProperties() = default;

  // Perform a bitwise and operation on the supported commands mask;
  // the default bit setting is either loaded from the configuration
  // file or all 1s.
  void SetSupportedCommands(std::array<uint8_t, 64> supported_commands);

  // Check if the feature masks are valid according to the specification.
  bool CheckSupportedFeatures() const;

  // Local Version Information (Vol 4, Part E § 7.4.1).
  HciVersion hci_version{HciVersion::V_5_3};
  LmpVersion lmp_version{LmpVersion::V_5_3};
  uint16_t hci_subversion{0};
  uint16_t lmp_subversion{0};
  uint16_t company_identifier{0x00E0};  // Google

  // Local Supported Commands (Vol 4, Part E § 7.4.2).
  std::array<uint8_t, 64> supported_commands;

  // Local Supported Features (Vol 4, Part E § 7.4.3) and
  // Local Extended Features (Vol 4, Part E § 7.4.3).
  std::array<uint64_t, 3> lmp_features;

  // LE Local Supported Features (Vol 4, Part E § 7.8.3).
  uint64_t le_features;

  // Buffer Size (Vol 4, Part E § 7.4.5).
  uint16_t acl_data_packet_length{1024};
  uint8_t sco_data_packet_length{255};
  uint16_t total_num_acl_data_packets{10};
  uint16_t total_num_sco_data_packets{10};

  // LE Buffer Size (Vol 4, Part E § 7.8.2).
  uint16_t le_acl_data_packet_length{27};
  uint16_t iso_data_packet_length{1021};
  uint8_t total_num_le_acl_data_packets{20};
  uint8_t total_num_iso_data_packets{12};

  // Number of Supported IAC (Vol 4, Part E § 7.3.43).
  uint8_t num_supported_iac{4};

  // LE Advertising Physical Channel TX Power (Vol 4, Part E § 7.8.6).
  uint8_t le_advertising_physical_channel_tx_power{static_cast<uint8_t>(-10)};

  // Supported Codecs (Vol 4, Part E § 7.4.8).
  // Implements the [v1] version only.
  std::vector<uint8_t> supported_standard_codecs{0};
  std::vector<uint32_t> supported_vendor_specific_codecs{};

  // LE Filter Accept List Size (Vol 4, Part E § 7.8.14).
  uint8_t le_filter_accept_list_size{16};

  // LE Resolving List Size (Vol 4, Part E § 7.8.41).
  uint8_t le_resolving_list_size{16};

  // LE Supported States (Vol 4, Part E § 7.8.27).
  uint64_t le_supported_states{0x3ffffffffff};

  // LE Maximum Advertising Data Length (Vol 4, Part E § 7.8.57).
  // Note: valid range 0x001F to 0x0672.
  uint16_t le_max_advertising_data_length{512};

  // LE Number of Supported Advertising Sets (Vol 4, Part E § 7.8.58)
  // Note: the controller can change the number of advertising sets
  // at any time. This behaviour is not emulated here.
  uint8_t le_num_supported_advertising_sets{8};

  // Vendor Information.
  // Provide parameters returned by vendor specific commands.
  std::vector<uint8_t> le_vendor_capabilities{};

  bool SupportsLMPFeature(bluetooth::hci::LMPFeaturesPage0Bits bit) const {
    return (lmp_features[0] & static_cast<uint64_t>(bit)) != 0;
  }

  bool SupportsLMPFeature(bluetooth::hci::LMPFeaturesPage2Bits bit) const {
    return (lmp_features[2] & static_cast<uint64_t>(bit)) != 0;
  }
};

}  // namespace rootcanal
