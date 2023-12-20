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
#include <vector>

#include "packets/hci_packets.h"
#include "rootcanal/configuration.pb.h"

namespace rootcanal {
using bluetooth::hci::HciVersion;
using bluetooth::hci::LmpVersion;

// Local controller quirks.
struct ControllerQuirks {
  // The specification states that the Random Address is invalid until
  // explicitly set by the command LE Set Random Address. Certain HCI commands
  // check for this condition.
  //
  // This quirk configures a default value for the LE random address in order
  // to bypass this validation. The default random address will
  // be ba:db:ad:ba:db:ad.
  bool has_default_random_address{false};

  // This quirks configures the controller to send an Hardware Error event
  // in case a command is received before the HCI Reset command.
  //
  // Receiving a different command is indicative of the emulator being
  // started from a snapshot. In this case the controller state is lost
  // but the Host stack is loaded post-initialization. This quirk
  // ensures that the stack will reset itself after reloading.
  bool hardware_error_before_reset{false};
};

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
  ControllerProperties();
  ControllerProperties(rootcanal::configuration::Controller const&);
  ControllerProperties(ControllerProperties const&) = default;
  ControllerProperties(ControllerProperties&&) = default;
  ~ControllerProperties() = default;

  ControllerProperties& operator=(ControllerProperties const&) = default;

  // Perform a bitwise and operation on the supported commands mask;
  // the default bit setting is either loaded from the configuration
  // file or all 1s.
  void SetSupportedCommands(std::array<uint8_t, 64> supported_commands);

  // Check if the feature masks are valid according to the specification.
  bool CheckSupportedFeatures() const;

  // Check if the supported command mask is valid according to the
  // specification. If fixup is true, then the mask is updated instead of
  // returning an error.
  bool CheckSupportedCommands() const;

  // Enabled quirks.
  ControllerQuirks quirks{};

  // Strict mode.
  bool strict{true};

  // Local Version Information (Vol 4, Part E § 7.4.1).
  HciVersion hci_version{HciVersion::V_5_3};
  LmpVersion lmp_version{LmpVersion::V_5_3};
  uint16_t hci_subversion{0};
  uint16_t lmp_subversion{0};
  uint16_t company_identifier{0x00E0};  // Google

  // Transports.
  bool br_supported{true};
  bool le_supported{true};

  // Local Supported Commands (Vol 4, Part E § 7.4.2).
  std::array<uint8_t, 64> supported_commands{};

  // Vendor Supported Commands.
  bool supports_le_get_vendor_capabilities_command{true};
  bool supports_csr_vendor_command{true};
  bool supports_le_apcf_vendor_command{true};

  // Local Supported Features (Vol 4, Part E § 7.4.3) and
  // Local Extended Features (Vol 4, Part E § 7.4.3).
  std::array<uint64_t, 3> lmp_features{};

  // LE Local Supported Features (Vol 4, Part E § 7.8.3).
  uint64_t le_features{0};

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
  uint8_t le_num_supported_advertising_sets{16};

  // LE Periodic Advertiser List Size (Vol 4, Part E § 7.8.73).
  uint8_t le_periodic_advertiser_list_size{8};

  // Android Vendor Capabilities.
  // https://source.android.com/docs/core/connect/bluetooth/hci_requirements#vendor-specific-capabilities
  uint8_t le_apcf_filter_list_size{16};
  uint8_t le_apcf_num_of_tracked_advertisers{16};
  uint8_t le_apcf_broadcaster_address_filter_list_size{16};
  uint8_t le_apcf_service_uuid_filter_list_size{16};
  uint8_t le_apcf_service_solicitation_uuid_filter_list_size{16};
  uint8_t le_apcf_local_name_filter_list_size{16};
  uint8_t le_apcf_manufacturer_data_filter_list_size{16};
  uint8_t le_apcf_service_data_filter_list_size{16};
  uint8_t le_apcf_ad_type_filter_list_size{16};

  bool SupportsLMPFeature(bluetooth::hci::LMPFeaturesPage0Bits bit) const {
    return (lmp_features[0] & static_cast<uint64_t>(bit)) != 0;
  }

  bool SupportsLMPFeature(bluetooth::hci::LMPFeaturesPage2Bits bit) const {
    return (lmp_features[2] & static_cast<uint64_t>(bit)) != 0;
  }

  bool SupportsLLFeature(bluetooth::hci::LLFeaturesBits bit) const {
    return (le_features & static_cast<uint64_t>(bit)) != 0;
  }

  bool SupportsCommand(bluetooth::hci::OpCodeIndex op_code) const {
    int index = static_cast<int>(op_code);
    return (supported_commands[index / 10] & (UINT64_C(1) << (index % 10))) !=
           0;
  }

  /// Return a bit mask with all supported PHYs
  /// (0b001 = LE_1M, 0b010 = LE_2M, 0b100 = LE_CODED).
  uint8_t LeSupportedPhys() const {
    uint8_t supported_phys = 0x1;  // LE_1M is always supported.
    if (SupportsLLFeature(bluetooth::hci::LLFeaturesBits::LE_2M_PHY)) {
      supported_phys |= 0x2;
    }
    if (SupportsLLFeature(bluetooth::hci::LLFeaturesBits::LE_CODED_PHY)) {
      supported_phys |= 0x4;
    }
    return supported_phys;
  }
};

}  // namespace rootcanal
