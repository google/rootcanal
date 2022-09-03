/*
 * Copyright 2015 The Android Open Source Project
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

#include "controller_properties.h"

#include <json/json.h>

#include <fstream>
#include <limits>
#include <memory>

#include "os/log.h"
#include "osi/include/osi.h"

namespace rootcanal {
using namespace bluetooth::hci;

static constexpr uint64_t Page0LmpFeatures() {
  LMPFeaturesPage0Bits features[] = {
      LMPFeaturesPage0Bits::LMP_3_SLOT_PACKETS,
      LMPFeaturesPage0Bits::LMP_5_SLOT_PACKETS,
      LMPFeaturesPage0Bits::ENCRYPTION,
      LMPFeaturesPage0Bits::SLOT_OFFSET,
      LMPFeaturesPage0Bits::TIMING_ACCURACY,
      LMPFeaturesPage0Bits::ROLE_SWITCH,
      LMPFeaturesPage0Bits::HOLD_MODE,
      LMPFeaturesPage0Bits::SNIFF_MODE,
      LMPFeaturesPage0Bits::POWER_CONTROL_REQUESTS,
      LMPFeaturesPage0Bits::CHANNEL_QUALITY_DRIVEN_DATA_RATE,
      LMPFeaturesPage0Bits::SCO_LINK,
      LMPFeaturesPage0Bits::HV2_PACKETS,
      LMPFeaturesPage0Bits::HV3_PACKETS,
      LMPFeaturesPage0Bits::M_LAW_LOG_SYNCHRONOUS_DATA,
      LMPFeaturesPage0Bits::A_LAW_LOG_SYNCHRONOUS_DATA,
      LMPFeaturesPage0Bits::CVSD_SYNCHRONOUS_DATA,
      LMPFeaturesPage0Bits::PAGING_PARAMETER_NEGOTIATION,
      LMPFeaturesPage0Bits::POWER_CONTROL,
      LMPFeaturesPage0Bits::TRANSPARENT_SYNCHRONOUS_DATA,
      LMPFeaturesPage0Bits::BROADCAST_ENCRYPTION,
      LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ACL_2_MB_S_MODE,
      LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ACL_3_MB_S_MODE,
      LMPFeaturesPage0Bits::ENHANCED_INQUIRY_SCAN,
      LMPFeaturesPage0Bits::INTERLACED_INQUIRY_SCAN,
      LMPFeaturesPage0Bits::INTERLACED_PAGE_SCAN,
      LMPFeaturesPage0Bits::RSSI_WITH_INQUIRY_RESULTS,
      LMPFeaturesPage0Bits::EXTENDED_SCO_LINK,
      LMPFeaturesPage0Bits::EV4_PACKETS,
      LMPFeaturesPage0Bits::EV5_PACKETS,
      LMPFeaturesPage0Bits::AFH_CAPABLE_PERIPHERAL,
      LMPFeaturesPage0Bits::AFH_CLASSIFICATION_PERIPHERAL,
      LMPFeaturesPage0Bits::LE_SUPPORTED_CONTROLLER,
      LMPFeaturesPage0Bits::LMP_3_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS,
      LMPFeaturesPage0Bits::LMP_5_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS,
      LMPFeaturesPage0Bits::SNIFF_SUBRATING,
      LMPFeaturesPage0Bits::PAUSE_ENCRYPTION,
      LMPFeaturesPage0Bits::AFH_CAPABLE_CENTRAL,
      LMPFeaturesPage0Bits::AFH_CLASSIFICATION_CENTRAL,
      LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ESCO_2_MB_S_MODE,
      LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ESCO_3_MB_S_MODE,
      LMPFeaturesPage0Bits::LMP_3_SLOT_ENHANCED_DATA_RATE_ESCO_PACKETS,
      LMPFeaturesPage0Bits::EXTENDED_INQUIRY_RESPONSE,
      LMPFeaturesPage0Bits::SIMULTANEOUS_LE_AND_BR_CONTROLLER,
      LMPFeaturesPage0Bits::SECURE_SIMPLE_PAIRING_CONTROLLER,
      LMPFeaturesPage0Bits::ENCAPSULATED_PDU,
      LMPFeaturesPage0Bits::HCI_LINK_SUPERVISION_TIMEOUT_CHANGED_EVENT,
      LMPFeaturesPage0Bits::VARIABLE_INQUIRY_TX_POWER_LEVEL,
      LMPFeaturesPage0Bits::ENHANCED_POWER_CONTROL,
      LMPFeaturesPage0Bits::EXTENDED_FEATURES};

  uint64_t value = 0;
  for (auto feature : features) {
    value |= static_cast<uint64_t>(feature);
  }
  return value;
}

static constexpr uint64_t Page1LmpFeatures() {
  LMPFeaturesPage1Bits features[] = {
      LMPFeaturesPage1Bits::SIMULTANEOUS_LE_AND_BR_HOST,
  };

  uint64_t value = 0;
  for (auto feature : features) {
    value |= static_cast<uint64_t>(feature);
  }
  return value;
}

static constexpr uint64_t Page2LmpFeatures() {
  LMPFeaturesPage2Bits features[] = {
      LMPFeaturesPage2Bits::SECURE_CONNECTIONS_CONTROLLER_SUPPORT,
  };

  uint64_t value = 0;
  for (auto feature : features) {
    value |= static_cast<uint64_t>(feature);
  }
  return value;
}

static constexpr uint64_t LlFeatures() {
  LLFeaturesBits features[] = {
      LLFeaturesBits::LE_ENCRYPTION,
      LLFeaturesBits::CONNECTION_PARAMETERS_REQUEST_PROCEDURE,
      LLFeaturesBits::EXTENDED_REJECT_INDICATION,
      LLFeaturesBits::PERIPHERAL_INITIATED_FEATURES_EXCHANGE,
      LLFeaturesBits::LE_PING,

      LLFeaturesBits::EXTENDED_SCANNER_FILTER_POLICIES,
      LLFeaturesBits::LE_EXTENDED_ADVERTISING,

      // TODO: breaks AVD boot tests with LE audio
      // LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL,
      // LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL,
  };

  uint64_t value = 0;
  for (auto feature : features) {
    value |= static_cast<uint64_t>(feature);
  }
  return value;
}

template <typename T>
static bool ParseUint(Json::Value root, std::string field_name,
                      T& output_value) {
  T max_value = std::numeric_limits<T>::max();
  Json::Value value = root[field_name];

  if (value.isString()) {
    unsigned long long parsed_value = std::stoull(value.asString(), nullptr, 0);
    if (parsed_value > max_value) {
      LOG_INFO("invalid value for %s is discarded: %llu > %llu",
               field_name.c_str(), parsed_value,
               static_cast<unsigned long long>(max_value));
      return false;
    } else {
      output_value = static_cast<T>(parsed_value);
      return true;
    }
  }

  return false;
}

template <typename T, std::size_t N>
static bool ParseUintArray(Json::Value root, std::string field_name,
                           std::array<T, N>& output_value) {
  T max_value = std::numeric_limits<T>::max();
  Json::Value value = root[field_name];

  if (value.empty()) {
    return false;
  }

  if (!value.isArray()) {
    LOG_INFO("invalid value for %s is discarded: not an array",
             field_name.c_str());
    return false;
  }

  if (value.size() != N) {
    LOG_INFO(
        "invalid value for %s is discarded: incorrect size %u, expected %zu",
        field_name.c_str(), value.size(), N);
    return false;
  }

  for (size_t n = 0; n < N; n++) {
    unsigned long long parsed_value = std::stoull(value.asString(), nullptr, 0);
    if (parsed_value > max_value) {
      LOG_INFO("invalid value for %s[%zu] is discarded: %llu > %llu",
               field_name.c_str(), n, parsed_value,
               static_cast<unsigned long long>(max_value));
    } else {
      output_value[n] = parsed_value;
    }
  }

  return false;
}

template <typename T>
static bool ParseUintVector(Json::Value root, std::string field_name,
                            std::vector<T>& output_value) {
  T max_value = std::numeric_limits<T>::max();
  Json::Value value = root[field_name];

  if (value.empty()) {
    return false;
  }

  if (!value.isArray()) {
    LOG_INFO("invalid value for %s is discarded: not an array",
             field_name.c_str());
    return false;
  }

  output_value.clear();
  for (size_t n = 0; n < value.size(); n++) {
    unsigned long long parsed_value = std::stoull(value.asString(), nullptr, 0);
    if (parsed_value > max_value) {
      LOG_INFO("invalid value for %s[%zu] is discarded: %llu > %llu",
               field_name.c_str(), n, parsed_value,
               static_cast<unsigned long long>(max_value));
    } else {
      output_value.push_back(parsed_value);
    }
  }

  return false;
}

static void ParseHex64(Json::Value value, uint64_t* field) {
  if (value.isString()) {
    size_t end_char = 0;
    uint64_t parsed = std::stoll(value.asString(), &end_char, 16);
    if (end_char > 0) {
      *field = parsed;
    }
  }
}

ControllerProperties::ControllerProperties(const std::string& file_name)
    : lmp_features(
          {Page0LmpFeatures(), Page1LmpFeatures(), Page2LmpFeatures()}),
      le_features(LlFeatures()) {
  // Set support for all HCI commands by default.
  // The controller will update the mask with its implemented commands
  // after the creation of the properties.
  for (int i = 0; i < 47; i++) {
    supported_commands[i] = 0xff;
  }

  // Mark reserved commands as unsupported.
  for (int i = 47; i < 64; i++) {
    supported_commands[i] = 0x00;
  }

  if (file_name.empty()) {
    return;
  }

  LOG_INFO("Reading controller properties from %s.", file_name.c_str());

  std::ifstream file(file_name);

  Json::Value root;
  Json::CharReaderBuilder builder;

  std::string errs;
  if (!Json::parseFromStream(builder, file, &root, &errs)) {
    LOG_ERROR("Error reading controller properties from file: %s error: %s",
              file_name.c_str(), errs.c_str());
    return;
  }

  // Legacy configuration options.

  ParseUint(root, "AclDataPacketSize", acl_data_packet_length);
  ParseUint(root, "ScoDataPacketSize", sco_data_packet_length);
  ParseUint(root, "NumAclDataPackets", total_num_acl_data_packets);
  ParseUint(root, "NumScoDataPackets", total_num_sco_data_packets);

  uint8_t hci_version = static_cast<uint8_t>(this->hci_version);
  uint8_t lmp_version = static_cast<uint8_t>(this->lmp_version);
  ParseUint(root, "Version", hci_version);
  ParseUint(root, "Revision", hci_subversion);
  ParseUint(root, "LmpPalVersion", lmp_version);
  ParseUint(root, "LmpPalSubversion", lmp_subversion);
  ParseUint(root, "ManufacturerName", company_identifier);

  ParseHex64(root["LeSupportedFeatures"], &le_features);
  ParseUint(root, "LeConnectListIgnoreReasons", le_connect_list_ignore_reasons);
  ParseUint(root, "LeResolvingListIgnoreReasons",
            le_resolving_list_ignore_reasons);

  // Configuration options.

  ParseUint(root, "hci_version", hci_version);
  ParseUint(root, "lmp_version", lmp_version);
  ParseUint(root, "hci_subversion", hci_subversion);
  ParseUint(root, "lmp_subversion", lmp_subversion);
  ParseUint(root, "company_identifier", company_identifier);

  ParseUintArray(root, "supported_commands", supported_commands);
  ParseUintArray(root, "lmp_features", lmp_features);
  ParseUint(root, "le_features", le_features);

  ParseUint(root, "acl_data_packet_length", acl_data_packet_length);
  ParseUint(root, "sco_data_packet_length ", sco_data_packet_length);
  ParseUint(root, "total_num_acl_data_packets ", total_num_acl_data_packets);
  ParseUint(root, "total_num_sco_data_packets ", total_num_sco_data_packets);
  ParseUint(root, "le_acl_data_packet_length ", le_acl_data_packet_length);
  ParseUint(root, "iso_data_packet_length ", iso_data_packet_length);
  ParseUint(root, "total_num_le_acl_data_packets ",
            total_num_le_acl_data_packets);
  ParseUint(root, "total_num_iso_data_packets ", total_num_iso_data_packets);

  ParseUintArray(root, "lmp_features", lmp_features);
  ParseUintVector(root, "supported_standard_codecs", supported_standard_codecs);
  ParseUintVector(root, "supported_vendor_specific_codecs",
                  supported_vendor_specific_codecs);

  ParseUint(root, "le_filter_accept_list_size", le_filter_accept_list_size);
  ParseUint(root, "le_resolving_list_size", le_resolving_list_size);
  ParseUint(root, "le_supported_states", le_supported_states);

  ParseUintVector(root, "le_vendor_capabilities", le_vendor_capabilities);

  this->hci_version = static_cast<HciVersion>(hci_version);
  this->lmp_version = static_cast<LmpVersion>(lmp_version);
}

void ControllerProperties::SetSupportedCommands(
    std::array<uint8_t, 64> supported_commands) {
  for (size_t i = 0; i < this->supported_commands.size(); i++) {
    this->supported_commands[i] &= supported_commands[i];
  }
}

}  // namespace rootcanal
