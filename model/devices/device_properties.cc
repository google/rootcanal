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

#include "device_properties.h"

#include <fstream>
#include <memory>

#include "json/json.h"
#include "os/log.h"
#include "osi/include/osi.h"

static void ParseUint8t(Json::Value value, uint8_t* field) {
  if (value.isString()) {
    *field = std::stoi(value.asString(), nullptr, 0);
  }
}

static void ParseUint16t(Json::Value value, uint16_t* field) {
  if (value.isString()) {
    *field = std::stoi(value.asString(), nullptr, 0);
  }
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

namespace rootcanal {

DeviceProperties::DeviceProperties(const std::string& file_name)
    : acl_data_packet_size_(1024),
      sco_data_packet_size_(255),
      num_acl_data_packets_(10),
      num_sco_data_packets_(10),
      version_(static_cast<uint8_t>(bluetooth::hci::HciVersion::V_4_1)),
      revision_(0),
      lmp_pal_version_(static_cast<uint8_t>(bluetooth::hci::LmpVersion::V_4_1)),
      manufacturer_name_(0),
      lmp_pal_subversion_(0),
      le_data_packet_length_(27),
      num_le_data_packets_(20),
      le_connect_list_size_(15),
      le_resolving_list_size_(15) {
  std::string properties_raw;

  ASSERT(Address::FromString("BB:BB:BB:BB:BB:AD", address_));
  ASSERT(Address::FromString("BB:BB:BB:BB:AD:1E", le_address_));
  name_ = {'D', 'e', 'f', 'a', 'u', 'l', 't'};

  supported_codecs_ = {0};  // Only SBC is supported.
  vendor_specific_codecs_ = {};

  for (int i = 0; i < 35; i++) supported_commands_[i] = 0xff;
  // Mark HCI_LE_Transmitter_Test[v2] and newer commands as unsupported
  // Use SetSupportedComands() to change what's supported.
  for (int i = 35; i < 64; i++) supported_commands_[i] = 0x00;

  le_supported_features_ = 0x1f;
  le_supported_states_ = 0x3ffffffffff;
  le_vendor_cap_ = {};

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

  ParseUint16t(root["AclDataPacketSize"], &acl_data_packet_size_);
  ParseUint8t(root["ScoDataPacketSize"], &sco_data_packet_size_);
  ParseUint8t(root["EncryptionKeySize"], &encryption_key_size_);
  ParseUint16t(root["NumAclDataPackets"], &num_acl_data_packets_);
  ParseUint16t(root["NumScoDataPackets"], &num_sco_data_packets_);
  ParseUint8t(root["Version"], &version_);
  ParseUint16t(root["Revision"], &revision_);
  ParseUint8t(root["LmpPalVersion"], &lmp_pal_version_);
  ParseUint16t(root["ManufacturerName"], &manufacturer_name_);
  ParseUint16t(root["LmpPalSubversion"], &lmp_pal_subversion_);
  Json::Value supported_commands = root["supported_commands"];
  if (!supported_commands.empty()) {
    use_supported_commands_from_file_ = true;
    for (unsigned i = 0; i < supported_commands.size(); i++) {
      std::string out = supported_commands[i].asString();
      uint8_t number = stoi(out, nullptr, 16);
      supported_commands_[i] = number;
    }
  }
  ParseHex64(root["LeSupportedFeatures"], &le_supported_features_);
  ParseUint16t(root["LeConnectListIgnoreReasons"],
               &le_connect_list_ignore_reasons_);
  ParseUint16t(root["LeResolvingListIgnoreReasons"],
               &le_resolving_list_ignore_reasons_);
}

}  // namespace rootcanal
