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

#include <inttypes.h>
#include <json/json.h>

#include <fstream>
#include <limits>
#include <memory>

#include "log.h"

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

static constexpr uint64_t Page2LmpFeatures() {
  LMPFeaturesPage2Bits features[] = {
      LMPFeaturesPage2Bits::SECURE_CONNECTIONS_CONTROLLER_SUPPORT,
      LMPFeaturesPage2Bits::PING,
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

static std::array<uint8_t, 64> SupportedCommands() {
  OpCodeIndex supported_commands[] = {
      // LINK_CONTROL
      OpCodeIndex::INQUIRY, OpCodeIndex::INQUIRY_CANCEL,
      // OpCodeIndex::PERIODIC_INQUIRY_MODE,
      // OpCodeIndex::EXIT_PERIODIC_INQUIRY_MODE,
      OpCodeIndex::CREATE_CONNECTION, OpCodeIndex::DISCONNECT,
      OpCodeIndex::ADD_SCO_CONNECTION, OpCodeIndex::CREATE_CONNECTION_CANCEL,
      OpCodeIndex::ACCEPT_CONNECTION_REQUEST,
      OpCodeIndex::REJECT_CONNECTION_REQUEST,
      OpCodeIndex::LINK_KEY_REQUEST_REPLY,
      OpCodeIndex::LINK_KEY_REQUEST_NEGATIVE_REPLY,
      OpCodeIndex::PIN_CODE_REQUEST_REPLY,
      OpCodeIndex::PIN_CODE_REQUEST_NEGATIVE_REPLY,
      OpCodeIndex::CHANGE_CONNECTION_PACKET_TYPE,
      OpCodeIndex::AUTHENTICATION_REQUESTED,
      OpCodeIndex::SET_CONNECTION_ENCRYPTION,
      OpCodeIndex::CHANGE_CONNECTION_LINK_KEY, OpCodeIndex::CENTRAL_LINK_KEY,
      OpCodeIndex::REMOTE_NAME_REQUEST,
      // OpCodeIndex::REMOTE_NAME_REQUEST_CANCEL,
      OpCodeIndex::READ_REMOTE_SUPPORTED_FEATURES,
      OpCodeIndex::READ_REMOTE_EXTENDED_FEATURES,
      OpCodeIndex::READ_REMOTE_VERSION_INFORMATION,
      OpCodeIndex::READ_CLOCK_OFFSET, OpCodeIndex::READ_LMP_HANDLE,
      OpCodeIndex::SETUP_SYNCHRONOUS_CONNECTION,
      OpCodeIndex::ACCEPT_SYNCHRONOUS_CONNECTION,
      OpCodeIndex::REJECT_SYNCHRONOUS_CONNECTION,
      OpCodeIndex::IO_CAPABILITY_REQUEST_REPLY,
      OpCodeIndex::USER_CONFIRMATION_REQUEST_REPLY,
      OpCodeIndex::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY,
      OpCodeIndex::USER_PASSKEY_REQUEST_REPLY,
      OpCodeIndex::USER_PASSKEY_REQUEST_NEGATIVE_REPLY,
      OpCodeIndex::REMOTE_OOB_DATA_REQUEST_REPLY,
      OpCodeIndex::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY,
      OpCodeIndex::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY,
      OpCodeIndex::ENHANCED_SETUP_SYNCHRONOUS_CONNECTION,
      OpCodeIndex::ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION,
      // OpCodeIndex::TRUNCATED_PAGE,
      // OpCodeIndex::TRUNCATED_PAGE_CANCEL,
      // OpCodeIndex::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST,
      // OpCodeIndex::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE,
      // OpCodeIndex::START_SYNCHRONIZATION_TRAIN,
      // OpCodeIndex::RECEIVE_SYNCHRONIZATION_TRAIN,
      OpCodeIndex::REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY,

      // LINK_POLICY
      OpCodeIndex::HOLD_MODE, OpCodeIndex::SNIFF_MODE,
      OpCodeIndex::EXIT_SNIFF_MODE, OpCodeIndex::QOS_SETUP,
      OpCodeIndex::ROLE_DISCOVERY, OpCodeIndex::SWITCH_ROLE,
      OpCodeIndex::READ_LINK_POLICY_SETTINGS,
      OpCodeIndex::WRITE_LINK_POLICY_SETTINGS,
      OpCodeIndex::READ_DEFAULT_LINK_POLICY_SETTINGS,
      OpCodeIndex::WRITE_DEFAULT_LINK_POLICY_SETTINGS,
      OpCodeIndex::FLOW_SPECIFICATION, OpCodeIndex::SNIFF_SUBRATING,

      // CONTROLLER_AND_BASEBAND
      OpCodeIndex::SET_EVENT_MASK, OpCodeIndex::RESET,
      OpCodeIndex::SET_EVENT_FILTER, OpCodeIndex::FLUSH,
      // OpCodeIndex::READ_PIN_TYPE,
      // OpCodeIndex::WRITE_PIN_TYPE,
      // OpCodeIndex::READ_STORED_LINK_KEY,
      // OpCodeIndex::WRITE_STORED_LINK_KEY,
      OpCodeIndex::DELETE_STORED_LINK_KEY, OpCodeIndex::WRITE_LOCAL_NAME,
      OpCodeIndex::READ_LOCAL_NAME, OpCodeIndex::READ_CONNECTION_ACCEPT_TIMEOUT,
      OpCodeIndex::WRITE_CONNECTION_ACCEPT_TIMEOUT,
      OpCodeIndex::READ_PAGE_TIMEOUT, OpCodeIndex::WRITE_PAGE_TIMEOUT,
      OpCodeIndex::READ_SCAN_ENABLE, OpCodeIndex::WRITE_SCAN_ENABLE,
      OpCodeIndex::READ_PAGE_SCAN_ACTIVITY,
      OpCodeIndex::WRITE_PAGE_SCAN_ACTIVITY,
      OpCodeIndex::READ_INQUIRY_SCAN_ACTIVITY,
      OpCodeIndex::WRITE_INQUIRY_SCAN_ACTIVITY,
      OpCodeIndex::READ_AUTHENTICATION_ENABLE,
      OpCodeIndex::WRITE_AUTHENTICATION_ENABLE,
      OpCodeIndex::READ_CLASS_OF_DEVICE, OpCodeIndex::WRITE_CLASS_OF_DEVICE,
      OpCodeIndex::READ_VOICE_SETTING, OpCodeIndex::WRITE_VOICE_SETTING,
      OpCodeIndex::READ_AUTOMATIC_FLUSH_TIMEOUT,
      OpCodeIndex::WRITE_AUTOMATIC_FLUSH_TIMEOUT,
      // OpCodeIndex::READ_NUM_BROADCAST_RETRANSMITS,
      // OpCodeIndex::WRITE_NUM_BROADCAST_RETRANSMITS,
      OpCodeIndex::READ_HOLD_MODE_ACTIVITY,
      OpCodeIndex::WRITE_HOLD_MODE_ACTIVITY,
      OpCodeIndex::READ_TRANSMIT_POWER_LEVEL,
      OpCodeIndex::READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE,
      OpCodeIndex::WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE,
      OpCodeIndex::SET_CONTROLLER_TO_HOST_FLOW_CONTROL,
      OpCodeIndex::HOST_BUFFER_SIZE,
      OpCodeIndex::HOST_NUMBER_OF_COMPLETED_PACKETS,
      OpCodeIndex::READ_LINK_SUPERVISION_TIMEOUT,
      OpCodeIndex::WRITE_LINK_SUPERVISION_TIMEOUT,
      OpCodeIndex::READ_NUMBER_OF_SUPPORTED_IAC,
      OpCodeIndex::READ_CURRENT_IAC_LAP, OpCodeIndex::WRITE_CURRENT_IAC_LAP,
      OpCodeIndex::SET_AFH_HOST_CHANNEL_CLASSIFICATION,
      OpCodeIndex::READ_INQUIRY_SCAN_TYPE, OpCodeIndex::WRITE_INQUIRY_SCAN_TYPE,
      OpCodeIndex::READ_INQUIRY_MODE, OpCodeIndex::WRITE_INQUIRY_MODE,
      OpCodeIndex::READ_PAGE_SCAN_TYPE, OpCodeIndex::WRITE_PAGE_SCAN_TYPE,
      OpCodeIndex::READ_AFH_CHANNEL_ASSESSMENT_MODE,
      OpCodeIndex::WRITE_AFH_CHANNEL_ASSESSMENT_MODE,
      OpCodeIndex::READ_EXTENDED_INQUIRY_RESPONSE,
      OpCodeIndex::WRITE_EXTENDED_INQUIRY_RESPONSE,
      OpCodeIndex::REFRESH_ENCRYPTION_KEY,
      OpCodeIndex::READ_SIMPLE_PAIRING_MODE,
      OpCodeIndex::WRITE_SIMPLE_PAIRING_MODE, OpCodeIndex::READ_LOCAL_OOB_DATA,
      OpCodeIndex::READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL,
      OpCodeIndex::WRITE_INQUIRY_TRANSMIT_POWER_LEVEL,
      // OpCodeIndex::READ_DEFAULT_ERRONEOUS_DATA_REPORTING,
      // OpCodeIndex::WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING,
      OpCodeIndex::ENHANCED_FLUSH, OpCodeIndex::SEND_KEYPRESS_NOTIFICATION,
      OpCodeIndex::SET_EVENT_MASK_PAGE_2,
      // OpCodeIndex::READ_FLOW_CONTROL_MODE,
      // OpCodeIndex::WRITE_FLOW_CONTROL_MODE,
      OpCodeIndex::READ_ENHANCED_TRANSMIT_POWER_LEVEL,
      OpCodeIndex::READ_LE_HOST_SUPPORT, OpCodeIndex::WRITE_LE_HOST_SUPPORT,
      // OpCodeIndex::SET_MWS_CHANNEL_PARAMETERS,
      // OpCodeIndex::SET_EXTERNAL_FRAME_CONFIGURATION,
      // OpCodeIndex::SET_MWS_SIGNALING,
      // OpCodeIndex::SET_MWS_TRANSPORT_LAYER,
      // OpCodeIndex::SET_MWS_SCAN_FREQUENCY_TABLE,
      // OpCodeIndex::SET_MWS_PATTERN_CONFIGURATION,
      // OpCodeIndex::SET_RESERVED_LT_ADDR,
      // OpCodeIndex::DELETE_RESERVED_LT_ADDR,
      // OpCodeIndex::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA,
      // OpCodeIndex::READ_SYNCHRONIZATION_TRAIN_PARAMETERS,
      // OpCodeIndex::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS,
      OpCodeIndex::READ_SECURE_CONNECTIONS_HOST_SUPPORT,
      OpCodeIndex::WRITE_SECURE_CONNECTIONS_HOST_SUPPORT,
      OpCodeIndex::READ_AUTHENTICATED_PAYLOAD_TIMEOUT,
      OpCodeIndex::WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT,
      OpCodeIndex::READ_LOCAL_OOB_EXTENDED_DATA,
      // OpCodeIndex::READ_EXTENDED_PAGE_TIMEOUT,
      // OpCodeIndex::WRITE_EXTENDED_PAGE_TIMEOUT,
      // OpCodeIndex::READ_EXTENDED_INQUIRY_LENGTH,
      // OpCodeIndex::WRITE_EXTENDED_INQUIRY_LENGTH,
      // OpCodeIndex::SET_ECOSYSTEM_BASE_INTERVAL,
      // OpCodeIndex::CONFIGURE_DATA_PATH,
      // OpCodeIndex::SET_MIN_ENCRYPTION_KEY_SIZE,

      // INFORMATIONAL_PARAMETERS
      OpCodeIndex::READ_LOCAL_VERSION_INFORMATION,
      OpCodeIndex::READ_LOCAL_SUPPORTED_FEATURES,
      OpCodeIndex::READ_LOCAL_EXTENDED_FEATURES, OpCodeIndex::READ_BUFFER_SIZE,
      OpCodeIndex::READ_BD_ADDR,
      // OpCodeIndex::READ_DATA_BLOCK_SIZE,
      OpCodeIndex::READ_LOCAL_SUPPORTED_CODECS_V1,
      // OpCodeIndex::READ_LOCAL_SIMPLE_PAIRING_OPTIONS,
      // OpCodeIndex::READ_LOCAL_SUPPORTED_CODECS_V2,
      // OpCodeIndex::READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES,
      // OpCodeIndex::READ_LOCAL_SUPPORTED_CONTROLLER_DELAY,

      // STATUS_PARAMETERS
      OpCodeIndex::READ_FAILED_CONTACT_COUNTER,
      OpCodeIndex::RESET_FAILED_CONTACT_COUNTER,
      // OpCodeIndex::READ_LINK_QUALITY,
      OpCodeIndex::READ_RSSI, OpCodeIndex::READ_AFH_CHANNEL_MAP,
      // OpCodeIndex::READ_CLOCK,
      OpCodeIndex::READ_ENCRYPTION_KEY_SIZE,
      // OpCodeIndex::GET_MWS_TRANSPORT_LAYER_CONFIGURATION,
      // OpCodeIndex::SET_TRIGGERED_CLOCK_CAPTURE,

      // TESTING
      OpCodeIndex::READ_LOOPBACK_MODE, OpCodeIndex::WRITE_LOOPBACK_MODE,
      OpCodeIndex::ENABLE_DEVICE_UNDER_TEST_MODE,
      OpCodeIndex::WRITE_SIMPLE_PAIRING_DEBUG_MODE,
      OpCodeIndex::WRITE_SECURE_CONNECTIONS_TEST_MODE,

      // LE_CONTROLLER
      OpCodeIndex::LE_SET_EVENT_MASK, OpCodeIndex::LE_READ_BUFFER_SIZE_V1,
      OpCodeIndex::LE_READ_LOCAL_SUPPORTED_FEATURES,
      OpCodeIndex::LE_SET_RANDOM_ADDRESS,
      OpCodeIndex::LE_SET_ADVERTISING_PARAMETERS,
      OpCodeIndex::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER,
      OpCodeIndex::LE_SET_ADVERTISING_DATA,
      OpCodeIndex::LE_SET_SCAN_RESPONSE_DATA,
      OpCodeIndex::LE_SET_ADVERTISING_ENABLE,
      OpCodeIndex::LE_SET_SCAN_PARAMETERS, OpCodeIndex::LE_SET_SCAN_ENABLE,
      OpCodeIndex::LE_CREATE_CONNECTION,
      OpCodeIndex::LE_CREATE_CONNECTION_CANCEL,
      OpCodeIndex::LE_READ_FILTER_ACCEPT_LIST_SIZE,
      OpCodeIndex::LE_CLEAR_FILTER_ACCEPT_LIST,
      OpCodeIndex::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST,
      OpCodeIndex::LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST,
      OpCodeIndex::LE_CONNECTION_UPDATE,
      OpCodeIndex::LE_SET_HOST_CHANNEL_CLASSIFICATION,
      OpCodeIndex::LE_READ_CHANNEL_MAP, OpCodeIndex::LE_READ_REMOTE_FEATURES,
      OpCodeIndex::LE_ENCRYPT, OpCodeIndex::LE_RAND,
      OpCodeIndex::LE_START_ENCRYPTION,
      OpCodeIndex::LE_LONG_TERM_KEY_REQUEST_REPLY,
      OpCodeIndex::LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY,
      OpCodeIndex::LE_READ_SUPPORTED_STATES, OpCodeIndex::LE_RECEIVER_TEST_V1,
      OpCodeIndex::LE_TRANSMITTER_TEST_V1, OpCodeIndex::LE_TEST_END,
      OpCodeIndex::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY,
      OpCodeIndex::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY,
      // OpCodeIndex::LE_SET_DATA_LENGTH,
      OpCodeIndex::LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH,
      OpCodeIndex::LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH,
      // OpCodeIndex::LE_READ_LOCAL_P_256_PUBLIC_KEY,
      // OpCodeIndex::LE_GENERATE_DHKEY_V1,
      // OpCodeIndex::LE_ADD_DEVICE_TO_RESOLVING_LIST,
      // OpCodeIndex::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST,
      // OpCodeIndex::LE_CLEAR_RESOLVING_LIST,
      // OpCodeIndex::LE_READ_RESOLVING_LIST_SIZE,
      // OpCodeIndex::LE_READ_PEER_RESOLVABLE_ADDRESS,
      // OpCodeIndex::LE_READ_LOCAL_RESOLVABLE_ADDRESS,
      // OpCodeIndex::LE_SET_ADDRESS_RESOLUTION_ENABLE,
      // OpCodeIndex::LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT,
      OpCodeIndex::LE_READ_MAXIMUM_DATA_LENGTH,
      // OpCodeIndex::LE_READ_PHY,
      // OpCodeIndex::LE_SET_DEFAULT_PHY,
      // OpCodeIndex::LE_SET_PHY,
      // OpCodeIndex::LE_RECEIVER_TEST_V2,
      // OpCodeIndex::LE_TRANSMITTER_TEST_V2,
      OpCodeIndex::LE_SET_ADVERTISING_SET_RANDOM_ADDRESS,
      OpCodeIndex::LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
      OpCodeIndex::LE_SET_EXTENDED_ADVERTISING_DATA,
      OpCodeIndex::LE_SET_EXTENDED_SCAN_RESPONSE_DATA,
      OpCodeIndex::LE_SET_EXTENDED_ADVERTISING_ENABLE,
      OpCodeIndex::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH,
      OpCodeIndex::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS,
      OpCodeIndex::LE_REMOVE_ADVERTISING_SET,
      OpCodeIndex::LE_CLEAR_ADVERTISING_SETS,
      // OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_PARAM,
      // OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_DATA,
      // OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_ENABLE,
      OpCodeIndex::LE_SET_EXTENDED_SCAN_PARAMETERS,
      OpCodeIndex::LE_SET_EXTENDED_SCAN_ENABLE,
      OpCodeIndex::LE_EXTENDED_CREATE_CONNECTION,
      // OpCodeIndex::LE_PERIODIC_ADVERTISING_CREATE_SYNC,
      // OpCodeIndex::LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL,
      // OpCodeIndex::LE_PERIODIC_ADVERTISING_TERMINATE_SYNC,
      // OpCodeIndex::LE_ADD_DEVICE_TO_PERIODIC_ADVERTISING_LIST,
      // OpCodeIndex::LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISING_LIST,
      // OpCodeIndex::LE_CLEAR_PERIODIC_ADVERTISING_LIST,
      // OpCodeIndex::LE_READ_PERIODIC_ADVERTISING_LIST_SIZE,
      // OpCodeIndex::LE_READ_TRANSMIT_POWER,
      OpCodeIndex::LE_READ_RF_PATH_COMPENSATION_POWER,
      OpCodeIndex::LE_WRITE_RF_PATH_COMPENSATION_POWER,
      // OpCodeIndex::LE_SET_PRIVACY_MODE,
      // OpCodeIndex::LE_RECEIVER_TEST_V3,
      // OpCodeIndex::LE_TRANSMITTER_TEST_V3,
      // OpCodeIndex::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS,
      // OpCodeIndex::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE,
      // OpCodeIndex::LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE,
      // OpCodeIndex::LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS,
      // OpCodeIndex::LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS,
      // OpCodeIndex::LE_CONNECTION_CTE_REQUEST_ENABLE,
      // OpCodeIndex::LE_CONNECTION_CTE_RESPONSE_ENABLE,
      // OpCodeIndex::LE_READ_ANTENNA_INFORMATION,
      // OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE,
      // OpCodeIndex::LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
      // OpCodeIndex::LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER,
      // OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
      // OpCodeIndex::LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
      // OpCodeIndex::LE_GENERATE_DHKEY_V2,
      // OpCodeIndex::LE_MODIFY_SLEEP_CLOCK_ACCURACY,
      OpCodeIndex::LE_READ_BUFFER_SIZE_V2,
      // OpCodeIndex::LE_READ_ISO_TX_SYNC,
      // OpCodeIndex::LE_SET_CIG_PARAMETERS,
      // OpCodeIndex::LE_SET_CIG_PARAMETERS_TEST,
      // OpCodeIndex::LE_CREATE_CIS,
      // OpCodeIndex::LE_REMOVE_CIG,
      // OpCodeIndex::LE_ACCEPT_CIS_REQUEST,
      // OpCodeIndex::LE_REJECT_CIS_REQUEST,
      // OpCodeIndex::LE_CREATE_BIG,
      // OpCodeIndex::LE_CREATE_BIG_TEST,
      // OpCodeIndex::LE_TERMINATE_BIG,
      // OpCodeIndex::LE_BIG_CREATE_SYNC,
      // OpCodeIndex::LE_BIG_TERMINATE_SYNC,
      // OpCodeIndex::LE_REQUEST_PEER_SCA,
      // OpCodeIndex::LE_SETUP_ISO_DATA_PATH,
      // OpCodeIndex::LE_REMOVE_ISO_DATA_PATH,
      // OpCodeIndex::LE_ISO_TRANSMIT_TEST,
      // OpCodeIndex::LE_ISO_RECEIVE_TEST,
      // OpCodeIndex::LE_ISO_READ_TEST_COUNTERS,
      // OpCodeIndex::LE_ISO_TEST_END,
      OpCodeIndex::LE_SET_HOST_FEATURE,
      // OpCodeIndex::LE_READ_ISO_LINK_QUALITY,
      // OpCodeIndex::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL,
      // OpCodeIndex::LE_READ_REMOTE_TRANSMIT_POWER_LEVEL,
      // OpCodeIndex::LE_SET_PATH_LOSS_REPORTING_PARAMETERS,
      // OpCodeIndex::LE_SET_PATH_LOSS_REPORTING_ENABLE,
      // OpCodeIndex::LE_SET_TRANSMIT_POWER_REPORTING_ENABLE,
      // OpCodeIndex::LE_TRANSMITTER_TEST_V4,
      // OpCodeIndex::LE_SET_DATA_RELATED_ADDRESS_CHANGES,
      // OpCodeIndex::LE_SET_DEFAULT_SUBRATE,
      // OpCodeIndex::LE_SUBRATE_REQUEST,
  };

  std::array<uint8_t, 64> value{};
  for (auto command : supported_commands) {
    int index = static_cast<int>(command);
    value[index / 10] |= 1U << (index % 10);
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
    }
    output_value = static_cast<T>(parsed_value);
    return true;
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
    unsigned long long parsed_value =
        std::stoull(value[static_cast<int>(n)].asString(), nullptr, 0);
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
    unsigned long long parsed_value =
        std::stoull(value[static_cast<int>(n)].asString(), nullptr, 0);
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
    : supported_commands(std::move(SupportedCommands())),
      lmp_features({Page0LmpFeatures(), 0, Page2LmpFeatures()}),
      le_features(LlFeatures()) {
  if (!CheckSupportedFeatures()) {
    LOG_INFO(
        "Warning: initial LMP and/or LE are not consistent. Please make sure"
        " that the features are correct w.r.t. the rules described"
        " in Vol 2, Part C 3.5 Feature requirements");
  }

  if (!CheckSupportedCommands()) {
    LOG_INFO(
        "Warning: initial supported commands are not consistent. Please make"
        " sure that the supported commands are correct w.r.t. the rules"
        " described in Vol 4, Part E § 3 Overview of commands and events");
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

  // Configuration options.

  le_supported = root.get("le_supported", Json::Value(true)).asBool();
  br_supported = root.get("br_supported", Json::Value(true)).asBool();

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
  ParseUint(root, "num_supported_iac", num_supported_iac);
  ParseUint(root, "le_advertising_physical_channel_tx_power",
            le_advertising_physical_channel_tx_power);

  ParseUintArray(root, "lmp_features", lmp_features);
  ParseUintVector(root, "supported_standard_codecs", supported_standard_codecs);
  ParseUintVector(root, "supported_vendor_specific_codecs",
                  supported_vendor_specific_codecs);

  ParseUint(root, "le_filter_accept_list_size", le_filter_accept_list_size);
  ParseUint(root, "le_resolving_list_size", le_resolving_list_size);
  ParseUint(root, "le_supported_states", le_supported_states);

  ParseUint(root, "le_max_advertising_data_length",
            le_max_advertising_data_length);
  ParseUint(root, "le_num_supported_advertising_sets",
            le_num_supported_advertising_sets);

  ParseUintVector(root, "le_vendor_capabilities", le_vendor_capabilities);

  this->hci_version = static_cast<HciVersion>(hci_version);
  this->lmp_version = static_cast<LmpVersion>(lmp_version);

  // Transport flag takes precedence over LMP features.
  if (le_supported && br_supported) {
    lmp_features[0] |= static_cast<int64_t>(
        LMPFeaturesPage0Bits::SIMULTANEOUS_LE_AND_BR_CONTROLLER);
    lmp_features[0] |=
        static_cast<int64_t>(LMPFeaturesPage0Bits::LE_SUPPORTED_CONTROLLER);
  } else if (le_supported) {
    lmp_features[0] &= ~static_cast<int64_t>(
        LMPFeaturesPage0Bits::SIMULTANEOUS_LE_AND_BR_CONTROLLER);
    lmp_features[0] |=
        static_cast<int64_t>(LMPFeaturesPage0Bits::LE_SUPPORTED_CONTROLLER);
  } else if (br_supported) {
    lmp_features[0] &= ~static_cast<int64_t>(
        LMPFeaturesPage0Bits::SIMULTANEOUS_LE_AND_BR_CONTROLLER);
    lmp_features[0] &=
        ~static_cast<int64_t>(LMPFeaturesPage0Bits::LE_SUPPORTED_CONTROLLER);
  } else {
    LOG_ERROR("le_supported or br_supported must be set in the configuration");
    br_supported = true;
    le_supported = true;
    lmp_features[0] |= static_cast<int64_t>(
        LMPFeaturesPage0Bits::SIMULTANEOUS_LE_AND_BR_CONTROLLER);
    lmp_features[0] |=
        static_cast<int64_t>(LMPFeaturesPage0Bits::LE_SUPPORTED_CONTROLLER);
  }

  if (!CheckSupportedFeatures()) {
    LOG_INFO(
        "Warning: the LMP and/or LE are not consistent. Please make sure"
        " that the features are correct w.r.t. the rules described"
        " in Vol 2, Part C 3.5 Feature requirements");
  } else {
    LOG_INFO("LMP and LE features successfully validated");
  }
}

bool ControllerProperties::CheckSupportedFeatures() const {
  // Vol 2, Part C § 3.3 Feature mask definition.
  // Check for reserved or deprecated feature bits.
  //
  // Note: the specification for v1.0 and v1.1 is no longer available for
  // download, the reserved feature bits are copied over from v1.2.
  uint64_t lmp_page_0_reserved_bits = 0;
  uint64_t lmp_page_2_reserved_bits = 0;
  switch (lmp_version) {
    case bluetooth::hci::LmpVersion::V_1_0B:
      lmp_page_0_reserved_bits = UINT64_C(0x7fffe7e407000000);
      lmp_page_2_reserved_bits = UINT64_C(0xffffffffffffffff);
      break;
    case bluetooth::hci::LmpVersion::V_1_1:
      lmp_page_0_reserved_bits = UINT64_C(0x7fffe7e407000000);
      lmp_page_2_reserved_bits = UINT64_C(0xffffffffffffffff);
      break;
    case bluetooth::hci::LmpVersion::V_1_2:
      lmp_page_0_reserved_bits = UINT64_C(0x7fffe7e407000000);
      lmp_page_2_reserved_bits = UINT64_C(0xffffffffffffffff);
      break;
    case bluetooth::hci::LmpVersion::V_2_0:
      lmp_page_0_reserved_bits = UINT64_C(0x7fff066401000000);
      lmp_page_2_reserved_bits = UINT64_C(0xffffffffffffffff);
      break;
    case bluetooth::hci::LmpVersion::V_2_1:
      lmp_page_0_reserved_bits = UINT64_C(0x7c86006401000000);
      lmp_page_2_reserved_bits = UINT64_C(0xffffffffffffffff);
      break;
    case bluetooth::hci::LmpVersion::V_3_0:
      lmp_page_0_reserved_bits = UINT64_C(0x7886006401000000);
      lmp_page_2_reserved_bits = UINT64_C(0xffffffffffffffff);
      break;
    case bluetooth::hci::LmpVersion::V_4_0:
      lmp_page_0_reserved_bits = UINT64_C(0x7884000401000000);
      lmp_page_2_reserved_bits = UINT64_C(0xffffffffffffffff);
      break;
    case bluetooth::hci::LmpVersion::V_4_1:
      lmp_page_0_reserved_bits = UINT64_C(0x7884000401000000);
      lmp_page_2_reserved_bits = UINT64_C(0xfffffffffffff480);
      break;
    case bluetooth::hci::LmpVersion::V_4_2:
      lmp_page_0_reserved_bits = UINT64_C(0x7884000401000000);
      lmp_page_2_reserved_bits = UINT64_C(0xfffffffffffff480);
      break;
    case bluetooth::hci::LmpVersion::V_5_0:
      lmp_page_0_reserved_bits = UINT64_C(0x7884000401000100);
      lmp_page_2_reserved_bits = UINT64_C(0xfffffffffffff480);
      break;
    case bluetooth::hci::LmpVersion::V_5_1:
      lmp_page_0_reserved_bits = UINT64_C(0x7884000401000100);
      lmp_page_2_reserved_bits = UINT64_C(0xfffffffffffff080);
      break;
    case bluetooth::hci::LmpVersion::V_5_2:
      lmp_page_0_reserved_bits = UINT64_C(0x7884000401000100);
      lmp_page_2_reserved_bits = UINT64_C(0xfffffffffffff080);
      break;
    case bluetooth::hci::LmpVersion::V_5_3:
    default:
      lmp_page_0_reserved_bits = UINT64_C(0x7884000401000100);
      lmp_page_2_reserved_bits = UINT64_C(0xfffffffffffff080);
      break;
  };

  if ((lmp_page_0_reserved_bits & lmp_features[0]) != 0) {
    LOG_INFO("The page 0 feature bits 0x%016" PRIx64
             " are reserved in the specification %s",
             lmp_page_0_reserved_bits & lmp_features[0],
             LmpVersionText(lmp_version).c_str());
    return false;
  }

  if ((lmp_page_2_reserved_bits & lmp_features[2]) != 0) {
    LOG_INFO("The page 2 feature bits 0x%016" PRIx64
             " are reserved in the specification %s",
             lmp_page_2_reserved_bits & lmp_features[2],
             LmpVersionText(lmp_version).c_str());
    return false;
  }

  // Vol 2, Part C § 3.5 Feature requirements.
  // RootCanal always support BR/EDR mode, this function implements
  // the feature requirements from the subsection 1. Devices supporting BR/EDR.
  //
  // Note: the feature requirements were introduced in version v5.1 of the
  // specification, for previous versions it is assumed that the same
  // requirements apply for the subset of defined feature bits.

  // The features listed in Table 3.5 are mandatory in this version of the
  // specification (see Section 3.1) and these feature bits shall be set.
  if (!SupportsLMPFeature(LMPFeaturesPage0Bits::ENCRYPTION) ||
      !SupportsLMPFeature(
          LMPFeaturesPage0Bits::SECURE_SIMPLE_PAIRING_CONTROLLER) ||
      !SupportsLMPFeature(LMPFeaturesPage0Bits::ENCAPSULATED_PDU)) {
    LOG_INFO("Table 3.5 validation failed");
    return false;
  }

  // The features listed in Table 3.6 are forbidden in this version of the
  // specification and these feature bits shall not be set.
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::BR_EDR_NOT_SUPPORTED)) {
    LOG_INFO("Table 3.6 validation failed");
    return false;
  }

  // For each row of Table 3.7, either every feature named in that row shall be
  // supported or none of the features named in that row shall be supported.
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::SNIFF_MODE) !=
      SupportsLMPFeature(LMPFeaturesPage0Bits::SNIFF_SUBRATING)) {
    LOG_INFO("Table 3.7 validation failed");
    return false;
  }

  // For each row of Table 3.8, not more than one feature in that row shall be
  // supported.
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::BROADCAST_ENCRYPTION) &&
      SupportsLMPFeature(LMPFeaturesPage2Bits::COARSE_CLOCK_ADJUSTMENT)) {
    LOG_INFO("Table 3.8 validation failed");
    return false;
  }

  // For each row of Table 3.9, if the feature named in the first column is
  // supported then the feature named in the second column shall be supported.
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::ROLE_SWITCH) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::SLOT_OFFSET)) {
    LOG_INFO("Table 3.9 validation failed; expected Slot Offset");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::HV2_PACKETS) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK)) {
    LOG_INFO("Table 3.9 validation failed; expected Sco Link");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::HV3_PACKETS) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK)) {
    LOG_INFO("Table 3.9 validation failed; expected Sco Link");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::M_LAW_LOG_SYNCHRONOUS_DATA) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Sco Link or Extended Sco Link");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::A_LAW_LOG_SYNCHRONOUS_DATA) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Sco Link or Extended Sco Link");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::CVSD_SYNCHRONOUS_DATA) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Sco Link or Extended Sco Link");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::TRANSPARENT_SYNCHRONOUS_DATA) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Sco Link or Extended Sco Link");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ACL_3_MB_S_MODE) &&
      !SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ACL_2_MB_S_MODE)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Enhanced Data Rate ACL 2Mb/s "
        "mode");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::EV4_PACKETS) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK)) {
    LOG_INFO("Table 3.9 validation failed; expected Extended Sco Link");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::EV5_PACKETS) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK)) {
    LOG_INFO("Table 3.9 validation failed; expected Extended Sco Link");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CLASSIFICATION_PERIPHERAL) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CAPABLE_PERIPHERAL)) {
    LOG_INFO("Table 3.9 validation failed; expected AFH Capable Peripheral");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage0Bits::LMP_3_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS) &&
      !SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ACL_2_MB_S_MODE)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Enhanced Data Rate ACL 2Mb/s "
        "mode");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage0Bits::LMP_5_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS) &&
      !SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ACL_2_MB_S_MODE)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Enhanced Data Rate ACL 2Mb/s "
        "mode");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CLASSIFICATION_CENTRAL) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CAPABLE_CENTRAL)) {
    LOG_INFO("Table 3.9 validation failed; expected AFH Capable Central");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ESCO_2_MB_S_MODE) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK)) {
    LOG_INFO("Table 3.9 validation failed; expected Extended Sco Link");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ESCO_3_MB_S_MODE) &&
      !SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ESCO_2_MB_S_MODE)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Enhanced Data Rate eSCO 2Mb/s "
        "mode");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage0Bits::LMP_3_SLOT_ENHANCED_DATA_RATE_ESCO_PACKETS) &&
      !SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ESCO_2_MB_S_MODE)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Enhanced Data Rate eSCO 2Mb/s "
        "mode");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_INQUIRY_RESPONSE) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::RSSI_WITH_INQUIRY_RESULTS)) {
    LOG_INFO("Table 3.9 validation failed; expected RSSI with Inquiry Results");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage0Bits::SIMULTANEOUS_LE_AND_BR_CONTROLLER) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::LE_SUPPORTED_CONTROLLER)) {
    LOG_INFO("Table 3.9 validation failed; expected LE Supported (Controller)");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::ERRONEOUS_DATA_REPORTING) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Sco Link or Extended Sco Link");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage0Bits::ENHANCED_POWER_CONTROL) &&
      (!SupportsLMPFeature(LMPFeaturesPage0Bits::POWER_CONTROL_REQUESTS) ||
       !SupportsLMPFeature(LMPFeaturesPage0Bits::POWER_CONTROL))) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Power Control Request and Power "
        "Control");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage2Bits::
              CONNECTIONLESS_PERIPHERAL_BROADCAST_TRANSMITTER_OPERATION) &&
      !SupportsLMPFeature(LMPFeaturesPage2Bits::SYNCHRONIZATION_TRAIN)) {
    LOG_INFO("Table 3.9 validation failed; expected Synchronization Train");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage2Bits::
              CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVER_OPERATION) &&
      !SupportsLMPFeature(LMPFeaturesPage2Bits::SYNCHRONIZATION_SCAN)) {
    LOG_INFO("Table 3.9 validation failed; expected Synchronization Scan");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage2Bits::GENERALIZED_INTERLACED_SCAN) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::INTERLACED_INQUIRY_SCAN) &&
      !SupportsLMPFeature(LMPFeaturesPage0Bits::INTERLACED_PAGE_SCAN)) {
    LOG_INFO(
        "Table 3.9 validation failed; expected Interlaced Inquiry Scan or "
        "Interlaced Page Scan");
    return false;
  }
  if (SupportsLMPFeature(LMPFeaturesPage2Bits::COARSE_CLOCK_ADJUSTMENT) &&
      (!SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CAPABLE_PERIPHERAL) ||
       !SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CAPABLE_CENTRAL) ||
       !SupportsLMPFeature(LMPFeaturesPage2Bits::SYNCHRONIZATION_TRAIN) ||
       !SupportsLMPFeature(LMPFeaturesPage2Bits::SYNCHRONIZATION_SCAN))) {
    LOG_INFO(
        "Table 3.9 validation failed; expected AFH Capable Central/Peripheral "
        "and Synchronization Train/Scan");
    return false;
  }
  if (SupportsLMPFeature(
          LMPFeaturesPage2Bits::SECURE_CONNECTIONS_CONTROLLER_SUPPORT) &&
      (!SupportsLMPFeature(LMPFeaturesPage0Bits::PAUSE_ENCRYPTION) ||
       !SupportsLMPFeature(LMPFeaturesPage2Bits::PING))) {
    LOG_INFO("Table 3.9 validation failed; expected Pause Encryption and Ping");
    return false;
  }

  return true;
}

bool ControllerProperties::CheckSupportedCommands() const {
  // Vol 4, Part E § 3 Overview of commands and events.
  //
  // A Controller shall support the command or event if it is shown as mandatory
  // for at least one of the transports (i.e. BR/EDR or LE) that the Controller
  // supports, otherwise the Controller may support the command or event if it
  // is shown as optional for at least one of the transports that the Controller
  // supports, otherwise it shall not support the command or event.
  //
  // RootCanal always support BR/EDR and LE modes, this function implements
  // the feature requirements from both BR/EDR and LE commands.

  // Some controller features are always set as supported in the RootCanal
  // controller:
  //  - The controller supports transmitting packets.
  //  - The controller supports receiving packets.
  //  - The controller supports Connection State.
  //  - The controller supports Initiating State.
  //  - The controller supports Synchronization State.
  //  - The controller supports Scanning State.
  //  - The controller supports Advertising State.
  //  - The controller supports Central Role.
  //  - The controller supports Peripheral Role.
  //  - The controller supports LE transport.
  //  - The controller supports Inquiry.
  // Some controller features are always set as not supported in the RootCanal
  // controller:
  //  - The controller can not change its sleep clock accuracy.
  //  - The controller does not support Test Mode.
  //  - The controller does not support Data block based flow control.
  //  - The controller does not support Truncated Page State.

  enum Requirement {
    kMandatory,
    kOptional,
    kExcluded,
  };

  constexpr auto mandatory = kMandatory;
  constexpr auto optional = kOptional;
  constexpr auto excluded = kExcluded;
  auto mandatory_or_excluded = [](bool cond) {
    return cond ? kMandatory : kExcluded;
  };
  auto mandatory_or_optional = [](bool cond) {
    return cond ? kMandatory : kOptional;
  };
  auto optional_or_excluded = [](bool cond) {
    return cond ? kMandatory : kExcluded;
  };
  auto mandatory_or_optional_or_excluded = [](bool cond1, bool cond2) {
    return cond1 ? kMandatory : cond2 ? kOptional : kExcluded;
  };

  // A Controller shall support the command or event if it is shown as
  // mandatory for at least one of the transports (i.e. BR/EDR or LE) that
  // the Controller supports, otherwise the Controller may support the command
  // or event if it is shown as optional for at least one of the transports
  // that the Controller supports, otherwise it shall not support the
  // command or event.
  auto check_command_requirement =
      [](bool br_supported, Requirement br_requirement, bool le_supported,
         Requirement le_requirement, bool command_supported) {
        Requirement command_requirement =
            !br_supported   ? le_requirement
            : !le_supported ? br_requirement
            : le_requirement == kMandatory || br_requirement == kMandatory
                ? kMandatory
            : le_requirement == kOptional || br_requirement == kOptional
                ? kOptional
                : kExcluded;

        if (command_requirement == kMandatory && !command_supported) {
          return false;
        }
        if (command_requirement == kExcluded && command_supported) {
          return false;
        }
        return true;
      };

  // C1: Mandatory if the LE Controller supports transmitting packets, otherwise
  // excluded.
  auto c1 = mandatory;
  // C2: Mandatory if the LE Controller supports receiving packets, otherwise
  // excluded.
  auto c2 = mandatory;
  // C3: Mandatory if the LE Controller supports Connection State, otherwise
  // excluded.
  auto c3 = mandatory;
  // C4: Mandatory if LE Feature (LE Encryption) is supported, otherwise
  // excluded.
  auto c4 =
      mandatory_or_excluded(SupportsLLFeature(LLFeaturesBits::LE_ENCRYPTION));
  // C6: Mandatory if LE Feature (Connection Parameters Request procedure) is
  // supported, otherwise excluded.
  auto c6 = mandatory_or_excluded(SupportsLLFeature(
      LLFeaturesBits::CONNECTION_PARAMETERS_REQUEST_PROCEDURE));
  // C7: Mandatory if LE Feature (LE Encryption) and LE Feature (LE Ping) are
  // supported, otherwise excluded.
  auto c7 =
      mandatory_or_excluded(SupportsLLFeature(LLFeaturesBits::LE_ENCRYPTION) &&
                            SupportsLLFeature(LLFeaturesBits::LE_PING));
  // C8: Mandatory if LE Feature (LE Data Packet Length Extension) is supported,
  // otherwise optional.
  auto c8 = mandatory_or_optional(
      SupportsLLFeature(LLFeaturesBits::LE_DATA_PACKET_LENGTH_EXTENSION));
  // C9: Mandatory if LE Feature (LL Privacy) is supported, otherwise excluded.
  auto c9 =
      mandatory_or_excluded(SupportsLLFeature(LLFeaturesBits::LL_PRIVACY));
  // C10: Optional if LE Feature (LL Privacy) is supported, otherwise excluded.
  auto c10 =
      optional_or_excluded(SupportsLLFeature(LLFeaturesBits::LL_PRIVACY));
  // C11: Mandatory if LE Feature (LE 2M PHY) or LE Feature (LE Coded PHY) is
  // supported, otherwise optional.
  auto c11 =
      mandatory_or_optional(SupportsLLFeature(LLFeaturesBits::LE_2M_PHY) ||
                            SupportsLLFeature(LLFeaturesBits::LE_CODED_PHY));
  // C12: Mandatory if LE Feature (LE 2M PHY) or LE Feature (LE Coded PHY) or
  // LE Feature (Stable Modulation Index - Transmitter) is supported, otherwise
  // optional if the LE Controller supports transmitting packets, otherwise
  // excluded.
  auto c12 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_2M_PHY) ||
      SupportsLLFeature(LLFeaturesBits::LE_CODED_PHY) ||
      SupportsLLFeature(LLFeaturesBits::STABLE_MODULATION_INDEX_TRANSMITTER));
  // C13: Mandatory if LE Feature (LE 2M PHY) or LE Feature (LE Coded PHY) or LE
  // Feature (Stable Modulation Index - Receiver) is supported, otherwise
  // optional if the LE Controller supports receiving packets, otherwise
  // excluded.
  auto c13 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_2M_PHY) ||
      SupportsLLFeature(LLFeaturesBits::LE_CODED_PHY) ||
      SupportsLLFeature(LLFeaturesBits::STABLE_MODULATION_INDEX_RECEIVER));
  // C15: Mandatory if LE Controller supports transmitting scannable
  // advertisements, otherwise excluded.
  auto c15 = mandatory;
  // C16: Mandatory if LE Feature (Periodic Advertising) is supported and the LE
  // Controller supports both Scanning State and Synchronization State,
  // otherwise excluded.
  auto c16 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_PERIODIC_ADVERTISING));
  // C17: Mandatory if LE Feature (Extended Advertising) is supported and the LE
  // Controller supports Advertising State, otherwise excluded.
  auto c17 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_EXTENDED_ADVERTISING));
  // C18: Mandatory if LE Feature (Periodic Advertising) is supported and the LE
  // Controller supports Advertising State, otherwise excluded.
  auto c18 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_PERIODIC_ADVERTISING));
  // C19: Mandatory if LE Feature (Extended Advertising) is supported and the LE
  // Controller supports Scanning State, otherwise excluded.
  auto c19 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_EXTENDED_ADVERTISING));
  // C20: Mandatory if LE Feature (Extended Advertising) is supported and the LE
  // Controller supports Initiating State, otherwise excluded.
  auto c20 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_EXTENDED_ADVERTISING));
  // C21: Mandatory if LE Feature (Periodic Advertising) is supported and the LE
  // Controller supports Synchronization State, otherwise excluded.
  auto c21 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_PERIODIC_ADVERTISING));
  // C22: Mandatory if the LE Controller supports sending Transmit Power in
  // advertisements or if LE Feature (LE Power Control Request) is supported,
  // otherwise optional.
  auto c22 = mandatory;
  // C23: Mandatory if LE Feature (LE Channel Selection Algorithm #2) is
  // supported, otherwise excluded.
  //
  // C24: Mandatory if the LE Controller supports
  // Connection State and either LE Feature (LL Privacy) or LE Feature (Extended
  // Advertising) is supported, otherwise optional if the LE Controller supports
  // Connection State, otherwise excluded.
  //
  // C25: Mandatory if LE Feature
  // (Connection CTE Request) is supported, otherwise excluded.
  auto c25 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTION_CTE_REQUEST));
  // C26: Mandatory if LE Feature (Connection CTE Response) is supported,
  // otherwise excluded.
  auto c26 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTION_CTE_RESPONSE));
  // C27: Mandatory if LE Feature (Connectionless CTE Transmitter) is supported,
  // otherwise excluded.
  auto c27 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTIONLESS_CTE_TRANSMITTER));
  // C28: Mandatory if LE Feature (Connectionless CTE Receiver) is supported,
  // otherwise excluded.
  auto c28 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTIONLESS_CTE_RECEIVER));
  // C29: Mandatory if LE Feature (Connection CTE Response) or LE Feature
  // (Connectionless CTE Transmitter) is supported, otherwise optional if the LE
  // Controller supports transmitting packets, otherwise excluded.
  auto c29 = mandatory_or_optional(
      SupportsLLFeature(LLFeaturesBits::CONNECTION_CTE_RESPONSE) ||
      SupportsLLFeature(LLFeaturesBits::CONNECTIONLESS_CTE_TRANSMITTER));
  // C30: Mandatory if LE Feature (Connection CTE Request) or LE Feature
  // (Connectionless CTE Receiver) is supported, otherwise optional if the LE
  // Controller supports receiving packets, otherwise excluded.
  auto c30 = mandatory_or_optional(
      SupportsLLFeature(LLFeaturesBits::CONNECTION_CTE_REQUEST) ||
      SupportsLLFeature(LLFeaturesBits::CONNECTIONLESS_CTE_RECEIVER));
  // C31: Mandatory if LE Feature (Connection CTE Request) or LE Feature
  // (Connection CTE Response) or LE Feature (Connectionless CTE Transmitter) or
  // LE Feature (Connectionless CTE Receiver) is supported, otherwise excluded.
  auto c31 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTION_CTE_REQUEST) ||
      SupportsLLFeature(LLFeaturesBits::CONNECTION_CTE_RESPONSE) ||
      SupportsLLFeature(LLFeaturesBits::CONNECTIONLESS_CTE_TRANSMITTER) ||
      SupportsLLFeature(LLFeaturesBits::CONNECTIONLESS_CTE_RECEIVER));
  // C32: Mandatory if LE Feature (Periodic Advertising Sync Transfer –
  // Recipient) is supported, otherwise optional if LE Feature (Periodic
  // Advertising) is supported and the LE Controller supports Synchronization
  // State, otherwise excluded.
  auto c32 = mandatory_or_optional_or_excluded(
      SupportsLLFeature(
          LLFeaturesBits::PERIODIC_ADVERTISING_SYNC_TRANSFER_RECIPIENT),
      SupportsLLFeature(LLFeaturesBits::LE_PERIODIC_ADVERTISING));
  // C33: Mandatory if LE Feature (Periodic Advertising Sync Transfer – Sender)
  // is supported and the LE Controller supports Scanning State, otherwise
  // excluded.
  auto c33 = mandatory_or_excluded(SupportsLLFeature(
      LLFeaturesBits::PERIODIC_ADVERTISING_SYNC_TRANSFER_SENDER));
  // C34: Mandatory if LE Feature (Periodic Advertising Sync Transfer – Sender)
  // is supported and the LE Controller supports Advertising State, otherwise
  // excluded.
  auto c34 = mandatory_or_excluded(SupportsLLFeature(
      LLFeaturesBits::PERIODIC_ADVERTISING_SYNC_TRANSFER_SENDER));
  // C35: Mandatory if LE Feature (Periodic Advertising Sync Transfer –
  // Recipient) is supported, otherwise excluded.
  auto c35 = mandatory_or_excluded(SupportsLLFeature(
      LLFeaturesBits::PERIODIC_ADVERTISING_SYNC_TRANSFER_RECIPIENT));
  // C36: Mandatory if the LE Controller supports Central role or supports both
  // Peripheral role and LE Feature (Channel Classification), otherwise optional
  // if LE Feature (Extended Advertising) is supported and the LE Controller
  // supports Advertising State or if LE Feature (Isochronous Broadcaster) is
  // supported, otherwise excluded.
  auto c36 = mandatory;
  // C37: Mandatory if the LE Controller can change its sleep clock accuracy,
  // otherwise excluded.
  auto c37 = excluded;
  // C38: Mandatory if LE Feature (Connected Isochronous Stream - Central) or
  // LE Feature (Connected Isochronous Stream - Peripheral) is supported,
  // otherwise excluded.
  //
  // C39: Mandatory if LE Feature (Connected Isochronous
  // Stream - Central) is supported, otherwise excluded.
  auto c39 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL));
  // C40: Mandatory if LE Feature (Connected Isochronous Stream - Peripheral) is
  // supported, otherwise excluded.
  auto c40 = mandatory_or_excluded(SupportsLLFeature(
      LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL));
  // C41: Mandatory if LE Feature (Isochronous Broadcaster) is supported,
  // otherwise excluded.
  auto c41 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::ISOCHRONOUS_BROADCASTER));
  // C42: Mandatory if LE Feature (Synchronized Receiver role) is supported,
  // otherwise excluded.
  auto c42 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::SYNCHRONIZED_RECEIVER));
  // C44: Mandatory if LE Feature (Sleep Clock Accuracy Updates) and either LE
  // Feature (Connected Isochronous Stream - Central) or LE Feature (Connected
  // Isochronous Stream - Peripheral) are supported, otherwise optional if LE
  // Feature (Sleep Clock Accuracy Updates) is supported, otherwise excluded.
  auto c44 = mandatory_or_optional_or_excluded(
      SupportsLLFeature(LLFeaturesBits::SLEEP_CLOCK_ACCURACY_UPDATES) &&
          (SupportsLLFeature(
               LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL) ||
           SupportsLLFeature(
               LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL)),
      SupportsLLFeature(LLFeaturesBits::SLEEP_CLOCK_ACCURACY_UPDATES));
  // C45: Mandatory if LE Feature (Connected Isochronous Stream - Central), or
  // LE Feature (Connected Isochronous Stream - Peripheral), or
  // LE Feature (Isochronous Broadcaster) is supported, otherwise excluded.
  auto c45 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL) ||
      SupportsLLFeature(
          LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL) ||
      SupportsLLFeature(LLFeaturesBits::ISOCHRONOUS_BROADCASTER));
  // C46: Mandatory if LE Feature (Connected Isochronous Stream - Central), or
  // LE Feature (Connected Isochronous Stream - Peripheral), or
  // LE Feature (Synchronized Receiver role) is supported, otherwise excluded.
  auto c46 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL) ||
      SupportsLLFeature(
          LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL) ||
      SupportsLLFeature(LLFeaturesBits::SYNCHRONIZED_RECEIVER));
  // C47: Mandatory if LE Feature (Connected Isochronous Stream - Central), or
  // LE Feature (Connected Isochronous Stream - Peripheral), or
  // LE Feature (Isochronous Broadcaster), or
  // LE Feature (Synchronized Receiver role) is supported, otherwise excluded.
  auto c47 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL) ||
      SupportsLLFeature(
          LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL) ||
      SupportsLLFeature(LLFeaturesBits::ISOCHRONOUS_BROADCASTER) ||
      SupportsLLFeature(LLFeaturesBits::SYNCHRONIZED_RECEIVER));
  // C49: Mandatory if LE Feature (Connected Isochronous Stream - Central) or
  // LE Feature (Connected Isochronous Stream - Peripheral) or
  // LE Feature (Connection Subrating) is supported, otherwise optional.
  auto c49 = mandatory_or_optional(
      SupportsLLFeature(LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL) ||
      SupportsLLFeature(
          LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL) ||
      SupportsLLFeature(LLFeaturesBits::CONNECTION_SUBRATING));
  // C50: Optional if LE Feature (Connected Isochronous Stream - Central), or
  // LE Feature (Connected Isochronous Stream - Peripheral), or
  // LE Feature (Synchronized Receiver role) is supported, otherwise excluded.
  auto c50 = optional_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL) ||
      SupportsLLFeature(
          LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL) ||
      SupportsLLFeature(LLFeaturesBits::SYNCHRONIZED_RECEIVER));
  // C51: Mandatory if LE Feature (LE Power Control Request) is supported,
  // otherwise excluded.
  auto c51 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_POWER_CONTROL_REQUEST));
  // C52: Mandatory if LE Feature (LE Path Loss Monitoring) is supported,
  // otherwise excluded.
  auto c52 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::LE_PATH_LOSS_MONITORING));
  // C53: Mandatory if LE Feature (LE Power Control Request) is supported,
  // otherwise optional if the LE Controller supports transmitting packets,
  // otherwise excluded.
  auto c53 = mandatory_or_optional(
      SupportsLLFeature(LLFeaturesBits::LE_POWER_CONTROL_REQUEST));
  // C54: Mandatory if LE Feature (Synchronized Receiver) is supported,
  // otherwise optional.
  //
  // C55: Mandatory if LE Feature (Connected Isochronous
  // Stream - Central), or LE Feature (Connected Isochronous Stream -
  // Peripheral), or LE Feature (Isochronous Broadcaster) is supported,
  // otherwise optional if the LE Controller supports Connection State,
  // otherwise excluded.
  auto c55 = mandatory_or_optional(
      SupportsLLFeature(LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_CENTRAL) ||
      SupportsLLFeature(
          LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL) ||
      SupportsLLFeature(LLFeaturesBits::ISOCHRONOUS_BROADCASTER));
  // C56: Optional if LE Feature (LE Encryption) is supported, otherwise
  // excluded.
  //
  // C57: Mandatory if LE Feature (Connection Subrating) is supported,
  // otherwise excluded.
  auto c57 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CONNECTION_SUBRATING));
  // C58: Mandatory if LE Feature (Channel Classification) is supported,
  // otherwise excluded.
  auto c58 = mandatory_or_excluded(
      SupportsLLFeature(LLFeaturesBits::CHANNEL_CLASSIFICATION));
  // C59: Mandatory if the LE Controller supports Central role, otherwise
  // excluded.
  auto c59 = mandatory;
  // C60: Mandatory if the LE Controller supports Central role and LE Feature
  // (LE Encryption), otherwise excluded.
  auto c60 =
      mandatory_or_excluded(SupportsLLFeature(LLFeaturesBits::LE_ENCRYPTION));
  // C61: Mandatory if the LE Controller supports Peripheral role and LE Feature
  // (LE Encryption), otherwise excluded.
  auto c61 =
      mandatory_or_excluded(SupportsLLFeature(LLFeaturesBits::LE_ENCRYPTION));
  // C62: Mandatory if the LE Controller supports Central role or supports both
  // Peripheral role and LE Feature (Connection Parameters Request Procedure),
  // otherwise excluded.
  auto c62 = mandatory;
  // C63: Mandatory if the LE Controller supports Scanning state and LE Feature
  // (LL Privacy), otherwise excluded.
  //
  // C64: Optional if the Controller supports
  // transmitting packets, otherwise excluded.
  auto c64 = optional;
  // C94: Mandatory if the LE Create Connection or LE Extended Create Connection
  // command is supported, otherwise excluded.
  auto c94 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::LE_CREATE_CONNECTION) ||
      SupportsCommand(OpCodeIndex::LE_EXTENDED_CREATE_CONNECTION));
  // C95: Mandatory if the LE Request Peer SCA command is supported, otherwise
  // excluded.
  //
  // C96: Optional if the LE Controller supports Connection State,
  // otherwise excluded.
  auto c96 = mandatory;
  // C97: Mandatory if Advertising State is supported, otherwise excluded.
  auto c97 = mandatory;
  // C98: Mandatory if Scanning State is supported, otherwise excluded.
  auto c98 = mandatory;
  // C99: Mandatory if LE Generate DHKey command [v2] is supported, otherwise
  // optional.
  auto c99 =
      mandatory_or_optional(SupportsCommand(OpCodeIndex::LE_GENERATE_DHKEY_V2));
  // C101: Mandatory if the Authentication Requested command is supported,
  // otherwise excluded.
  //
  // C102: Mandatory if the Change Connection Link Key command is supported,
  // otherwise excluded.
  //
  // C103: Mandatory if the Periodic
  // Inquiry Mode command is supported, otherwise excluded.
  auto c103 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::PERIODIC_INQUIRY_MODE));
  // C104: Mandatory if the Read Clock Offset command is supported, otherwise
  // excluded.
  //
  // C105: Mandatory if the Read Remote Version Information command is
  // supported, otherwise excluded.
  //
  // C106: Mandatory if the Remote Name Request
  // command is supported, otherwise excluded.
  auto c106 =
      mandatory_or_excluded(SupportsCommand(OpCodeIndex::REMOTE_NAME_REQUEST));
  // C107: Mandatory if the Set Controller To Host Flow Control command is
  // supported, otherwise excluded.
  auto c107 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::SET_CONTROLLER_TO_HOST_FLOW_CONTROL));
  // C108: Mandatory if the Set MWS_PATTERN Configuration command is supported,
  // otherwise optional.
  auto c108 = mandatory_or_optional(
      SupportsCommand(OpCodeIndex::SET_MWS_PATTERN_CONFIGURATION));
  // C109: Mandatory if the Set MWS Signaling command is supported, otherwise
  // excluded.
  auto c109 =
      mandatory_or_excluded(SupportsCommand(OpCodeIndex::SET_MWS_SIGNALING));
  // C110: Mandatory if the Set Triggered Clock Capture command is supported,
  // otherwise excluded.
  //
  // C111: Mandatory if the Write Authentication Enable
  // command is supported, otherwise excluded.
  auto c111 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_AUTHENTICATION_ENABLE));
  // C112: Mandatory if the Write Default Erroneous Data Reporting command is
  // supported, otherwise excluded.
  auto c112 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING));
  // C113: Mandatory if the Write Extended Inquiry Length command is supported,
  // otherwise excluded.
  auto c113 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_EXTENDED_INQUIRY_LENGTH));
  // C114: Mandatory if the Write Extended Page Timeout command is supported,
  // otherwise excluded.
  auto c114 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_EXTENDED_PAGE_TIMEOUT));
  // C115: Mandatory if the Write Inquiry Mode command is supported, otherwise
  // excluded.
  auto c115 =
      mandatory_or_excluded(SupportsCommand(OpCodeIndex::WRITE_INQUIRY_MODE));
  // C116: Mandatory if the Write LE Host Support command is supported,
  // otherwise excluded.
  auto c116 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_LE_HOST_SUPPORT));
  // C117: Mandatory if the Write Link Supervision Timeout command is supported,
  // otherwise excluded.
  auto c117 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_LINK_SUPERVISION_TIMEOUT));
  // C118: Mandatory if the Write Num Broadcast Retransmissions command is
  // supported, otherwise excluded.
  auto c118 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_NUM_BROADCAST_RETRANSMITS));
  // C119: Mandatory if the Write Page Scan Type command is supported, otherwise
  // excluded.
  auto c119 =
      mandatory_or_excluded(SupportsCommand(OpCodeIndex::WRITE_PAGE_SCAN_TYPE));
  // C120: Mandatory if the Write PIN Type command is supported, otherwise
  // excluded.
  auto c120 =
      mandatory_or_excluded(SupportsCommand(OpCodeIndex::WRITE_PIN_TYPE));
  // C121: Mandatory if the Write Stored Link Key command is supported,
  // otherwise excluded.
  auto c121 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_STORED_LINK_KEY));
  // C122: Mandatory if the Write Synchronous Flow Control Enable command is
  // supported, otherwise excluded.
  auto c122 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE));
  // C123: Mandatory if BR/EDR test mode is supported, otherwise excluded.
  auto c123 = mandatory;
  // C124: Mandatory if Data block based flow control is supported, otherwise
  // excluded.
  auto c124 = excluded;
  // C125: Mandatory if Inquiry Scan is supported, otherwise excluded.
  auto c125 = mandatory;
  // C126: Optional if Inquiry Scan is supported, otherwise excluded.
  //
  // C127: Mandatory if Inquiry is supported, otherwise excluded.
  auto c127 = mandatory;
  // C128: Optional if Inquiry is supported, otherwise excluded.
  auto c128 = optional;
  // C129: Mandatory if Truncated page state is supported, otherwise excluded.
  auto c129 = excluded;
  // C132: Mandatory if multi-slot ACL packets are is supported, otherwise
  // excluded.
  //
  // C133: Mandatory if HV2, HV3, or multi-slot or EDR ACL packets are
  // supported, otherwise excluded.
  auto c133 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::HV2_PACKETS) ||
      SupportsLMPFeature(LMPFeaturesPage0Bits::HV3_PACKETS) ||
      SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ACL_2_MB_S_MODE) ||
      SupportsLMPFeature(
          LMPFeaturesPage0Bits::ENHANCED_DATA_RATE_ACL_3_MB_S_MODE) ||
      SupportsLMPFeature(
          LMPFeaturesPage0Bits::LMP_3_SLOT_ENHANCED_DATA_RATE_ACL_PACKETS));
  // C134: Mandatory if SCO or eSCO is supported, otherwise excluded.
  auto c134 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK) ||
      SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK));
  // C135: Optional if SCO or eSCO is supported, otherwise excluded.
  auto c135 = optional_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::SCO_LINK) ||
      SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK));
  // C136: Optional if Slot Availability Mask is supported, otherwise excluded.
  auto c136 = optional_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage2Bits::SLOT_AVAILABILITY_MASK));
  // C138: Mandatory if Secure Connections (Controller) is supported, otherwise
  // optional if eSCO is supported, otherwise excluded.
  auto c138 = mandatory_or_optional_or_excluded(
      SupportsLMPFeature(
          LMPFeaturesPage2Bits::SECURE_CONNECTIONS_CONTROLLER_SUPPORT),
      SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_SCO_LINK));
  // C139: Mandatory if the Controller is AFH capable in either role, otherwise
  // excluded.
  auto c139 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CAPABLE_CENTRAL) ||
      SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CAPABLE_PERIPHERAL));
  // C140: Mandatory if the Controller supports AFH classification in either
  // role or is an AFH capable Central, otherwise excluded.
  auto c140 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CLASSIFICATION_CENTRAL) ||
      SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CLASSIFICATION_PERIPHERAL) ||
      SupportsLMPFeature(LMPFeaturesPage0Bits::AFH_CAPABLE_CENTRAL));
  // C141: Mandatory if Role Switch, Hold mode, or Sniff mode is supported,
  // otherwise excluded.
  auto c141 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::ROLE_SWITCH) ||
      SupportsLMPFeature(LMPFeaturesPage0Bits::HOLD_MODE) ||
      SupportsLMPFeature(LMPFeaturesPage0Bits::SNIFF_MODE));
  // C142: Mandatory if Secure Connections (Host) is supported, otherwise
  // excluded.
  auto c142 = mandatory;
  // C143: Mandatory if Secure Connections (both Host and Controller) is
  // supported, otherwise excluded.
  auto c143 = mandatory_or_excluded(SupportsLMPFeature(
      LMPFeaturesPage2Bits::SECURE_CONNECTIONS_CONTROLLER_SUPPORT));
  // C144: Mandatory if Hold Mode or Sniff Mode is supported, otherwise
  // excluded.
  //
  // C145: Mandatory if any event in event mask page 2 is supported,
  // otherwise optional.
  auto c145 = mandatory;
  // C146: Mandatory if the Extended Inquiry Result event or the IO Capability
  // Request event is supported, otherwise optional if Inquiry is supported,
  // otherwise excluded.
  auto c146 = mandatory;
  // C147: Optional if the Inquiry Result with RSSI event is supported,
  // otherwise excluded.
  //
  // C148: Optional if any of the Connection Complete,
  // Connection Request, Extended Inquiry Result, Inquiry Result with RSSI, IO
  // Capability Request, or Synchronous Connection Complete events is supported,
  // otherwise excluded.
  auto c148 = mandatory;
  // C151: Mandatory if Secure Connections (Controller) and Ping are supported,
  // otherwise excluded.
  auto c151 = mandatory_or_excluded(
      SupportsLMPFeature(
          LMPFeaturesPage2Bits::SECURE_CONNECTIONS_CONTROLLER_SUPPORT) &&
      SupportsLMPFeature(LMPFeaturesPage2Bits::PING));
  // C152: Mandatory if Power Control is supported, otherwise optional.
  auto c152 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::POWER_CONTROL));
  // C153: Mandatory if LE supported in the Controller, otherwise optional.
  auto c153 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::LE_SUPPORTED_CONTROLLER));
  // C154: Mandatory if Interlaced Page Scan is supported, otherwise optional.
  auto c154 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::INTERLACED_PAGE_SCAN));
  // C155: Mandatory if the Write Authenticated Payload Timeout command is
  // supported, otherwise excluded.
  auto c155 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT));
  // C156: Mandatory if the Read Local Supported Codecs command [v2] is
  // supported, otherwise excluded.
  auto c156 = mandatory_or_excluded(
      SupportsCommand(OpCodeIndex::READ_LOCAL_SUPPORTED_CODECS_V2));
  // C157: Mandatory if the Read Local Supported Codecs command [v2] is
  // supported, otherwise optional.
  auto c157 = mandatory_or_optional(
      SupportsCommand(OpCodeIndex::READ_LOCAL_SUPPORTED_CODECS_V2));
  // C158: Mandatory if the Set Min Encryption Key Size command is supported,
  // otherwise optional.
  //
  // C201: Mandatory if Connectionless Peripheral Broadcast - Transmitter is
  // supported, otherwise excluded.
  auto c201 = mandatory_or_excluded(SupportsLMPFeature(
      LMPFeaturesPage2Bits::
          CONNECTIONLESS_PERIPHERAL_BROADCAST_TRANSMITTER_OPERATION));
  // C202: Mandatory if Connectionless Peripheral Broadcast - Receiver is
  // supported, otherwise excluded.
  auto c202 = mandatory_or_excluded(SupportsLMPFeature(
      LMPFeaturesPage2Bits::
          CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVER_OPERATION));
  // C203: Mandatory if Synchronization Train is supported, otherwise excluded.
  auto c203 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage2Bits::SYNCHRONIZATION_TRAIN));
  // C204: Mandatory if Synchronization Scan is supported, otherwise excluded.
  auto c204 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage2Bits::SYNCHRONIZATION_SCAN));
  // C205: Mandatory if Extended Inquiry Response is supported, otherwise
  // excluded.
  auto c205 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_INQUIRY_RESPONSE));
  // C212: Mandatory if Role Switch is supported, otherwise excluded.
  auto c212 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::ROLE_SWITCH));
  // C213: Mandatory if Hold mode is supported, otherwise excluded.
  auto c213 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::HOLD_MODE));
  // C214: Mandatory if Sniff mode is supported, otherwise excluded.
  auto c214 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::SNIFF_MODE));
  // C215: Mandatory if Broadcast Encryption is supported, otherwise excluded.
  auto c215 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::BROADCAST_ENCRYPTION));
  // C217: Mandatory if BR/EDR Enhanced Power Control is supported, otherwise
  // excluded.
  auto c217 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::ENHANCED_POWER_CONTROL));
  // C218: Mandatory if Secure Connections (Controller) is supported, otherwise
  // excluded.
  auto c218 = mandatory_or_excluded(SupportsLMPFeature(
      LMPFeaturesPage2Bits::SECURE_CONNECTIONS_CONTROLLER_SUPPORT));
  // C219: Mandatory if Slot Availability Mask is supported, otherwise excluded.
  // C220: Mandatory if LMP Extended Features mask is supported, otherwise
  // excluded.
  auto c220 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::EXTENDED_FEATURES));
  // C221: Mandatory if Sniff subrating is supported, otherwise excluded.
  auto c221 = mandatory_or_excluded(
      SupportsLMPFeature(LMPFeaturesPage0Bits::SNIFF_SUBRATING));

#define check_command_(op_code, br_requirement, le_requirement)                \
  {                                                                            \
    bool command_supported =                                                   \
        SupportsCommand(bluetooth::hci::OpCodeIndex::op_code);                 \
    if (!check_command_requirement(br_supported, br_requirement, le_supported, \
                                   le_requirement, command_supported)) {       \
      LOG_INFO(#op_code " command validation failed (" #br_requirement         \
                        "," #le_requirement ")");                              \
    }                                                                          \
  }

  // Table 3.1: Alphabetical list of commands and events (Sheet 1 of 49)
  check_command_(ACCEPT_CONNECTION_REQUEST, mandatory, excluded);
  check_command_(ACCEPT_SYNCHRONOUS_CONNECTION, c134, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 2 of 49)
  check_command_(CHANGE_CONNECTION_PACKET_TYPE, c133, excluded);
  check_command_(CONFIGURE_DATA_PATH, c156, c156);
  // Table 3.1: Alphabetical list of commands and events (Sheet 3 of 49)
  check_command_(CREATE_CONNECTION_CANCEL, mandatory, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 4 of 49)
  check_command_(CREATE_CONNECTION, mandatory, excluded);
  check_command_(DELETE_RESERVED_LT_ADDR, c201, excluded);
  check_command_(DELETE_STORED_LINK_KEY, c121, excluded);
  check_command_(DISCONNECT, mandatory, c3);
  check_command_(ENABLE_DEVICE_UNDER_TEST_MODE, c123, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 5 of 49)
  check_command_(ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION, c135, excluded);
  check_command_(ENHANCED_FLUSH, mandatory, excluded);
  check_command_(ENHANCED_SETUP_SYNCHRONOUS_CONNECTION, c135, excluded);
  check_command_(EXIT_PERIODIC_INQUIRY_MODE, c103, excluded);
  check_command_(EXIT_SNIFF_MODE, c214, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 6 of 49)
  check_command_(FLOW_SPECIFICATION, mandatory, excluded);
  check_command_(FLUSH, mandatory, excluded);
  check_command_(GET_MWS_TRANSPORT_LAYER_CONFIGURATION, c109, c109);
  check_command_(HOLD_MODE, c213, excluded);
  check_command_(HOST_BUFFER_SIZE, c107, c107);
  // Table 3.1: Alphabetical list of commands and events (Sheet 7 of 49)
  check_command_(HOST_NUMBER_OF_COMPLETED_PACKETS, c107, c107);
  check_command_(INQUIRY_CANCEL, c127, excluded);
  check_command_(INQUIRY, c127, excluded);
  check_command_(IO_CAPABILITY_REQUEST_NEGATIVE_REPLY, mandatory, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 8 of 49)
  check_command_(IO_CAPABILITY_REQUEST_REPLY, mandatory, excluded);
  check_command_(LE_ACCEPT_CIS_REQUEST, excluded, c40);
  check_command_(LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST, excluded, mandatory);
  check_command_(LE_ADD_DEVICE_TO_PERIODIC_ADVERTISING_LIST, excluded, c21);
  check_command_(LE_ADD_DEVICE_TO_RESOLVING_LIST, excluded, c9);
  // Table 3.1: Alphabetical list of commands and events (Sheet 9 of 49)
  check_command_(LE_BIG_CREATE_SYNC, excluded, c42);
  check_command_(LE_BIG_TERMINATE_SYNC, excluded, c42);
  check_command_(LE_CLEAR_ADVERTISING_SETS, excluded, c17);
  check_command_(LE_CLEAR_FILTER_ACCEPT_LIST, excluded, mandatory);
  check_command_(LE_CLEAR_PERIODIC_ADVERTISING_LIST, excluded, c21);
  check_command_(LE_CLEAR_RESOLVING_LIST, excluded, c9);
  // Table 3.1: Alphabetical list of commands and events (Sheet 10 of 49)
  check_command_(LE_CONNECTION_CTE_REQUEST_ENABLE, excluded, c25);
  check_command_(LE_CONNECTION_CTE_RESPONSE_ENABLE, excluded, c26);
  check_command_(LE_CONNECTION_UPDATE, excluded, c62);
  check_command_(LE_CREATE_BIG, excluded, c41);
  // Table 3.1: Alphabetical list of commands and events (Sheet 11 of 49)
  check_command_(LE_CREATE_BIG_TEST, excluded, c41);
  check_command_(LE_CREATE_CIS, excluded, c39);
  check_command_(LE_CREATE_CONNECTION_CANCEL, excluded, c94);
  check_command_(LE_CREATE_CONNECTION, excluded, c59);
  check_command_(LE_START_ENCRYPTION, excluded, c60);
  check_command_(LE_ENCRYPT, excluded, c4);
  // Table 3.1: Alphabetical list of commands and events (Sheet 12 of 49)
  check_command_(LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL, excluded, c51);
  check_command_(LE_EXTENDED_CREATE_CONNECTION, excluded, c20);
  check_command_(LE_GENERATE_DHKEY_V1, excluded, c99);
  check_command_(LE_GENERATE_DHKEY_V2, excluded, optional);
  check_command_(LE_ISO_READ_TEST_COUNTERS, excluded, c46);
  check_command_(LE_ISO_RECEIVE_TEST, excluded, c46);
  check_command_(LE_ISO_TEST_END, excluded, c47);
  // Table 3.1: Alphabetical list of commands and events (Sheet 13 of 49)
  check_command_(LE_ISO_TRANSMIT_TEST, excluded, c45);
  check_command_(LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY, excluded, c61);
  check_command_(LE_LONG_TERM_KEY_REQUEST_REPLY, excluded, c61);
  check_command_(LE_MODIFY_SLEEP_CLOCK_ACCURACY, excluded, c37);
  check_command_(LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL, excluded, c16);
  check_command_(LE_PERIODIC_ADVERTISING_CREATE_SYNC, excluded, c16);
  // Table 3.1: Alphabetical list of commands and events (Sheet 14 of 49)
  check_command_(LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER, excluded, c34);
  check_command_(LE_PERIODIC_ADVERTISING_SYNC_TRANSFER, excluded, c33);
  check_command_(LE_PERIODIC_ADVERTISING_TERMINATE_SYNC, excluded, c21);
  check_command_(LE_RAND, excluded, c4);
  check_command_(LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER, excluded, c97);
  // Table 3.1: Alphabetical list of commands and events (Sheet 15 of 49)
  check_command_(LE_READ_ANTENNA_INFORMATION, excluded, c31);
  check_command_(LE_READ_BUFFER_SIZE_V1, excluded, c3);
  check_command_(LE_READ_BUFFER_SIZE_V2, excluded, c55);
  check_command_(LE_READ_CHANNEL_MAP, excluded, c3);
  check_command_(LE_READ_FILTER_ACCEPT_LIST_SIZE, excluded, mandatory);
  check_command_(LE_READ_ISO_LINK_QUALITY, excluded, c50);
  check_command_(LE_READ_ISO_TX_SYNC, excluded, c45);
  check_command_(LE_READ_LOCAL_RESOLVABLE_ADDRESS, excluded, c10);
  // Table 3.1: Alphabetical list of commands and events (Sheet 16 of 49)
  check_command_(LE_READ_LOCAL_SUPPORTED_FEATURES, excluded, mandatory);
  check_command_(LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH, excluded, c17);
  check_command_(LE_READ_MAXIMUM_DATA_LENGTH, excluded, c8);
  check_command_(LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS, excluded, c17);
  check_command_(LE_READ_PEER_RESOLVABLE_ADDRESS, excluded, c10);
  check_command_(LE_READ_PERIODIC_ADVERTISING_LIST_SIZE, excluded, c21);
  check_command_(LE_READ_PHY, excluded, c11);
  check_command_(LE_READ_REMOTE_FEATURES, excluded, c3);
  // Table 3.1: Alphabetical list of commands and events (Sheet 17 of 49)
  check_command_(LE_READ_REMOTE_TRANSMIT_POWER_LEVEL, excluded, c51);
  check_command_(LE_READ_RESOLVING_LIST_SIZE, excluded, c9);
  check_command_(LE_READ_RF_PATH_COMPENSATION_POWER, excluded, c22);
  check_command_(LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH, excluded, c8);
  check_command_(LE_READ_SUPPORTED_STATES, excluded, mandatory);
  check_command_(LE_READ_TRANSMIT_POWER, excluded, c64);
  check_command_(LE_RECEIVER_TEST_V1, excluded, c2);
  check_command_(LE_RECEIVER_TEST_V2, excluded, c13);
  check_command_(LE_RECEIVER_TEST_V3, excluded, c30);
  // Table 3.1: Alphabetical list of commands and events (Sheet 18 of 49)
  check_command_(LE_REJECT_CIS_REQUEST, excluded, c40);
  check_command_(LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY,
                 excluded, c6);
  check_command_(LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY, excluded, c6);
  check_command_(LE_REMOVE_ADVERTISING_SET, excluded, c17);
  check_command_(LE_REMOVE_CIG, excluded, c39);
  check_command_(LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST, excluded, mandatory);
  check_command_(LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISING_LIST, excluded,
                 c21);
  check_command_(LE_REMOVE_DEVICE_FROM_RESOLVING_LIST, excluded, c9);
  // Table 3.1: Alphabetical list of commands and events (Sheet 19 of 49)
  check_command_(LE_REMOVE_ISO_DATA_PATH, excluded, c47);
  check_command_(LE_REQUEST_PEER_SCA, excluded, c44);
  check_command_(LE_SET_ADDRESS_RESOLUTION_ENABLE, excluded, c9);
  check_command_(LE_SET_ADVERTISING_DATA, excluded, c97);
  check_command_(LE_SET_ADVERTISING_ENABLE, excluded, c97);
  check_command_(LE_SET_ADVERTISING_PARAMETERS, excluded, c97);
  check_command_(LE_SET_ADVERTISING_SET_RANDOM_ADDRESS, excluded, c17);
  check_command_(LE_SET_CIG_PARAMETERS, excluded, c39);
  // Table 3.1: Alphabetical list of commands and events (Sheet 20 of 49)
  check_command_(LE_SET_CIG_PARAMETERS_TEST, excluded, c39);
  check_command_(LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS, excluded, c25);
  check_command_(LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS, excluded, c26);
  check_command_(LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE, excluded, c27);
  check_command_(LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS, excluded, c27);
  check_command_(LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE, excluded, c28);
  check_command_(LE_SET_DATA_LENGTH, excluded, c8);
  // Table 3.1: Alphabetical list of commands and events (Sheet 21 of 49)
  check_command_(LE_SET_DATA_RELATED_ADDRESS_CHANGES, excluded, c10);
  check_command_(LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
                 excluded, c35);
  check_command_(LE_SET_DEFAULT_PHY, excluded, c11);
  check_command_(LE_SET_DEFAULT_SUBRATE, excluded, c57);
  check_command_(LE_SET_EVENT_MASK, excluded, mandatory);
  check_command_(LE_SET_EXTENDED_ADVERTISING_DATA, excluded, c17);
  check_command_(LE_SET_EXTENDED_ADVERTISING_ENABLE, excluded, c17);
  check_command_(LE_SET_EXTENDED_ADVERTISING_PARAMETERS, excluded, c17);
  check_command_(LE_SET_EXTENDED_SCAN_ENABLE, excluded, c19);
  // Table 3.1: Alphabetical list of commands and events (Sheet 22 of 49)
  check_command_(LE_SET_EXTENDED_SCAN_PARAMETERS, excluded, c19);
  check_command_(LE_SET_EXTENDED_SCAN_RESPONSE_DATA, excluded, c17);
  check_command_(LE_SET_HOST_CHANNEL_CLASSIFICATION, excluded, c36);
  check_command_(LE_SET_HOST_FEATURE, excluded, c49);
  check_command_(LE_SET_PATH_LOSS_REPORTING_ENABLE, excluded, c52);
  check_command_(LE_SET_PATH_LOSS_REPORTING_PARAMETERS, excluded, c52);
  check_command_(LE_SET_PERIODIC_ADVERTISING_DATA, excluded, c18);
  check_command_(LE_SET_PERIODIC_ADVERTISING_ENABLE, excluded, c18);
  check_command_(LE_SET_PERIODIC_ADVERTISING_PARAM, excluded, c18);
  // Table 3.1: Alphabetical list of commands and events (Sheet 23 of 49)
  check_command_(LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE, excluded, c32);
  check_command_(LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS, excluded,
                 c35);
  check_command_(LE_SET_PHY, excluded, c11);
  check_command_(LE_SET_PRIVACY_MODE, excluded, c9);
  check_command_(LE_SET_RANDOM_ADDRESS, excluded, c1);
  check_command_(LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT, excluded, c9);
  check_command_(LE_SET_SCAN_ENABLE, excluded, c98);
  check_command_(LE_SET_SCAN_PARAMETERS, excluded, c98);
  check_command_(LE_SET_SCAN_RESPONSE_DATA, excluded, c15);
  // Table 3.1: Alphabetical list of commands and events (Sheet 24 of 49)
  check_command_(LE_SET_TRANSMIT_POWER_REPORTING_ENABLE, excluded, c51);
  check_command_(LE_SETUP_ISO_DATA_PATH, excluded, c47);
  check_command_(LE_SUBRATE_REQUEST, excluded, c57);
  check_command_(LE_TERMINATE_BIG, excluded, c41);
  check_command_(LE_TEST_END, excluded, mandatory);
  check_command_(LE_TRANSMITTER_TEST_V1, excluded, c1);
  check_command_(LE_TRANSMITTER_TEST_V2, excluded, c12);
  check_command_(LE_TRANSMITTER_TEST_V3, excluded, c29);
  check_command_(LE_TRANSMITTER_TEST_V4, excluded, c53);
  // Table 3.1: Alphabetical list of commands and events (Sheet 25 of 49)
  check_command_(LE_WRITE_RF_PATH_COMPENSATION_POWER, excluded, c22);
  check_command_(LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH, excluded, c8);
  check_command_(LINK_KEY_REQUEST_NEGATIVE_REPLY, mandatory, excluded);
  check_command_(LINK_KEY_REQUEST_REPLY, mandatory, excluded);
  check_command_(CENTRAL_LINK_KEY, c215, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 26 of 49)
  // Table 3.1: Alphabetical list of commands and events (Sheet 27 of 49)
  check_command_(PERIODIC_INQUIRY_MODE, c128, excluded);
  check_command_(PIN_CODE_REQUEST_NEGATIVE_REPLY, mandatory, excluded);
  check_command_(PIN_CODE_REQUEST_REPLY, mandatory, excluded);
  check_command_(QOS_SETUP, mandatory, excluded);
  check_command_(READ_AFH_CHANNEL_ASSESSMENT_MODE, c140, c58);
  // Table 3.1: Alphabetical list of commands and events (Sheet 28 of 49)
  check_command_(READ_AFH_CHANNEL_MAP, c139, excluded);
  check_command_(READ_AUTHENTICATED_PAYLOAD_TIMEOUT, c155, c155);
  check_command_(READ_AUTHENTICATION_ENABLE, c111, excluded);
  check_command_(READ_AUTOMATIC_FLUSH_TIMEOUT, mandatory, excluded);
  check_command_(READ_BD_ADDR, mandatory, mandatory);
  check_command_(READ_BUFFER_SIZE, mandatory, excluded);
  check_command_(READ_CLASS_OF_DEVICE, mandatory, excluded);
  check_command_(READ_CLOCK, optional, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 29 of 49)
  check_command_(READ_CLOCK_OFFSET, optional, excluded);
  check_command_(READ_CONNECTION_ACCEPT_TIMEOUT, mandatory, c40);
  check_command_(READ_CURRENT_IAC_LAP, c125, excluded);
  check_command_(READ_DATA_BLOCK_SIZE, c124, excluded);
  check_command_(READ_DEFAULT_ERRONEOUS_DATA_REPORTING, c112, excluded);
  check_command_(READ_DEFAULT_LINK_POLICY_SETTINGS, c141, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 30 of 49)
  check_command_(READ_ENCRYPTION_KEY_SIZE, mandatory, excluded);
  check_command_(READ_ENHANCED_TRANSMIT_POWER_LEVEL, c217, excluded);
  check_command_(READ_EXTENDED_INQUIRY_LENGTH, c113, excluded);
  check_command_(READ_EXTENDED_INQUIRY_RESPONSE, c205, excluded);
  check_command_(READ_EXTENDED_PAGE_TIMEOUT, c114, excluded);
  check_command_(READ_FAILED_CONTACT_COUNTER, mandatory, excluded);
  check_command_(READ_FLOW_CONTROL_MODE, c124, excluded);
  check_command_(READ_HOLD_MODE_ACTIVITY, c213, excluded);
  check_command_(READ_INQUIRY_MODE, c115, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 31 of 49)
  check_command_(READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL, c125, excluded);
  check_command_(READ_INQUIRY_SCAN_ACTIVITY, c125, excluded);
  check_command_(READ_INQUIRY_SCAN_TYPE, c125, excluded);
  check_command_(READ_LE_HOST_SUPPORT, c116, c116);
  check_command_(READ_LINK_POLICY_SETTINGS, c141, excluded);
  check_command_(READ_LINK_QUALITY, optional, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 32 of 49)
  check_command_(READ_LINK_SUPERVISION_TIMEOUT, c117, excluded);
  check_command_(READ_LMP_HANDLE, c134, excluded);
  check_command_(READ_LOCAL_EXTENDED_FEATURES, c220, excluded);
  check_command_(READ_LOCAL_NAME, mandatory, excluded);
  check_command_(READ_LOCAL_OOB_DATA, mandatory, excluded);
  check_command_(READ_LOCAL_OOB_EXTENDED_DATA, c142, excluded);
  check_command_(READ_LOCAL_SIMPLE_PAIRING_OPTIONS, optional, excluded);
  check_command_(READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES, c156, c156);
  check_command_(READ_LOCAL_SUPPORTED_CODECS_V1, c157, excluded);
  check_command_(READ_LOCAL_SUPPORTED_CODECS_V2, optional, optional);
  // Table 3.1: Alphabetical list of commands and events (Sheet 33 of 49)
  // check_command_(READ_LOCAL_SUPPORTED_COMMANDS, mandatory, mandatory);
  check_command_(READ_LOCAL_SUPPORTED_CONTROLLER_DELAY, c156, c156);
  check_command_(READ_LOCAL_SUPPORTED_FEATURES, mandatory, mandatory);
  check_command_(READ_LOCAL_VERSION_INFORMATION, mandatory, mandatory);
  check_command_(READ_LOOPBACK_MODE, c123, excluded);
  check_command_(READ_NUM_BROADCAST_RETRANSMITS, c118, excluded);
  check_command_(READ_NUMBER_OF_SUPPORTED_IAC, c125, excluded);
  check_command_(READ_PAGE_SCAN_ACTIVITY, mandatory, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 34 of 49)
  check_command_(READ_PAGE_SCAN_TYPE, c119, excluded);
  check_command_(READ_PAGE_TIMEOUT, mandatory, excluded);
  check_command_(READ_PIN_TYPE, c120, excluded);
  check_command_(READ_REMOTE_EXTENDED_FEATURES, c220, excluded);
  check_command_(READ_REMOTE_SUPPORTED_FEATURES, mandatory, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 35 of 49)
  check_command_(READ_REMOTE_VERSION_INFORMATION, optional, c3);
  check_command_(READ_RSSI, optional, c3);
  check_command_(READ_SCAN_ENABLE, mandatory, excluded);
  check_command_(READ_SECURE_CONNECTIONS_HOST_SUPPORT, c218, excluded);
  check_command_(READ_SIMPLE_PAIRING_MODE, mandatory, excluded);
  check_command_(READ_STORED_LINK_KEY, c121, excluded);
  check_command_(READ_SYNCHRONIZATION_TRAIN_PARAMETERS, c203, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 36 of 49)
  check_command_(READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE, c122, excluded);
  check_command_(READ_TRANSMIT_POWER_LEVEL, c152, c3);
  check_command_(READ_VOICE_SETTING, c134, excluded);
  check_command_(RECEIVE_SYNCHRONIZATION_TRAIN, c204, excluded);
  check_command_(REFRESH_ENCRYPTION_KEY, mandatory, excluded);
  check_command_(REJECT_CONNECTION_REQUEST, mandatory, excluded);
  check_command_(REJECT_SYNCHRONOUS_CONNECTION, c134, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 37 of 49)
  check_command_(REMOTE_NAME_REQUEST_CANCEL, c106, excluded);
  check_command_(REMOTE_NAME_REQUEST, optional, excluded);
  check_command_(REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY, mandatory, excluded);
  check_command_(REMOTE_OOB_DATA_REQUEST_REPLY, mandatory, excluded);
  check_command_(REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY, c143, excluded);
  check_command_(RESET, mandatory, mandatory);
  // Table 3.1: Alphabetical list of commands and events (Sheet 38 of 49)
  check_command_(RESET_FAILED_CONTACT_COUNTER, mandatory, excluded);
  check_command_(ROLE_DISCOVERY, optional, excluded);
  check_command_(SEND_KEYPRESS_NOTIFICATION, mandatory, excluded);
  check_command_(SET_AFH_HOST_CHANNEL_CLASSIFICATION, c140, excluded);
  check_command_(SET_CONNECTION_ENCRYPTION, mandatory, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 39 of 49)
  check_command_(SET_CONNECTIONLESS_PERIPHERAL_BROADCAST, c201, excluded);
  check_command_(SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA, c201, excluded);
  check_command_(SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE, c202,
                 excluded);
  check_command_(SET_CONTROLLER_TO_HOST_FLOW_CONTROL, optional, c96);
  check_command_(SET_ECOSYSTEM_BASE_INTERVAL, optional, optional);
  check_command_(SET_EVENT_FILTER, c148, excluded);
  check_command_(SET_EVENT_MASK, mandatory, mandatory);
  check_command_(SET_EVENT_MASK_PAGE_2, c145, c145);
  // Table 3.1: Alphabetical list of commands and events (Sheet 40 of 49)
  check_command_(SET_EXTERNAL_FRAME_CONFIGURATION, c108, optional);
  check_command_(SET_MIN_ENCRYPTION_KEY_SIZE, optional, excluded);
  check_command_(SET_MWS_CHANNEL_PARAMETERS, optional, optional);
  check_command_(SET_MWS_SCAN_FREQUENCY_TABLE, optional, optional);
  check_command_(SET_MWS_SIGNALING, optional, optional);
  check_command_(SET_MWS_TRANSPORT_LAYER, c109, c109);
  check_command_(SET_MWS_PATTERN_CONFIGURATION, c136, excluded);
  check_command_(SET_RESERVED_LT_ADDR, c201, excluded);
  check_command_(SET_TRIGGERED_CLOCK_CAPTURE, optional, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 41 of 49)
  check_command_(SETUP_SYNCHRONOUS_CONNECTION, c134, excluded);
  check_command_(SNIFF_MODE, c214, excluded);
  check_command_(SNIFF_SUBRATING, c221, excluded);
  check_command_(START_SYNCHRONIZATION_TRAIN, c203, excluded);
  check_command_(SWITCH_ROLE, c212, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 42 of 49)
  check_command_(TRUNCATED_PAGE_CANCEL, c129, excluded);
  check_command_(TRUNCATED_PAGE, c129, excluded);
  check_command_(USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY, mandatory, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 43 of 49)
  check_command_(USER_CONFIRMATION_REQUEST_REPLY, mandatory, excluded);
  check_command_(USER_PASSKEY_REQUEST_NEGATIVE_REPLY, mandatory, excluded);
  check_command_(USER_PASSKEY_REQUEST_REPLY, mandatory, excluded);
  check_command_(WRITE_AFH_CHANNEL_ASSESSMENT_MODE, c140, c58);
  // Table 3.1: Alphabetical list of commands and events (Sheet 44 of 49)
  check_command_(WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT, c151, c7);
  check_command_(WRITE_AUTHENTICATION_ENABLE, optional, excluded);
  check_command_(WRITE_AUTOMATIC_FLUSH_TIMEOUT, mandatory, excluded);
  check_command_(WRITE_CLASS_OF_DEVICE, mandatory, excluded);
  check_command_(WRITE_CONNECTION_ACCEPT_TIMEOUT, mandatory, c40);
  check_command_(WRITE_CURRENT_IAC_LAP, c125, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 45 of 49)
  check_command_(WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING, c135, excluded);
  check_command_(WRITE_DEFAULT_LINK_POLICY_SETTINGS, c141, excluded);
  check_command_(WRITE_EXTENDED_INQUIRY_LENGTH, c128, excluded);
  check_command_(WRITE_EXTENDED_INQUIRY_RESPONSE, c205, excluded);
  check_command_(WRITE_EXTENDED_PAGE_TIMEOUT, optional, excluded);
  check_command_(WRITE_FLOW_CONTROL_MODE, c124, excluded);
  check_command_(WRITE_HOLD_MODE_ACTIVITY, c213, excluded);
  check_command_(WRITE_INQUIRY_MODE, c146, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 46 of 49)
  check_command_(WRITE_INQUIRY_SCAN_ACTIVITY, c125, excluded);
  check_command_(WRITE_INQUIRY_SCAN_TYPE, c125, excluded);
  check_command_(WRITE_INQUIRY_TRANSMIT_POWER_LEVEL, c127, excluded);
  check_command_(WRITE_LE_HOST_SUPPORT, c153, optional);
  check_command_(WRITE_LINK_POLICY_SETTINGS, c141, excluded);
  check_command_(WRITE_LINK_SUPERVISION_TIMEOUT, optional, excluded);
  check_command_(WRITE_LOCAL_NAME, mandatory, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 47 of 49)
  check_command_(WRITE_LOOPBACK_MODE, c123, excluded);
  check_command_(WRITE_NUM_BROADCAST_RETRANSMITS, optional, excluded);
  check_command_(WRITE_PAGE_SCAN_ACTIVITY, mandatory, excluded);
  check_command_(WRITE_PAGE_SCAN_TYPE, c154, excluded);
  check_command_(WRITE_PAGE_TIMEOUT, mandatory, excluded);
  check_command_(WRITE_PIN_TYPE, optional, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 48 of 49)
  check_command_(WRITE_SCAN_ENABLE, mandatory, excluded);
  check_command_(WRITE_SECURE_CONNECTIONS_HOST_SUPPORT, c218, excluded);
  check_command_(WRITE_SECURE_CONNECTIONS_TEST_MODE, c138, excluded);
  check_command_(WRITE_SIMPLE_PAIRING_DEBUG_MODE, mandatory, excluded);
  check_command_(WRITE_SIMPLE_PAIRING_MODE, mandatory, excluded);
  check_command_(WRITE_STORED_LINK_KEY, optional, excluded);
  check_command_(WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS, c203, excluded);
  // Table 3.1: Alphabetical list of commands and events (Sheet 49 of 49)
  check_command_(WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE, c135, excluded);
  check_command_(WRITE_VOICE_SETTING, c134, excluded);
  return true;
}

}  // namespace rootcanal
