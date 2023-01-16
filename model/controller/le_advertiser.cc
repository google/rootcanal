/*
 * Copyright 2020 The Android Open Source Project
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

#include "le_advertiser.h"

#include "link_layer_controller.h"
#include "log.h"

using namespace bluetooth::hci;
using namespace std::literals;

namespace rootcanal {

namespace chrono {
using duration = std::chrono::steady_clock::duration;
using time_point = std::chrono::steady_clock::time_point;
};  // namespace chrono

slots operator"" _slots(unsigned long long count) { return slots(count); }

// =============================================================================
//  Constants
// =============================================================================

// Vol 6, Part B § 4.4.2.4.3 High duty cycle connectable directed advertising.
const chrono::duration adv_direct_ind_high_timeout = 1280ms;
const chrono::duration adv_direct_ind_high_interval = 3750us;

// Vol 6, Part B § 2.3.4.9 Host Advertising Data.
const uint16_t max_legacy_advertising_pdu_size = 31;
const uint16_t max_extended_advertising_pdu_size = 1650;

// =============================================================================
//  Legacy Advertising Commands
// =============================================================================

// HCI command LE_Set_Advertising_Parameters (Vol 4, Part E § 7.8.5).
ErrorCode LinkLayerController::LeSetAdvertisingParameters(
    uint16_t advertising_interval_min, uint16_t advertising_interval_max,
    AdvertisingType advertising_type, OwnAddressType own_address_type,
    PeerAddressType peer_address_type, Address peer_address,
    uint8_t advertising_channel_map,
    AdvertisingFilterPolicy advertising_filter_policy) {
  // Legacy advertising commands are disallowed when extended advertising
  // commands were used since the last reset.
  if (!SelectLegacyAdvertising()) {
    LOG_INFO(
        "legacy advertising command rejected because extended advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // Clear reserved bits.
  advertising_channel_map &= 0x7;

  // For high duty cycle directed advertising, i.e. when
  // Advertising_Type is 0x01 (ADV_DIRECT_IND, high duty cycle),
  // the Advertising_Interval_Min and Advertising_Interval_Max parameters
  // are not used and shall be ignored.
  if (advertising_type == AdvertisingType::ADV_DIRECT_IND_HIGH) {
    advertising_interval_min = 0x800;  // Default interval value
    advertising_interval_max = 0x800;
  }

  // The Host shall not issue this command when advertising is enabled in the
  // Controller; if it is the Command Disallowed error code shall be used.
  if (legacy_advertiser_.advertising_enable) {
    LOG_INFO("legacy advertising is enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // At least one channel bit shall be set in the
  // Advertising_Channel_Map parameter.
  if (advertising_channel_map == 0) {
    LOG_INFO(
        "advertising_channel_map (0x%04x) does not enable any"
        " advertising channel",
        advertising_channel_map);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the advertising interval range provided by the Host
  // (Advertising_Interval_Min, Advertising_Interval_Max) is outside the
  // advertising interval range supported by the Controller, then the
  // Controller shall return the Unsupported Feature or Parameter Value (0x11)
  // error code.
  if (advertising_interval_min < 0x0020 || advertising_interval_min > 0x4000 ||
      advertising_interval_max < 0x0020 || advertising_interval_max > 0x4000) {
    LOG_INFO(
        "advertising_interval_min (0x%04x) and/or"
        " advertising_interval_max (0x%04x) are outside the range"
        " of supported values (0x0020 - 0x4000)",
        advertising_interval_min, advertising_interval_max);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The Advertising_Interval_Min shall be less than or equal to the
  // Advertising_Interval_Max.
  if (advertising_interval_min > advertising_interval_max) {
    LOG_INFO(
        "advertising_interval_min (0x%04x) is larger than"
        " advertising_interval_max (0x%04x)",
        advertising_interval_min, advertising_interval_max);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  legacy_advertiser_.advertising_interval =
      advertising_type == AdvertisingType::ADV_DIRECT_IND_HIGH
          ? std::chrono::duration_cast<slots>(adv_direct_ind_high_interval)
          : slots(advertising_interval_min);
  legacy_advertiser_.advertising_type = advertising_type;
  legacy_advertiser_.own_address_type = own_address_type;
  legacy_advertiser_.peer_address_type = peer_address_type;
  legacy_advertiser_.peer_address = peer_address;
  legacy_advertiser_.advertising_channel_map = advertising_channel_map;
  legacy_advertiser_.advertising_filter_policy = advertising_filter_policy;
  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Advertising_Data (Vol 4, Part E § 7.8.7).
ErrorCode LinkLayerController::LeSetAdvertisingData(
    const std::vector<uint8_t>& advertising_data) {
  // Legacy advertising commands are disallowed when extended advertising
  // commands were used since the last reset.
  if (!SelectLegacyAdvertising()) {
    LOG_INFO(
        "legacy advertising command rejected because extended advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  legacy_advertiser_.advertising_data = advertising_data;
  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Scan_Response_Data (Vol 4, Part E § 7.8.8).
ErrorCode LinkLayerController::LeSetScanResponseData(
    const std::vector<uint8_t>& scan_response_data) {
  // Legacy advertising commands are disallowed when extended advertising
  // commands were used since the last reset.
  if (!SelectLegacyAdvertising()) {
    LOG_INFO(
        "legacy advertising command rejected because extended advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  legacy_advertiser_.scan_response_data = scan_response_data;
  return ErrorCode::SUCCESS;
}

// HCI command LE_Advertising_Enable (Vol 4, Part E § 7.8.9).
ErrorCode LinkLayerController::LeSetAdvertisingEnable(bool advertising_enable) {
  // Legacy advertising commands are disallowed when extended advertising
  // commands were used since the last reset.
  if (!SelectLegacyAdvertising()) {
    LOG_INFO(
        "legacy advertising command rejected because extended advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (!advertising_enable) {
    legacy_advertiser_.advertising_enable = false;
    return ErrorCode::SUCCESS;
  }

  AddressWithType peer_address = PeerDeviceAddress(
      legacy_advertiser_.peer_address, legacy_advertiser_.peer_address_type);
  AddressWithType public_address{address_, AddressType::PUBLIC_DEVICE_ADDRESS};
  AddressWithType random_address{random_address_,
                                 AddressType::RANDOM_DEVICE_ADDRESS};
  std::optional<AddressWithType> resolvable_address =
      GenerateResolvablePrivateAddress(peer_address, IrkSelection::Local);

  // TODO: additional checks would apply in the case of a LE only Controller
  // with no configured public device address.

  switch (legacy_advertiser_.own_address_type) {
    case OwnAddressType::PUBLIC_DEVICE_ADDRESS:
      legacy_advertiser_.advertising_address = public_address;
      break;

    case OwnAddressType::RANDOM_DEVICE_ADDRESS:
      // If Advertising_Enable is set to 0x01, the advertising parameters'
      // Own_Address_Type parameter is set to 0x01, and the random address for
      // the device has not been initialized using the HCI_LE_Set_Random_Address
      // command, the Controller shall return the error code
      // Invalid HCI Command Parameters (0x12).
      if (random_address.GetAddress() == Address::kEmpty) {
        LOG_INFO(
            "own_address_type is Random_Device_Address but the Random_Address"
            " has not been initialized");
        return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
      }
      legacy_advertiser_.advertising_address = random_address;
      break;

    case OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS:
      legacy_advertiser_.advertising_address =
          resolvable_address.value_or(public_address);
      break;

    case OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
      // If Advertising_Enable is set to 0x01, the advertising parameters'
      // Own_Address_Type parameter is set to 0x03, the controller's resolving
      // list did not contain a matching entry, and the random address for the
      // device has not been initialized using the HCI_LE_Set_Random_Address
      // command, the Controller shall return the error code Invalid HCI Command
      // Parameters (0x12).
      if (resolvable_address) {
        legacy_advertiser_.advertising_address = resolvable_address.value();
      } else if (random_address.GetAddress() == Address::kEmpty) {
        LOG_INFO(
            "own_address_type is Resolvable_Or_Random_Address but the"
            " Resolving_List does not contain a matching entry and the"
            " Random_Address is not initialized");
        return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
      } else {
        legacy_advertiser_.advertising_address = random_address;
      }
      break;
  }

  legacy_advertiser_.timeout = {};
  legacy_advertiser_.target_address =
      AddressWithType{Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS};

  switch (legacy_advertiser_.advertising_type) {
    case AdvertisingType::ADV_DIRECT_IND_HIGH:
      // The Link Layer shall exit the Advertising state no later than 1.28 s
      // after the Advertising state was entered.
      legacy_advertiser_.timeout =
          std::chrono::steady_clock::now() + adv_direct_ind_high_timeout;
      [[fallthrough]];

    case AdvertisingType::ADV_DIRECT_IND_LOW: {
      // Note: Vol 6, Part B § 6.2.2 Connectable directed event type
      //
      // If an IRK is available in the Link Layer Resolving
      // List for the peer device, then the target’s device address
      // (TargetA field) shall use a resolvable private address. If an IRK is
      // not available in the Link Layer Resolving List or the IRK is set to
      // zero for the peer device, then the target’s device address
      // (TargetA field) shall use the Identity Address when entering the
      // Advertising State and using connectable directed events.
      std::optional<AddressWithType> peer_resolvable_address =
          GenerateResolvablePrivateAddress(peer_address, IrkSelection::Peer);
      legacy_advertiser_.target_address =
          peer_resolvable_address.value_or(peer_address);
      break;
    }
    default:
      break;
  }

  legacy_advertiser_.advertising_enable = true;
  legacy_advertiser_.next_event = std::chrono::steady_clock::now() +
                                  legacy_advertiser_.advertising_interval;
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  Extended Advertising Commands
// =============================================================================

// HCI command LE_Set_Advertising_Set_Random_Address (Vol 4, Part E § 7.8.52).
ErrorCode LinkLayerController::LeSetAdvertisingSetRandomAddress(
    uint8_t advertising_handle, Address random_address) {
  // If the advertising set corresponding to the Advertising_Handle parameter
  // does not exist, then the Controller shall return the error code
  // Unknown Advertising Identifier (0x42).
  // TODO(c++20) unordered_map<>::contains
  if (extended_advertisers_.count(advertising_handle) == 0) {
    LOG_INFO("no advertising set defined with handle %02x",
             static_cast<int>(advertising_handle));
    return ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER;
  }

  ExtendedAdvertiser& advertiser = extended_advertisers_[advertising_handle];

  // If the Host issues this command while the advertising set identified by the
  // Advertising_Handle parameter is using connectable advertising and is
  // enabled, the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (advertiser.advertising_enable) {
    LOG_INFO("advertising is enabled for the specified advertising set");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  advertiser.random_address = random_address;
  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Extended_Advertising_Parameters (Vol 4, Part E § 7.8.53).
ErrorCode LinkLayerController::LeSetExtendedAdvertisingParameters(
    uint8_t advertising_handle,
    AdvertisingEventProperties advertising_event_properties,
    uint16_t primary_advertising_interval_min,
    uint16_t primary_advertising_interval_max,
    uint8_t primary_advertising_channel_map, OwnAddressType own_address_type,
    PeerAddressType peer_address_type, Address peer_address,
    AdvertisingFilterPolicy advertising_filter_policy,
    uint8_t advertising_tx_power, PrimaryPhyType primary_advertising_phy,
    uint8_t secondary_max_skip, SecondaryPhyType secondary_advertising_phy,
    uint8_t advertising_sid, bool scan_request_notification_enable) {
  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    LOG_INFO(
        "extended advertising command rejected because legacy advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  bool legacy_advertising = advertising_event_properties.legacy_;
  bool extended_advertising = !advertising_event_properties.legacy_;
  bool connectable_advertising = advertising_event_properties.connectable_;
  bool scannable_advertising = advertising_event_properties.scannable_;
  bool directed_advertising = advertising_event_properties.directed_;
  bool high_duty_cycle_advertising =
      advertising_event_properties.high_duty_cycle_;
  bool anonymous_advertising = advertising_event_properties.anonymous_;
  uint16_t raw_advertising_event_properties =
      ExtendedAdvertiser::GetRawAdvertisingEventProperties(
          advertising_event_properties);

  // Clear reserved bits.
  primary_advertising_channel_map &= 0x7;

  // If the Advertising_Handle does not identify an existing advertising set
  // and the Controller is unable to support a new advertising set at present,
  // the Controller shall return the error code Memory Capacity Exceeded (0x07).
  ExtendedAdvertiser advertiser(advertising_handle);

  // TODO(c++20) unordered_map<>::contains
  if (extended_advertisers_.count(advertising_handle) == 0) {
    if (extended_advertisers_.size() >=
        properties_.le_num_supported_advertising_sets) {
      LOG_INFO(
          "no advertising set defined with handle %02x and"
          " cannot allocate any more advertisers",
          static_cast<int>(advertising_handle));
      return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
    }
  } else {
    advertiser = extended_advertisers_[advertising_handle];
  }

  // If the Host issues this command when advertising is enabled for the
  // specified advertising set, the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (advertiser.advertising_enable) {
    LOG_INFO("advertising is enabled for the specified advertising set");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If legacy advertising PDU types are being used, then the parameter value
  // shall be one of those specified in Table 7.2.
  if (legacy_advertising &&
      (raw_advertising_event_properties & ~0x10) !=
          static_cast<uint16_t>(LegacyAdvertisingEventProperties::ADV_IND) &&
      (raw_advertising_event_properties & ~0x10) !=
          static_cast<uint16_t>(
              LegacyAdvertisingEventProperties::ADV_DIRECT_IND_LOW) &&
      (raw_advertising_event_properties & ~0x10) !=
          static_cast<uint16_t>(
              LegacyAdvertisingEventProperties::ADV_DIRECT_IND_HIGH) &&
      (raw_advertising_event_properties & ~0x10) !=
          static_cast<uint16_t>(
              LegacyAdvertisingEventProperties::ADV_SCAN_IND) &&
      (raw_advertising_event_properties & ~0x10) !=
          static_cast<uint16_t>(
              LegacyAdvertisingEventProperties::ADV_NONCONN_IND)) {
    LOG_INFO(
        "advertising_event_properties (0x%02x) is legacy but does not"
        " match valid legacy advertising event types",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  bool can_have_advertising_data =
      (legacy_advertising && !directed_advertising) ||
      (extended_advertising && !scannable_advertising);

  // If the Advertising_Event_Properties parameter [..] specifies a type that
  // does not support advertising data when the advertising set already
  // contains some, the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (!can_have_advertising_data && !advertiser.advertising_data.empty()) {
    LOG_INFO(
        "advertising_event_properties (0x%02x) specifies an event type"
        " that does not support avertising data but the set contains some",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Note: not explicitly specified in the specification but makes sense
  // in the context of the other checks.
  if (!scannable_advertising && !advertiser.scan_response_data.empty()) {
    LOG_INFO(
        "advertising_event_properties (0x%02x) specifies an event type"
        " that does not support scan response data but the set contains some",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the advertising set already contains data, the type shall be one that
  // supports advertising data and the amount of data shall not
  // exceed 31 octets.
  if (legacy_advertising &&
      (advertiser.advertising_data.size() > max_legacy_advertising_pdu_size ||
       advertiser.scan_response_data.size() >
           max_legacy_advertising_pdu_size)) {
    LOG_INFO(
        "advertising_event_properties (0x%02x) is legacy and the"
        " advertising data or scan response data exceeds the capacity"
        " of legacy PDUs",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If extended advertising PDU types are being used (bit 4 = 0) then:
  // The advertisement shall not be both connectable and scannable.
  if (extended_advertising && connectable_advertising &&
      scannable_advertising) {
    LOG_INFO(
        "advertising_event_properties (0x%02x) is extended and may not"
        " be connectable and scannable at the same time",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // High duty cycle directed connectable advertising (≤ 3.75 ms
  // advertising interval) shall not be used (bit 3 = 0).
  if (extended_advertising && connectable_advertising && directed_advertising &&
      high_duty_cycle_advertising) {
    LOG_INFO(
        "advertising_event_properties (0x%02x) is extended and may not"
        " be high-duty cycle directed connectable",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the primary advertising interval range provided by the Host
  // (Primary_Advertising_Interval_Min, Primary_Advertising_Interval_Max) is
  // outside the advertising interval range supported by the Controller, then
  // the Controller shall return the error code Unsupported Feature or
  // Parameter Value (0x11).
  if (primary_advertising_interval_min < 0x20 ||
      primary_advertising_interval_max < 0x20) {
    LOG_INFO(
        "primary_advertising_interval_min (0x%04x) and/or"
        " primary_advertising_interval_max (0x%04x) are outside the range"
        " of supported values (0x0020 - 0xffff)",
        primary_advertising_interval_min, primary_advertising_interval_max);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The Primary_Advertising_Interval_Min parameter shall be less than or equal
  // to the Primary_Advertising_Interval_Max parameter.
  if (primary_advertising_interval_min > primary_advertising_interval_max) {
    LOG_INFO(
        "primary_advertising_interval_min (0x%04x) is larger than"
        " primary_advertising_interval_max (0x%04x)",
        primary_advertising_interval_min, primary_advertising_interval_max);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // At least one channel bit shall be set in the
  // Primary_Advertising_Channel_Map parameter.
  if (primary_advertising_channel_map == 0) {
    LOG_INFO(
        "primary_advertising_channel_map does not enable any"
        " advertising channel");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If legacy advertising PDUs are being used, the
  // Primary_Advertising_PHY shall indicate the LE 1M PHY.
  if (legacy_advertising && primary_advertising_phy != PrimaryPhyType::LE_1M) {
    LOG_INFO(
        "advertising_event_properties (0x%04x) is legacy but"
        " primary_advertising_phy (%02x) is not LE 1M",
        raw_advertising_event_properties,
        static_cast<uint8_t>(primary_advertising_phy));
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If Constant Tone Extensions are enabled for the advertising set and
  // Secondary_Advertising_PHY specifies a PHY that does not allow
  // Constant Tone Extensions, the Controller shall
  // return the error code Command Disallowed (0x0C).
  if (advertiser.constant_tone_extensions &&
      secondary_advertising_phy == SecondaryPhyType::LE_CODED) {
    LOG_INFO(
        "constant tone extensions are enabled but"
        " secondary_advertising_phy (%02x) does not support them",
        static_cast<uint8_t>(secondary_advertising_phy));
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command when periodic advertising is enabled for
  // the specified advertising set and connectable, scannable, legacy,
  // or anonymous advertising is specified, the Controller shall return the
  // error code Invalid HCI Command Parameters (0x12).
  if (advertiser.periodic_advertising_enable &&
      (connectable_advertising || scannable_advertising || legacy_advertising ||
       anonymous_advertising)) {
    LOG_INFO(
        "periodic advertising is enabled for the specified advertising set"
        " and advertising_event_properties (0x%02x) is either"
        " connectable, scannable, legacy, or anonymous",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If periodic advertising is enabled for the advertising set and the
  // Secondary_Advertising_PHY parameter does not specify the PHY currently
  // being used for the periodic advertising, the Controller shall return the
  // error code Command Disallowed (0x0C).
#if 0
  if (advertiser.periodic_advertising_enable) {
    // TODO
    LOG_INFO(
        "periodic advertising is enabled for the specified advertising set"
        " and the secondary PHY does not match the periodic"
        " advertising PHY");
    return ErrorCode::COMMAND_DISALLOWED;
  }
#endif

  // If the advertising set already contains advertising data or scan response
  // data, extended advertising is being used, and the length of the data is
  // greater than the maximum that the Controller can transmit within the
  // longest possible auxiliary advertising segment consistent with the
  // parameters, the Controller shall return the error code
  // Packet Too Long (0x45). If advertising on the LE Coded PHY, the S=8
  // coding shall be assumed.
  if (extended_advertising &&
      (advertiser.advertising_data.size() > max_extended_advertising_pdu_size ||
       advertiser.scan_response_data.size() >
           max_extended_advertising_pdu_size)) {
    LOG_INFO(
        "the advertising data contained in the set is larger than the"
        " available PDU capacity");
    return ErrorCode::PACKET_TOO_LONG;
  }

  advertiser.advertising_event_properties = advertising_event_properties;
  advertiser.primary_advertising_interval =
      slots(primary_advertising_interval_min);
  advertiser.primary_advertising_channel_map = primary_advertising_channel_map;
  advertiser.own_address_type = own_address_type;
  advertiser.peer_address_type = peer_address_type;
  advertiser.peer_address = peer_address;
  advertiser.advertising_filter_policy = advertising_filter_policy;
  advertiser.advertising_tx_power = advertising_tx_power;
  advertiser.primary_advertising_phy = primary_advertising_phy;
  advertiser.secondary_max_skip = secondary_max_skip;
  advertiser.secondary_advertising_phy = secondary_advertising_phy;
  advertiser.advertising_sid = advertising_sid;
  advertiser.scan_request_notification_enable =
      scan_request_notification_enable;

  extended_advertisers_.insert_or_assign(advertising_handle,
                                         std::move(advertiser));
  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Extended_Advertising_Data (Vol 4, Part E § 7.8.54).
ErrorCode LinkLayerController::LeSetExtendedAdvertisingData(
    uint8_t advertising_handle, Operation operation,
    FragmentPreference fragment_preference,
    const std::vector<uint8_t>& advertising_data) {
  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    LOG_INFO(
        "extended advertising command rejected because legacy advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // fragment_preference is unused for now.
  (void)fragment_preference;

  // If the advertising set corresponding to the Advertising_Handle parameter
  // does not exist, then the Controller shall return the error code
  // Unknown Advertising Identifier (0x42).
  // TODO(c++20) unordered_map<>::contains
  if (extended_advertisers_.count(advertising_handle) == 0) {
    LOG_INFO("no advertising set defined with handle %02x",
             static_cast<int>(advertising_handle));
    return ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER;
  }

  ExtendedAdvertiser& advertiser = extended_advertisers_[advertising_handle];
  const AdvertisingEventProperties& advertising_event_properties =
      advertiser.advertising_event_properties;
  uint16_t raw_advertising_event_properties =
      ExtendedAdvertiser::GetRawAdvertisingEventProperties(
          advertising_event_properties);

  bool can_have_advertising_data = (advertising_event_properties.legacy_ &&
                                    !advertising_event_properties.directed_) ||
                                   (!advertising_event_properties.legacy_ &&
                                    !advertising_event_properties.scannable_);

  // If the advertising set specifies a type that does not support
  // advertising data, the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (!can_have_advertising_data) {
    LOG_INFO(
        "advertising_event_properties (%02x) does not support"
        " advertising data",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the advertising set uses legacy advertising PDUs that support
  // advertising data and either Operation is not 0x03 or the
  // Advertising_Data_Length parameter exceeds 31 octets, the Controller
  // shall return the error code Invalid HCI Command Parameters (0x12).
  if (advertising_event_properties.legacy_ &&
      (operation != Operation::COMPLETE_ADVERTISEMENT ||
       advertising_data.size() > max_legacy_advertising_pdu_size)) {
    LOG_INFO(
        "advertising_event_properties (%02x) is legacy and"
        " and an incomplete operation was used or the advertising data"
        " is larger than 31",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If Operation is 0x04 and:
  //    • advertising is currently disabled for the advertising set;
  //    • the advertising set contains no data;
  //    • the advertising set uses legacy PDUs; or
  //    • Advertising_Data_Length is not zero;
  // then the Controller shall return the error code Invalid HCI Command
  // Parameters (0x12).
  if (operation == Operation::UNCHANGED_DATA &&
      (!advertiser.advertising_enable || advertiser.advertising_data.empty() ||
       advertising_event_properties.legacy_ || !advertising_data.empty())) {
    LOG_INFO(
        "Unchanged_Data operation is used but advertising is disabled;"
        " or the advertising set contains no data;"
        " or the advertising set uses legacy PDUs;"
        " or the advertising data is not empty");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If Operation is not 0x03 or 0x04 and Advertising_Data_Length is zero,
  // the Controller shall return the error code Invalid HCI
  // Command Parameters (0x12).
  if (operation != Operation::COMPLETE_ADVERTISEMENT &&
      operation != Operation::UNCHANGED_DATA && advertising_data.empty()) {
    LOG_INFO(
        "operation (%02x) is not Complete_Advertisement or Unchanged_Data"
        " but the advertising data is empty",
        static_cast<int>(operation));
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If advertising is currently enabled for the specified advertising set and
  // Operation does not have the value 0x03 or 0x04, the Controller shall
  // return the error code Command Disallowed (0x0C).
  if (advertiser.advertising_enable &&
      operation != Operation::COMPLETE_ADVERTISEMENT &&
      operation != Operation::UNCHANGED_DATA) {
    LOG_INFO(
        "operation (%02x) is used but advertising is enabled for the"
        " specified advertising set",
        static_cast<int>(operation));
    return ErrorCode::COMMAND_DISALLOWED;
  }

  switch (operation) {
    case Operation::INTERMEDIATE_FRAGMENT:
      advertiser.advertising_data.insert(advertiser.advertising_data.end(),
                                         advertising_data.begin(),
                                         advertising_data.end());
      advertiser.partial_advertising_data = true;
      break;

    case Operation::FIRST_FRAGMENT:
      advertiser.advertising_data = advertising_data;
      advertiser.partial_advertising_data = true;
      break;

    case Operation::LAST_FRAGMENT:
      advertiser.advertising_data.insert(advertiser.advertising_data.end(),
                                         advertising_data.begin(),
                                         advertising_data.end());
      advertiser.partial_advertising_data = false;
      break;

    case Operation::COMPLETE_ADVERTISEMENT:
      advertiser.advertising_data = advertising_data;
      advertiser.partial_advertising_data = false;
      break;

    case Operation::UNCHANGED_DATA:
      break;

    default:
      LOG_INFO("unknown operation (%x)", static_cast<int>(operation));
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the combined length of the data exceeds the capacity of the
  // advertising set identified by the Advertising_Handle parameter
  // (see Section 7.8.57 LE Read Maximum Advertising Data Length command)
  // or the amount of memory currently available, all the data
  // shall be discarded and the Controller shall return the error code Memory
  // Capacity Exceeded (0x07).
  if (advertiser.advertising_data.size() >
      properties_.le_max_advertising_data_length) {
    LOG_INFO(
        "the combined length %zu of the advertising data exceeds the"
        " advertising set capacity %d",
        advertiser.advertising_data.size(),
        properties_.le_max_advertising_data_length);
    advertiser.advertising_data.clear();
    advertiser.partial_advertising_data = false;
    return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
  }

  // If advertising is currently enabled for the specified advertising set,
  // the advertising set uses extended advertising, and the length of the
  // data is greater than the maximum that the Controller can transmit within
  // the longest possible auxiliary advertising segment consistent with the
  // current parameters of the advertising set, the Controller shall return
  // the error code Packet Too Long (0x45). If advertising on the
  // LE Coded PHY, the S=8 coding shall be assumed.
  size_t max_advertising_data_length =
      ExtendedAdvertiser::GetMaxAdvertisingDataLength(
          advertising_event_properties);
  if (advertiser.advertising_enable &&
      advertiser.advertising_data.size() > max_advertising_data_length) {
    LOG_INFO(
        "the advertising data contained in the set is larger than the"
        " available PDU capacity");
    advertiser.advertising_data.clear();
    advertiser.partial_advertising_data = false;
    return ErrorCode::PACKET_TOO_LONG;
  }

  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Extended_Scan_Response_Data (Vol 4, Part E § 7.8.55).
ErrorCode LinkLayerController::LeSetExtendedScanResponseData(
    uint8_t advertising_handle, Operation operation,
    FragmentPreference fragment_preference,
    const std::vector<uint8_t>& scan_response_data) {
  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    LOG_INFO(
        "extended advertising command rejected because legacy advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // fragment_preference is unused for now.
  (void)fragment_preference;

  // If the advertising set corresponding to the Advertising_Handle parameter
  // does not exist, then the Controller shall return the error code
  // Unknown Advertising Identifier (0x42).
  // TODO(c++20) unordered_map<>::contains
  if (extended_advertisers_.count(advertising_handle) == 0) {
    LOG_INFO("no advertising set defined with handle %02x",
             static_cast<int>(advertising_handle));
    return ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER;
  }

  ExtendedAdvertiser& advertiser = extended_advertisers_[advertising_handle];
  const AdvertisingEventProperties& advertising_event_properties =
      advertiser.advertising_event_properties;
  uint16_t raw_advertising_event_properties =
      ExtendedAdvertiser::GetRawAdvertisingEventProperties(
          advertising_event_properties);

  // If the advertising set is non-scannable and the Host uses this
  // command other than to discard existing data, the Controller shall
  // return the error code Invalid HCI Command Parameters (0x12).
  if (!advertising_event_properties.scannable_ && !scan_response_data.empty()) {
    LOG_INFO(
        "advertising_event_properties (%02x) is not scannable"
        " but the scan response data is not empty",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the advertising set uses scannable legacy advertising PDUs and
  // either Operation is not 0x03 or the Scan_Response_Data_Length
  // parameter exceeds 31 octets, the Controller shall
  // return the error code Invalid HCI Command Parameters (0x12).
  if (advertising_event_properties.scannable_ &&
      advertising_event_properties.legacy_ &&
      (operation != Operation::COMPLETE_ADVERTISEMENT ||
       scan_response_data.size() > max_legacy_advertising_pdu_size)) {
    LOG_INFO(
        "advertising_event_properties (%02x) is scannable legacy"
        " and an incomplete operation was used or the scan response data"
        " is larger than 31",
        raw_advertising_event_properties);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If Operation is not 0x03 and Scan_Response_Data_Length is zero, the
  // Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (operation != Operation::COMPLETE_ADVERTISEMENT &&
      scan_response_data.empty()) {
    LOG_INFO(
        "operation (%02x) is not Complete_Advertisement but the"
        " scan response data is empty",
        static_cast<int>(operation));
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If advertising is currently enabled for the specified advertising set and
  // Operation does not have the value 0x03, the Controller shall
  // return the error code Command Disallowed (0x0C).
  if (advertiser.advertising_enable &&
      operation != Operation::COMPLETE_ADVERTISEMENT) {
    LOG_INFO(
        "operation (%02x) is used but advertising is enabled for the"
        " specified advertising set",
        static_cast<int>(operation));
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the advertising set uses scannable extended advertising PDUs,
  // advertising is currently enabled for the specified advertising set,
  // and Scan_Response_Data_Length is zero, the Controller shall return
  // the error code Command Disallowed (0x0C).
  if (advertiser.advertising_enable &&
      advertising_event_properties.scannable_ &&
      !advertising_event_properties.legacy_ && scan_response_data.empty()) {
    LOG_INFO(
        "advertising_event_properties (%02x) is scannable extended,"
        " advertising is enabled for the specified advertising set"
        " and the scan response data is empty",
        raw_advertising_event_properties);
    return ErrorCode::COMMAND_DISALLOWED;
  }

  switch (operation) {
    case Operation::INTERMEDIATE_FRAGMENT:
      advertiser.scan_response_data.insert(advertiser.scan_response_data.end(),
                                           scan_response_data.begin(),
                                           scan_response_data.end());
      advertiser.partial_scan_response_data = true;
      break;

    case Operation::FIRST_FRAGMENT:
      advertiser.scan_response_data = scan_response_data;
      advertiser.partial_scan_response_data = true;
      break;

    case Operation::LAST_FRAGMENT:
      advertiser.scan_response_data.insert(advertiser.scan_response_data.end(),
                                           scan_response_data.begin(),
                                           scan_response_data.end());
      advertiser.partial_scan_response_data = false;
      break;

    case Operation::COMPLETE_ADVERTISEMENT:
      advertiser.scan_response_data = scan_response_data;
      advertiser.partial_scan_response_data = false;
      break;

    case Operation::UNCHANGED_DATA:
      LOG_INFO(
          "the operation Unchanged_Data is only allowed"
          " for Advertising_Data");
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;

    default:
      LOG_INFO("unknown operation (%x)", static_cast<int>(operation));
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the combined length of the data exceeds the capacity of the
  // advertising set identified by the Advertising_Handle parameter
  // (see Section 7.8.57 LE Read Maximum Advertising Data Length command)
  // or the amount of memory currently available, all the data shall be
  // discarded and the Controller shall return the error code
  // Memory Capacity Exceeded (0x07).
  if (advertiser.scan_response_data.size() >
      properties_.le_max_advertising_data_length) {
    LOG_INFO(
        "the combined length of the scan response data exceeds the"
        " advertising set capacity");
    advertiser.scan_response_data.clear();
    advertiser.partial_scan_response_data = false;
    return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
  }

  // If the advertising set uses extended advertising and the combined length
  // of the data is greater than the maximum that the Controller can transmit
  // within the longest possible auxiliary advertising segment consistent
  // with the current parameters of the advertising set (using the current
  // advertising interval if advertising is enabled), all the data shall be
  // discarded and the Controller shall return the error code
  // Packet Too Long (0x45). If advertising on the LE Coded PHY,
  // the S=8 coding shall be assumed.
  if (advertiser.scan_response_data.size() >
      max_extended_advertising_pdu_size) {
    LOG_INFO(
        "the scan response data contained in the set is larger than the"
        " available PDU capacity");
    advertiser.scan_response_data.clear();
    advertiser.partial_scan_response_data = false;
    return ErrorCode::PACKET_TOO_LONG;
  }

  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Extended_Advertising_Enable (Vol 4, Part E § 7.8.56).
ErrorCode LinkLayerController::LeSetExtendedAdvertisingEnable(
    bool enable, const std::vector<bluetooth::hci::EnabledSet>& sets) {
  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    LOG_INFO(
        "extended advertising command rejected because legacy advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // Validate the advertising handles.
  std::array<bool, UINT8_MAX> used_advertising_handles{};
  for (auto& set : sets) {
    // If the same advertising set is identified by more than one entry in the
    // Advertising_Handle[i] arrayed parameter, then the Controller shall return
    // the error code Invalid HCI Command Parameters (0x12).
    if (used_advertising_handles[set.advertising_handle_]) {
      LOG_INFO("advertising handle %02x is added more than once",
               set.advertising_handle_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    // If the advertising set corresponding to the Advertising_Handle[i]
    // parameter does not exist, then the Controller shall return the error code
    // Unknown Advertising Identifier (0x42).
    if (extended_advertisers_.find(set.advertising_handle_) ==
        extended_advertisers_.end()) {
      LOG_INFO("advertising handle %02x is not defined",
               set.advertising_handle_);
      return ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER;
    }

    used_advertising_handles[set.advertising_handle_] = true;
  }

  // If Enable and Num_Sets are both set to
  // 0x00, then all advertising sets are disabled.
  if (!enable && sets.empty()) {
    for (auto& advertiser : extended_advertisers_) {
      advertiser.second.advertising_enable = false;
    }
    return ErrorCode::SUCCESS;
  }

  // If Num_Sets is set to 0x00, the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (sets.empty()) {
    LOG_INFO("enable is true but no advertising set is selected");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // No additional checks for disabling advertising sets.
  if (!enable) {
    for (auto& set : sets) {
      auto& advertiser = extended_advertisers_[set.advertising_handle_];
      advertiser.advertising_enable = false;
    }
    return ErrorCode::SUCCESS;
  }

  // Validate the advertising parameters before enabling any set.
  for (auto& set : sets) {
    ExtendedAdvertiser& advertiser =
        extended_advertisers_[set.advertising_handle_];
    const AdvertisingEventProperties& advertising_event_properties =
        advertiser.advertising_event_properties;

    bool extended_advertising = !advertising_event_properties.legacy_;
    bool connectable_advertising = advertising_event_properties.connectable_;
    bool scannable_advertising = advertising_event_properties.scannable_;
    bool directed_advertising = advertising_event_properties.directed_;
    bool high_duty_cycle_advertising =
        advertising_event_properties.high_duty_cycle_;

    // If the advertising is high duty cycle connectable directed advertising,
    // then Duration[i] shall be less than or equal to 1.28 seconds and shall
    // not be equal to 0.
    if (connectable_advertising && directed_advertising &&
        high_duty_cycle_advertising &&
        (set.duration_ == 0 ||
         slots(set.duration_) > adv_direct_ind_high_timeout)) {
      LOG_INFO(
          "extended advertising is high duty cycle connectable directed"
          " but the duration is either 0 or larger than 1.28 seconds");
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    // If the advertising set contains partial advertising data or partial
    // scan response data, the Controller shall return the error code
    // Command Disallowed (0x0C).
    if (advertiser.partial_advertising_data ||
        advertiser.partial_scan_response_data) {
      LOG_INFO(
          "advertising set contains partial advertising"
          " or scan response data");
      return ErrorCode::COMMAND_DISALLOWED;
    }

    // If the advertising set uses scannable extended advertising PDUs and no
    // scan response data is currently provided, the Controller shall return the
    // error code Command Disallowed (0x0C).
    if (extended_advertising && scannable_advertising &&
        advertiser.scan_response_data.empty()) {
      LOG_INFO(
          "advertising set uses scannable extended advertising PDUs"
          " but no scan response data is provided");
      return ErrorCode::COMMAND_DISALLOWED;
    }

    // If the advertising set uses connectable extended advertising PDUs and the
    // advertising data in the advertising set will not fit in the
    // AUX_ADV_IND PDU, the Controller shall return the error code
    // Invalid HCI Command Parameters (0x12).
    if (extended_advertising && connectable_advertising &&
        advertiser.advertising_data.size() >
            ExtendedAdvertiser::GetMaxAdvertisingDataLength(
                advertising_event_properties)) {
      LOG_INFO(
          "advertising set uses connectable extended advertising PDUs"
          " but the advertising data does not fit in AUX_ADV_IND PDUs");
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    // If extended advertising is being used and the length of any advertising
    // data or of any scan response data is greater than the maximum that the
    // Controller can transmit within the longest possible auxiliary
    // advertising segment consistent with the chosen advertising interval,
    // the Controller shall return the error code Packet Too Long (0x45).
    // If advertising on the LE Coded PHY, the S=8 coding shall be assumed.
    if (extended_advertising && (advertiser.advertising_data.size() >
                                     max_extended_advertising_pdu_size ||
                                 advertiser.scan_response_data.size() >
                                     max_extended_advertising_pdu_size)) {
      LOG_INFO(
          "advertising set uses extended advertising PDUs"
          " but the advertising data does not fit in advertising PDUs");
      return ErrorCode::PACKET_TOO_LONG;
    }

    AddressWithType peer_address = PeerDeviceAddress(
        advertiser.peer_address, advertiser.peer_address_type);
    AddressWithType public_address{address_,
                                   AddressType::PUBLIC_DEVICE_ADDRESS};
    AddressWithType random_address{
        advertiser.random_address.value_or(Address::kEmpty),
        AddressType::RANDOM_DEVICE_ADDRESS};
    std::optional<AddressWithType> resolvable_address =
        GenerateResolvablePrivateAddress(peer_address, IrkSelection::Local);

    // TODO: additional checks would apply in the case of a LE only Controller
    // with no configured public device address.

    switch (advertiser.own_address_type) {
      case OwnAddressType::PUBLIC_DEVICE_ADDRESS:
        advertiser.advertising_address = public_address;
        break;

      case OwnAddressType::RANDOM_DEVICE_ADDRESS:
        // If the advertising set's Own_Address_Type parameter is set to 0x01
        // and the random address for the advertising set has not been
        // initialized using the HCI_LE_Set_Advertising_Set_Random_Address
        // command, the Controller shall return the error code
        // Invalid HCI Command Parameters (0x12).
        if (random_address.GetAddress() == Address::kEmpty) {
          LOG_INFO(
              "own_address_type is Random_Device_Address but the Random_Address"
              " has not been initialized");
          return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
        }
        advertiser.advertising_address = random_address;
        break;

      case OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS:
        advertiser.advertising_address =
            resolvable_address.value_or(public_address);
        break;

      case OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
        // If the advertising set's Own_Address_Type parameter is set to 0x03,
        // the controller's resolving list did not contain a matching entry,
        // and the random address for the advertising set has not been
        // initialized using the HCI_LE_Set_Advertising_Set_Random_Address
        // command, the Controller shall return the error code
        // Invalid HCI Command Parameters (0x12).
        if (resolvable_address) {
          advertiser.advertising_address = resolvable_address.value();
        } else if (random_address.GetAddress() == Address::kEmpty) {
          LOG_INFO(
              "own_address_type is Resolvable_Or_Random_Address but the"
              " Resolving_List does not contain a matching entry and the"
              " Random_Address is not initialized");
          return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
        } else {
          advertiser.advertising_address = random_address;
        }
        break;
    }
  }

  for (auto& set : sets) {
    ExtendedAdvertiser& advertiser =
        extended_advertisers_[set.advertising_handle_];

    advertiser.num_completed_extended_advertising_events = 0;
    advertiser.advertising_enable = true;
    advertiser.next_event = std::chrono::steady_clock::now() +
                            advertiser.primary_advertising_interval;
  }

  return ErrorCode::SUCCESS;
}

// HCI command LE_Remove_Advertising_Set (Vol 4, Part E § 7.8.59).
ErrorCode LinkLayerController::LeRemoveAdvertisingSet(
    uint8_t advertising_handle) {
  // If the advertising set corresponding to the Advertising_Handle parameter
  // does not exist, then the Controller shall return the error code
  // Unknown Advertising Identifier (0x42).
  auto advertiser = extended_advertisers_.find(advertising_handle);
  if (advertiser == extended_advertisers_.end()) {
    LOG_INFO("no advertising set defined with handle %02x",
             static_cast<int>(advertising_handle));
    return ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER;
  }

  // If advertising or periodic advertising on the advertising set is
  // enabled, then the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (advertiser->second.advertising_enable) {
    LOG_INFO("the advertising set defined with handle %02x is enabled",
             static_cast<int>(advertising_handle));
    return ErrorCode::COMMAND_DISALLOWED;
  }

  extended_advertisers_.erase(advertiser);
  return ErrorCode::SUCCESS;
}

// HCI command LE_Clear_Advertising_Sets (Vol 4, Part E § 7.8.60).
ErrorCode LinkLayerController::LeClearAdvertisingSets() {
  // If advertising or periodic advertising is enabled on any advertising set,
  // then the Controller shall return the error code Command Disallowed (0x0C).
  for (auto& advertiser : extended_advertisers_) {
    if (advertiser.second.advertising_enable) {
      LOG_INFO("the advertising set with handle %02x is enabled",
               static_cast<int>(advertiser.second.advertising_enable));
      return ErrorCode::COMMAND_DISALLOWED;
    }
  }

  extended_advertisers_.clear();
  return ErrorCode::SUCCESS;
}

uint16_t ExtendedAdvertiser::GetMaxAdvertisingDataLength(
    const AdvertisingEventProperties& properties) {
  // The PDU AdvData size is defined in the following sections:
  // - Vol 6, Part B § 2.3.1.1 ADV_IND
  // - Vol 6, Part B § 2.3.1.2 ADV_DIRECT_IND
  // - Vol 6, Part B § 2.3.1.3 ADV_NONCONN_IND
  // - Vol 6, Part B § 2.3.1.4 ADV_SCAN_IND
  // - Vol 6, Part B § 2.3.1.5 ADV_EXT_IND
  // - Vol 6, Part B § 2.3.1.6 AUX_ADV_IND
  // - Vol 6, Part B § 2.3.1.8 AUX_CHAIN_IND
  // - Vol 6, Part B § 2.3.4 Common Extended Advertising Payload Format
  uint16_t max_advertising_data_length;

  if (properties.legacy_ && properties.directed_) {
    // Directed legacy advertising PDUs do not have AdvData payload.
    max_advertising_data_length = 0;
  } else if (properties.legacy_) {
    max_advertising_data_length = max_legacy_advertising_pdu_size;
  } else if (properties.scannable_) {
    // Scannable extended advertising PDUs do not have AdvData payload.
    max_advertising_data_length = 0;
  } else if (!properties.connectable_) {
    // When extended advertising is non-scannable and non-connectable,
    // AUX_CHAIN_IND PDUs can be used, and the advertising data may be
    // fragmented over multiple PDUs; the length is still capped at 1650
    // as stated in Vol 6, Part B § 2.3.4.9 Host Advertising Data.
    max_advertising_data_length = max_extended_advertising_pdu_size;
  } else {
    // When extended advertising is either scannable or connectable,
    // AUX_CHAIN_IND PDUs may not be used, and the maximum advertising data
    // length is 254. Extended payload header fields eat into the
    // available space.
    max_advertising_data_length = 254;
    max_advertising_data_length -= 6;                         // AdvA
    max_advertising_data_length -= 2;                         // ADI
    max_advertising_data_length -= 6 * properties.directed_;  // TargetA
    max_advertising_data_length -= 1 * properties.tx_power_;  // TxPower
    // TODO(pedantic): configure the ACAD field in order to leave the least
    // amount of AdvData space to the user (191).
  }

  return max_advertising_data_length;
}

uint16_t ExtendedAdvertiser::GetMaxScanResponseDataLength(
    const AdvertisingEventProperties& properties) {
  // The PDU AdvData size is defined in the following sections:
  // - Vol 6, Part B § 2.3.2.2 SCAN_RSP
  // - Vol 6, Part B § 2.3.2.3 AUX_SCAN_RSP
  // - Vol 6, Part B § 2.3.1.8 AUX_CHAIN_IND
  // - Vol 6, Part B § 2.3.4 Common Extended Advertising Payload Format
  uint16_t max_scan_response_data_length;

  if (!properties.scannable_) {
    max_scan_response_data_length = 0;
  } else if (properties.legacy_) {
    max_scan_response_data_length = max_legacy_advertising_pdu_size;
  } else {
    // Extended scan response data may be sent over AUX_CHAIN_PDUs, and
    // the advertising data may be fragmented over multiple PDUs; the length
    // is still capped at 1650 as stated in
    // Vol 6, Part B § 2.3.4.9 Host Advertising Data.
    max_scan_response_data_length = max_extended_advertising_pdu_size;
  }

  return max_scan_response_data_length;
}

uint16_t ExtendedAdvertiser::GetRawAdvertisingEventProperties(
    const AdvertisingEventProperties& properties) {
  uint16_t mask = 0;
  if (properties.connectable_) {
    mask |= 0x1;
  }
  if (properties.scannable_) {
    mask |= 0x2;
  }
  if (properties.directed_) {
    mask |= 0x4;
  }
  if (properties.high_duty_cycle_) {
    mask |= 0x8;
  }
  if (properties.legacy_) {
    mask |= 0x10;
  }
  if (properties.anonymous_) {
    mask |= 0x20;
  }
  if (properties.tx_power_) {
    mask |= 0x40;
  }
  return mask;
}

// =============================================================================
//  Advertising Routines
// =============================================================================

void LinkLayerController::LeAdvertising() {
  chrono::time_point now = std::chrono::steady_clock::now();

  // Legacy Advertising Timeout

  // Generate HCI Connection Complete or Enhanced HCI Connection Complete
  // events with Advertising Timeout error code when the advertising
  // type is ADV_DIRECT_IND and the connection failed to be established.
  if (legacy_advertiser_.IsEnabled() && legacy_advertiser_.timeout &&
      now >= legacy_advertiser_.timeout.value()) {
    // If the Advertising_Type parameter is 0x01 (ADV_DIRECT_IND, high duty
    // cycle) and the directed advertising fails to create a connection, an
    // HCI_LE_Connection_Complete or HCI_LE_Enhanced_Connection_Complete
    // event shall be generated with the Status code set to
    // Advertising Timeout (0x3C).
    LOG_INFO("Directed Advertising Timeout");
    legacy_advertiser_.Disable();

    // TODO: The PTS tool expects an LE_Connection_Complete event in this
    // case and will fail the test GAP/DISC/GENP/BV-05-C if
    // LE_Enhanced_Connection_Complete is sent instead.
    //
    // Note: HCI_LE_Connection_Complete is not sent if the
    // HCI_LE_Enhanced_Connection_Complete event (see Section 7.7.65.10)
    // is unmasked.
#if 0
    if (IsLeEventUnmasked(SubeventCode::ENHANCED_CONNECTION_COMPLETE)) {
      send_event_(bluetooth::hci::LeEnhancedConnectionCompleteBuilder::Create(
          ErrorCode::ADVERTISING_TIMEOUT, 0, Role::CENTRAL,
          AddressType::PUBLIC_DEVICE_ADDRESS, Address(), Address(), Address(),
          0, 0, 0, ClockAccuracy::PPM_500));
    } else
#endif
    if (IsLeEventUnmasked(SubeventCode::CONNECTION_COMPLETE)) {
      send_event_(bluetooth::hci::LeConnectionCompleteBuilder::Create(
          ErrorCode::ADVERTISING_TIMEOUT, 0, Role::CENTRAL,
          AddressType::PUBLIC_DEVICE_ADDRESS, Address(), 0, 0, 0,
          ClockAccuracy::PPM_500));
    }
  }

  // Legacy Advertising Event

  // Generate Link Layer Advertising events when advertising is enabled
  // and a full interval has passed since the last event.
  if (legacy_advertiser_.IsEnabled() && now >= legacy_advertiser_.next_event) {
    legacy_advertiser_.next_event += legacy_advertiser_.advertising_interval;
    model::packets::LegacyAdvertisingType type;
    bool attach_advertising_data = true;
    switch (legacy_advertiser_.advertising_type) {
      case AdvertisingType::ADV_IND:
        type = model::packets::LegacyAdvertisingType::ADV_IND;
        break;
      case AdvertisingType::ADV_DIRECT_IND_HIGH:
      case AdvertisingType::ADV_DIRECT_IND_LOW:
        attach_advertising_data = false;
        type = model::packets::LegacyAdvertisingType::ADV_DIRECT_IND;
        break;
      case AdvertisingType::ADV_SCAN_IND:
        type = model::packets::LegacyAdvertisingType::ADV_SCAN_IND;
        break;
      case AdvertisingType::ADV_NONCONN_IND:
        type = model::packets::LegacyAdvertisingType::ADV_NONCONN_IND;
        break;
    }

    SendLeLinkLayerPacket(
        model::packets::LeLegacyAdvertisingPduBuilder::Create(
            legacy_advertiser_.advertising_address.GetAddress(),
            legacy_advertiser_.target_address.GetAddress(),
            static_cast<model::packets::AddressType>(
                legacy_advertiser_.advertising_address.GetAddressType()),
            static_cast<model::packets::AddressType>(
                legacy_advertiser_.target_address.GetAddressType()),
            type,
            attach_advertising_data ? legacy_advertiser_.advertising_data
                                    : std::vector<uint8_t>{}),
        properties_.le_advertising_physical_channel_tx_power);
  }

  for (auto& [_, advertiser] : extended_advertisers_) {
    // Extended Advertising Timeouts

    if (advertiser.IsEnabled() && advertiser.timeout &&
        now >= advertiser.timeout.value()) {
      // If the Duration[i] parameter is set to a value other than 0x0000, an
      // HCI_LE_Advertising_Set_Terminated event shall be generated when the
      // duration specified in the Duration[i] parameter expires.
      // However, if the advertising set is for high duty cycle connectable
      // directed advertising and no connection is created before the duration
      // expires, an HCI_LE_Connection_Complete or
      // HCI_LE_Enhanced_Connection_Complete event with the Status parameter
      // set to the error code Advertising Timeout (0x3C) may be generated
      // instead of or in addition to the HCI_LE_Advertising_Set_Terminated
      // event.
      LOG_INFO("Extended Advertising Timeout");
      advertiser.Disable();

      bool high_duty_cycle_connectable_directed_advertising =
          advertiser.advertising_event_properties.directed_ &&
          advertiser.advertising_event_properties.connectable_ &&
          advertiser.advertising_event_properties.high_duty_cycle_;

      // Note: HCI_LE_Connection_Complete is not sent if the
      // HCI_LE_Enhanced_Connection_Complete event (see Section 7.7.65.10)
      // is unmasked.
      if (high_duty_cycle_connectable_directed_advertising &&
          IsLeEventUnmasked(SubeventCode::ENHANCED_CONNECTION_COMPLETE)) {
        send_event_(bluetooth::hci::LeEnhancedConnectionCompleteBuilder::Create(
            ErrorCode::ADVERTISING_TIMEOUT, 0, Role::CENTRAL,
            AddressType::PUBLIC_DEVICE_ADDRESS, Address(), Address(), Address(),
            0, 0, 0, ClockAccuracy::PPM_500));
      } else if (high_duty_cycle_connectable_directed_advertising &&
                 IsLeEventUnmasked(SubeventCode::CONNECTION_COMPLETE)) {
        send_event_(bluetooth::hci::LeConnectionCompleteBuilder::Create(
            ErrorCode::ADVERTISING_TIMEOUT, 0, Role::CENTRAL,
            AddressType::PUBLIC_DEVICE_ADDRESS, Address(), 0, 0, 0,
            ClockAccuracy::PPM_500));
      }

      if (IsLeEventUnmasked(SubeventCode::ADVERTISING_SET_TERMINATED)) {
        send_event_(bluetooth::hci::LeAdvertisingSetTerminatedBuilder::Create(
            ErrorCode::ADVERTISING_TIMEOUT, advertiser.advertising_handle, 0,
            advertiser.num_completed_extended_advertising_events));
      }
    }

    if (advertiser.IsEnabled() && advertiser.max_extended_advertising_events &&
        advertiser.num_completed_extended_advertising_events >=
            advertiser.max_extended_advertising_events) {
      // If the Max_Extended_Advertising_Events[i] parameter is set to a value
      // other than 0x00, an HCI_LE_Advertising_Set_Terminated event shall be
      // generated when the maximum number of extended advertising events has
      // been transmitted by the Controller.
      LOG_INFO("Max Extended Advertising count reached");
      advertiser.Disable();

      if (IsLeEventUnmasked(SubeventCode::ADVERTISING_SET_TERMINATED)) {
        send_event_(bluetooth::hci::LeAdvertisingSetTerminatedBuilder::Create(
            ErrorCode::ADVERTISING_TIMEOUT, advertiser.advertising_handle, 0,
            advertiser.num_completed_extended_advertising_events));
      }
    }

    // Extended Advertising Event

    // Generate Link Layer Advertising events when advertising is enabled
    // and a full interval has passed since the last event.
    if (advertiser.IsEnabled() && now >= advertiser.next_event) {
      advertiser.next_event += advertiser.primary_advertising_interval;
      advertiser.num_completed_extended_advertising_events++;

      if (advertiser.advertising_event_properties.legacy_) {
        model::packets::LegacyAdvertisingType type;
        uint16_t raw_advertising_event_properties =
            ExtendedAdvertiser::GetRawAdvertisingEventProperties(
                advertiser.advertising_event_properties);
        switch (static_cast<LegacyAdvertisingEventProperties>(
            raw_advertising_event_properties & 0xf)) {
          case LegacyAdvertisingEventProperties::ADV_IND:
            type = model::packets::LegacyAdvertisingType::ADV_IND;
            break;
          case LegacyAdvertisingEventProperties::ADV_DIRECT_IND_HIGH:
          case LegacyAdvertisingEventProperties::ADV_DIRECT_IND_LOW:
            type = model::packets::LegacyAdvertisingType::ADV_DIRECT_IND;
            break;
          case LegacyAdvertisingEventProperties::ADV_SCAN_IND:
            type = model::packets::LegacyAdvertisingType::ADV_SCAN_IND;
            break;
          case LegacyAdvertisingEventProperties::ADV_NONCONN_IND:
            type = model::packets::LegacyAdvertisingType::ADV_NONCONN_IND;
            break;
          default:
            ASSERT(
                "unexpected raw advertising event properties;"
                " please check the extended advertising parameter validation");
            break;
        }

        SendLeLinkLayerPacket(
            model::packets::LeLegacyAdvertisingPduBuilder::Create(
                advertiser.advertising_address.GetAddress(),
                advertiser.target_address.GetAddress(),
                static_cast<model::packets::AddressType>(
                    advertiser.advertising_address.GetAddressType()),
                static_cast<model::packets::AddressType>(
                    advertiser.target_address.GetAddressType()),
                type, advertiser.advertising_data),
            advertiser.advertising_tx_power);
      } else {
        SendLeLinkLayerPacket(
            model::packets::LeExtendedAdvertisingPduBuilder::Create(
                advertiser.advertising_address.GetAddress(),
                advertiser.target_address.GetAddress(),
                static_cast<model::packets::AddressType>(
                    advertiser.advertising_address.GetAddressType()),
                static_cast<model::packets::AddressType>(
                    advertiser.target_address.GetAddressType()),
                advertiser.advertising_event_properties.connectable_,
                advertiser.advertising_event_properties.scannable_,
                advertiser.advertising_event_properties.directed_,
                advertiser.advertising_sid, advertiser.advertising_tx_power,
                static_cast<model::packets::PrimaryPhyType>(
                    advertiser.primary_advertising_phy),
                static_cast<model::packets::SecondaryPhyType>(
                    advertiser.secondary_advertising_phy),
                advertiser.advertising_data),
            advertiser.advertising_tx_power);
      }
    }
  }
}

}  // namespace rootcanal
