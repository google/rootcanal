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
#include "os/log.h"

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

void LeAdvertiser::InitializeExtended(
    unsigned advertising_handle, OwnAddressType address_type,
    AddressWithType public_address, AddressWithType peer_address,
    AdvertisingFilterPolicy filter_policy, AdvertisingType type,
    std::chrono::steady_clock::duration interval, uint8_t tx_power,
    const std::function<bluetooth::hci::Address()>& get_address) {
  get_address_ = get_address;
  own_address_type_ = address_type;
  public_address_ = public_address;
  advertising_handle_ = advertising_handle;
  peer_address_ = peer_address;
  filter_policy_ = filter_policy;
  type_ = type;
  interval_ = interval;
  tx_power_ = tx_power;
  LOG_INFO("%s -> %s type = %hhx interval = %d ms tx_power = 0x%hhx",
           public_address_.ToString().c_str(), peer_address.ToString().c_str(),
           type_, static_cast<int>(interval_.count()), tx_power);
}

void LeAdvertiser::Clear() {
  address_ = AddressWithType{};
  peer_address_ = AddressWithType{};
  filter_policy_ = AdvertisingFilterPolicy::ALL_DEVICES;
  type_ = AdvertisingType::ADV_IND;
  advertisement_.clear();
  scan_response_.clear();
  interval_ = 0ms;
  enabled_ = false;
}

void LeAdvertiser::SetAddress(Address address) {
  LOG_INFO("set address %s", address_.ToString().c_str());
  address_ = AddressWithType(address, address_.GetAddressType());
}

AddressWithType LeAdvertiser::GetAddress() const { return address_; }

void LeAdvertiser::SetData(const std::vector<uint8_t>& data) {
  advertisement_ = data;
}

void LeAdvertiser::SetScanResponse(const std::vector<uint8_t>& data) {
  scan_response_ = data;
}

void LeAdvertiser::EnableExtended(std::chrono::milliseconds duration_ms) {
  enabled_ = true;
  extended_ = true;
  num_events_ = 0;

  chrono::duration adv_direct_ind_timeout = 1280ms;        // 1.28s
  chrono::duration adv_direct_ind_interval_low = 10000us;  // 10ms
  chrono::duration adv_direct_ind_interval_high = 3750us;  // 3.75ms
  chrono::duration duration = duration_ms;
  chrono::time_point now = std::chrono::steady_clock::now();

  bluetooth::hci::Address resolvable_address = get_address_();
  switch (own_address_type_) {
    case bluetooth::hci::OwnAddressType::PUBLIC_DEVICE_ADDRESS:
      address_ = public_address_;
      break;
    case bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS:
      address_ = AddressWithType(address_.GetAddress(),
                                 AddressType::RANDOM_DEVICE_ADDRESS);
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS:
      if (resolvable_address != Address::kEmpty) {
        address_ = AddressWithType(resolvable_address,
                                   AddressType::RANDOM_DEVICE_ADDRESS);
      } else {
        address_ = public_address_;
      }
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
      if (resolvable_address != Address::kEmpty) {
        address_ = AddressWithType(resolvable_address,
                                   AddressType::RANDOM_DEVICE_ADDRESS);
      } else {
        address_ = AddressWithType(address_.GetAddress(),
                                   AddressType::RANDOM_DEVICE_ADDRESS);
      }
      break;
  }

  switch (type_) {
    // [Vol 6] Part B. 4.4.2.4.3 High duty cycle connectable directed
    // advertising
    case AdvertisingType::ADV_DIRECT_IND_HIGH:
      duration = duration == 0ms ? adv_direct_ind_timeout
                                 : std::min(duration, adv_direct_ind_timeout);
      interval_ = adv_direct_ind_interval_high;
      break;

    // [Vol 6] Part B. 4.4.2.4.2 Low duty cycle connectable directed advertising
    case AdvertisingType::ADV_DIRECT_IND_LOW:
      interval_ = adv_direct_ind_interval_low;
      break;

    // duration set to parameter,
    // interval set by Initialize().
    default:
      break;
  }

  last_le_advertisement_ = now - interval_;
  ending_time_ = now + duration;
  limited_ = duration != 0ms;

  LOG_INFO("%s -> %s type = %hhx ad length %zu, scan length %zu",
           address_.ToString().c_str(), peer_address_.ToString().c_str(), type_,
           advertisement_.size(), scan_response_.size());
}

void LeAdvertiser::Disable() { enabled_ = false; }
bool LeAdvertiser::IsEnabled() const { return enabled_; }
bool LeAdvertiser::IsExtended() const { return extended_; }

bool LeAdvertiser::IsConnectable() const {
  return type_ != AdvertisingType::ADV_NONCONN_IND &&
         type_ != AdvertisingType::ADV_SCAN_IND;
}

uint8_t LeAdvertiser::GetNumAdvertisingEvents() const { return num_events_; }

std::unique_ptr<bluetooth::hci::EventBuilder> LeAdvertiser::GetEvent(
    std::chrono::steady_clock::time_point now) {
  // Advertiser disabled.
  if (!enabled_) {
    return nullptr;
  }

  // [Vol 4] Part E 7.8.9   LE Set Advertising Enable command
  // [Vol 4] Part E 7.8.56  LE Set Extended Advertising Enable command
  if (type_ == AdvertisingType::ADV_DIRECT_IND_HIGH && now >= ending_time_ &&
      limited_) {
    LOG_INFO("Directed Advertising Timeout");
    enabled_ = false;
    return bluetooth::hci::LeConnectionCompleteBuilder::Create(
        ErrorCode::ADVERTISING_TIMEOUT, 0, bluetooth::hci::Role::CENTRAL,
        bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS,
        bluetooth::hci::Address(), 0, 0, 0,
        bluetooth::hci::ClockAccuracy::PPM_500);
  }

  // [Vol 4] Part E 7.8.56  LE Set Extended Advertising Enable command
  if (extended_ && now >= ending_time_ && limited_) {
    LOG_INFO("Extended Advertising Timeout");
    enabled_ = false;
    return bluetooth::hci::LeAdvertisingSetTerminatedBuilder::Create(
        ErrorCode::SUCCESS, advertising_handle_, 0, num_events_);
  }

  return nullptr;
}

std::unique_ptr<model::packets::LinkLayerPacketBuilder>
LeAdvertiser::GetAdvertisement(std::chrono::steady_clock::time_point now) {
  if (!enabled_) {
    return nullptr;
  }

  if (now - last_le_advertisement_ < interval_) {
    return nullptr;
  }

  model::packets::LegacyAdvertisingType advertising_type;
  switch (type_) {
    case AdvertisingType::ADV_IND:
      advertising_type = model::packets::LegacyAdvertisingType::ADV_IND;
      break;
    case AdvertisingType::ADV_DIRECT_IND_HIGH:
    case AdvertisingType::ADV_DIRECT_IND_LOW:
      advertising_type = model::packets::LegacyAdvertisingType::ADV_DIRECT_IND;
      break;
    case AdvertisingType::ADV_SCAN_IND:
      advertising_type = model::packets::LegacyAdvertisingType::ADV_SCAN_IND;
      break;
    case AdvertisingType::ADV_NONCONN_IND:
      advertising_type = model::packets::LegacyAdvertisingType::ADV_NONCONN_IND;
      break;
  }

  last_le_advertisement_ = now;
  num_events_ += (num_events_ < 255 ? 1 : 0);
  if (tx_power_ == kTxPowerUnavailable) {
    return model::packets::LeLegacyAdvertisingPduBuilder::Create(
        address_.GetAddress(), peer_address_.GetAddress(),
        static_cast<model::packets::AddressType>(address_.GetAddressType()),
        static_cast<model::packets::AddressType>(
            peer_address_.GetAddressType()),
        advertising_type, advertisement_);
  } else {
    uint8_t tx_power_jittered = 2 + tx_power_ - (num_events_ & 0x03);
    return model::packets::RssiWrapperBuilder::Create(
        address_.GetAddress(), peer_address_.GetAddress(), tx_power_jittered,
        model::packets::LeLegacyAdvertisingPduBuilder::Create(
            address_.GetAddress(), peer_address_.GetAddress(),
            static_cast<model::packets::AddressType>(address_.GetAddressType()),
            static_cast<model::packets::AddressType>(
                peer_address_.GetAddressType()),
            advertising_type, advertisement_));
  }
}

std::unique_ptr<model::packets::LinkLayerPacketBuilder>
LeAdvertiser::GetScanResponse(bluetooth::hci::AddressWithType scanned,
                              bluetooth::hci::AddressWithType scanner,
                              bool scanner_in_filter_accept_list) {
  (void)scanner;
  if (scanned != address_ || !enabled_) {
    return nullptr;
  }

  switch (filter_policy_) {
    case bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES:
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_CONNECT:
      break;
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN:
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN_AND_CONNECT:
      if (!scanner_in_filter_accept_list) {
        return nullptr;
      }
      break;
  }

  if (tx_power_ == kTxPowerUnavailable) {
    return model::packets::LeScanResponseBuilder::Create(
        address_.GetAddress(), peer_address_.GetAddress(),
        static_cast<model::packets::AddressType>(address_.GetAddressType()),
        scan_response_);
  } else {
    uint8_t tx_power_jittered = 2 + tx_power_ - (num_events_ & 0x03);
    return model::packets::RssiWrapperBuilder::Create(
        address_.GetAddress(), peer_address_.GetAddress(), tx_power_jittered,
        model::packets::LeScanResponseBuilder::Create(
            address_.GetAddress(), peer_address_.GetAddress(),
            static_cast<model::packets::AddressType>(address_.GetAddressType()),
            scan_response_));
  }
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

    // Note: HCI_LE_Connection_Complete is not sent if the
    // HCI_LE_Enhanced_Connection_Complete event (see Section 7.7.65.10)
    // is unmasked.
    if (IsLeEventUnmasked(SubeventCode::ENHANCED_CONNECTION_COMPLETE)) {
      send_event_(bluetooth::hci::LeEnhancedConnectionCompleteBuilder::Create(
          ErrorCode::ADVERTISING_TIMEOUT, 0, Role::PERIPHERAL,
          AddressType::PUBLIC_DEVICE_ADDRESS, Address(), Address(), Address(),
          0, 0, 0, ClockAccuracy::PPM_500));
    } else if (IsLeEventUnmasked(SubeventCode::CONNECTION_COMPLETE)) {
      send_event_(bluetooth::hci::LeConnectionCompleteBuilder::Create(
          ErrorCode::ADVERTISING_TIMEOUT, 0, Role::PERIPHERAL,
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
    switch (legacy_advertiser_.advertising_type) {
      case AdvertisingType::ADV_IND:
        type = model::packets::LegacyAdvertisingType::ADV_IND;
        break;
      case AdvertisingType::ADV_DIRECT_IND_HIGH:
      case AdvertisingType::ADV_DIRECT_IND_LOW:
        type = model::packets::LegacyAdvertisingType::ADV_DIRECT_IND;
        break;
      case AdvertisingType::ADV_SCAN_IND:
        type = model::packets::LegacyAdvertisingType::ADV_SCAN_IND;
        break;
      case AdvertisingType::ADV_NONCONN_IND:
        type = model::packets::LegacyAdvertisingType::ADV_NONCONN_IND;
        break;
    }

    SendLeLinkLayerPacket(model::packets::LeLegacyAdvertisingPduBuilder::Create(
        legacy_advertiser_.advertising_address.GetAddress(),
        legacy_advertiser_.target_address.GetAddress(),
        static_cast<model::packets::AddressType>(
            legacy_advertiser_.advertising_address.GetAddressType()),
        static_cast<model::packets::AddressType>(
            legacy_advertiser_.target_address.GetAddressType()),
        type, legacy_advertiser_.advertising_data));
  }

  // Extended Advertising Timeouts

  for (auto& advertiser : advertisers_) {
    auto event = advertiser.GetEvent(now);
    if (event != nullptr) {
      send_event_(std::move(event));
    }

    auto advertisement = advertiser.GetAdvertisement(now);
    if (advertisement != nullptr) {
      SendLeLinkLayerPacket(std::move(advertisement));
    }
  }
}

}  // namespace rootcanal
