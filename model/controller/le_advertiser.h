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

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <ratio>
#include <vector>

#include "hci/address.h"
#include "hci/address_with_type.h"
#include "packets/hci_packets.h"

namespace rootcanal {

// Duration type for slots (increments of 625us).
using slots =
    std::chrono::duration<unsigned long long, std::ratio<625, 1000000>>;

// User defined literal for slots, e.g. `0x800_slots`
slots operator"" _slots(unsigned long long count);

using namespace bluetooth::hci;

// Advertising interface common to legacy and extended advertisers.
class Advertiser {
 public:
  Advertiser() = default;
  ~Advertiser() = default;

  bool IsEnabled() const { return advertising_enable; }
  void Disable() { advertising_enable = false; }

  AddressWithType GetAdvertisingAddress() const { return advertising_address; }
  AddressWithType GetTargetAddress() const { return target_address; }

  // HCI properties.
  bool advertising_enable{false};
  AddressWithType advertising_address{Address::kEmpty,
                                      AddressType::PUBLIC_DEVICE_ADDRESS};
  AddressWithType target_address{Address::kEmpty,
                                 AddressType::PUBLIC_DEVICE_ADDRESS};

  // Time keeping.
  std::chrono::steady_clock::time_point next_event{};
  std::optional<std::chrono::steady_clock::time_point> timeout{};
};

// Implement the unique legacy advertising instance.
// For extended advertising check the ExtendedAdvertiser class.
class LegacyAdvertiser : public Advertiser {
 public:
  LegacyAdvertiser() = default;
  ~LegacyAdvertiser() = default;

  bool IsScannable() const {
    return advertising_type != AdvertisingType::ADV_NONCONN_IND &&
           advertising_type != AdvertisingType::ADV_DIRECT_IND_HIGH &&
           advertising_type != AdvertisingType::ADV_DIRECT_IND_LOW;
  }

  bool IsConnectable() const {
    return advertising_type != AdvertisingType::ADV_NONCONN_IND &&
           advertising_type != AdvertisingType::ADV_SCAN_IND;
  }

  bool IsDirected() const {
    return advertising_type == AdvertisingType::ADV_DIRECT_IND_HIGH ||
           advertising_type == AdvertisingType::ADV_DIRECT_IND_LOW;
  }

  // Host configuration parameters. Gather the configuration from the
  // legacy advertising HCI commands. The initial configuration
  // matches the default values of the parameters of the HCI command
  // LE Set Advertising Parameters.
  slots advertising_interval{0x0800};
  AdvertisingType advertising_type{AdvertisingType::ADV_IND};
  OwnAddressType own_address_type{OwnAddressType::PUBLIC_DEVICE_ADDRESS};
  PeerAddressType peer_address_type{
      PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS};
  Address peer_address{};
  uint8_t advertising_channel_map{0x07};
  AdvertisingFilterPolicy advertising_filter_policy{
      AdvertisingFilterPolicy::ALL_DEVICES};
  std::vector<uint8_t> advertising_data{};
  std::vector<uint8_t> scan_response_data{};
};

// Implement a single extended advertising set.
// The configuration is set by the extended advertising commands;
// for the legacy advertiser check the LegacyAdvertiser class.
class ExtendedAdvertiser : public Advertiser {
 public:
  ExtendedAdvertiser(uint8_t advertising_handle = 0)
      : advertising_handle(advertising_handle) {}
  ~ExtendedAdvertiser() = default;

  void Enable() {
    advertising_enable = true;
    periodic_advertising_enable_latch = periodic_advertising_enable;
    next_event = std::chrono::steady_clock::now();
  }

  void EnablePeriodic() {
    periodic_advertising_enable = true;
    periodic_advertising_enable_latch = advertising_enable;
    next_periodic_event = std::chrono::steady_clock::now();
  }

  void DisablePeriodic() {
    periodic_advertising_enable = false;
    periodic_advertising_enable_latch = false;
  }

  bool IsPeriodicEnabled() const { return periodic_advertising_enable_latch; }
  bool IsScannable() const { return advertising_event_properties.scannable_; }

  bool IsConnectable() const {
    return advertising_event_properties.connectable_;
  }

  bool IsDirected() const { return advertising_event_properties.directed_; }

  // Host configuration parameters. Gather the configuration from the
  // extended advertising HCI commands.
  uint8_t advertising_handle;
  AdvertisingEventProperties advertising_event_properties{};
  slots primary_advertising_interval{};
  uint8_t primary_advertising_channel_map{};
  OwnAddressType own_address_type{};
  PeerAddressType peer_address_type{};
  Address peer_address{};
  std::optional<Address> random_address{};
  AdvertisingFilterPolicy advertising_filter_policy{};
  uint8_t advertising_tx_power{};
  PrimaryPhyType primary_advertising_phy{};
  uint8_t secondary_max_skip{};
  SecondaryPhyType secondary_advertising_phy{};
  uint8_t advertising_sid{};
  bool scan_request_notification_enable{};
  std::vector<uint8_t> advertising_data{};
  std::vector<uint8_t> scan_response_data{};
  bool partial_advertising_data{false};
  bool partial_scan_response_data{false};

  // Periodic advertising configuration.
  // Note: the enable flag has a latch because of the semantic describe in the
  // specification:
  //
  // If the advertising set is not currently enabled, the periodic advertising
  // is not started until the advertising set is enabled. Once the advertising
  // set has been enabled, the Controller shall continue periodic advertising
  // until the Host issues an HCI_LE_Set_Periodic_Advertising_Enable command
  // with bit 0 of Enable set to 0 (periodic advertising is disabled).
  // Disabling the advertising set has no effect on the periodic advertising
  // once the advertising set has been enabled.
  //
  // Thus the enable latch is set when the advertising set is enabled and
  // periodic advertising is enabled, and cleared when periodic advertising
  // gets disabled.
  bool periodic_advertising_enable{false};
  bool periodic_advertising_enable_latch{false};
  slots periodic_advertising_interval{};
  std::vector<uint8_t> periodic_advertising_data{};
  bool partial_periodic_advertising_data{false};

  // Time keeping for periodic advertising.
  std::chrono::steady_clock::time_point next_periodic_event{};

  // Enabled state.
  uint8_t max_extended_advertising_events{0};
  uint8_t num_completed_extended_advertising_events{0};

  // Not implemented at the moment.
  bool constant_tone_extensions{false};

  // Compute the maximum advertising data payload size for the selected
  // advertising event properties. The advertising data is not present if
  // 0 is returned.
  static uint16_t GetMaxAdvertisingDataLength(
      const AdvertisingEventProperties& properties);

  // Compute the maximum scan response data payload size for the selected
  // advertising event properties. The scan response data is not present if
  // 0 is returned.
  static uint16_t GetMaxScanResponseDataLength(
      const AdvertisingEventProperties& properties);

  // Reconstitute the raw Advertising_Event_Properties bitmask.
  static uint16_t GetRawAdvertisingEventProperties(
      const AdvertisingEventProperties& properties);

  // Compute the maximum periodic advertising data payload size for the
  // selected periodic advertising interval.
  static uint16_t GetMaxPeriodicAdvertisingDataLength(
      slots periodic_advertising_interval);
};

}  // namespace rootcanal
