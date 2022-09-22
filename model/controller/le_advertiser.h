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
#include <memory>
#include <optional>
#include <ratio>

#include "hci/address_with_type.h"
#include "hci/hci_packets.h"
#include "packets/link_layer_packets.h"

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

  bool advertising_enable{false};
  AddressWithType advertising_address{Address::kEmpty,
                                      AddressType::PUBLIC_DEVICE_ADDRESS};
  AddressWithType target_address{Address::kEmpty,
                                 AddressType::PUBLIC_DEVICE_ADDRESS};
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

  // Time keeping.
  std::chrono::steady_clock::time_point next_event{};
  std::optional<std::chrono::steady_clock::time_point> timeout{};

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

// Track a single extended advertising instance
class LeAdvertiser {
 public:
  LeAdvertiser() = default;
  virtual ~LeAdvertiser() = default;

  void InitializeExtended(
      unsigned advertising_handle, bluetooth::hci::OwnAddressType address_type,
      bluetooth::hci::AddressWithType public_address,
      bluetooth::hci::AddressWithType peer_address,
      bluetooth::hci::AdvertisingFilterPolicy filter_policy,
      bluetooth::hci::AdvertisingType type,
      std::chrono::steady_clock::duration interval, uint8_t tx_power,
      const std::function<bluetooth::hci::Address()>& get_address);

  void SetAddress(bluetooth::hci::Address address);

  void SetData(const std::vector<uint8_t>& data);

  void SetScanResponse(const std::vector<uint8_t>& data);

  // Generate LE Connection Complete or LE Extended Advertising Set Terminated
  // events at the end of the advertising period. The advertiser is
  // automatically disabled.
  std::unique_ptr<bluetooth::hci::EventBuilder> GetEvent(
      std::chrono::steady_clock::time_point);

  std::unique_ptr<model::packets::LinkLayerPacketBuilder> GetAdvertisement(
      std::chrono::steady_clock::time_point);

  std::unique_ptr<model::packets::LinkLayerPacketBuilder> GetScanResponse(
      bluetooth::hci::AddressWithType scanned_address,
      bluetooth::hci::AddressWithType scanner_address,
      bool scanner_in_filter_accept_list);

  void Clear();
  void Disable();
  void EnableExtended(std::chrono::milliseconds duration);

  bluetooth::hci::AdvertisingFilterPolicy GetAdvertisingFilterPolicy() const {
    return filter_policy_;
  }

  bool IsEnabled() const;
  bool IsExtended() const;
  bool IsConnectable() const;

  uint8_t GetNumAdvertisingEvents() const;
  bluetooth::hci::AddressWithType GetAddress() const;

 private:
  std::function<bluetooth::hci::Address()> default_get_address_ = []() {
    return bluetooth::hci::Address::kEmpty;
  };
  std::function<bluetooth::hci::Address()>& get_address_ = default_get_address_;
  bluetooth::hci::AddressWithType address_{};
  bluetooth::hci::AddressWithType public_address_{};
  bluetooth::hci::OwnAddressType own_address_type_;
  bluetooth::hci::AddressWithType
      peer_address_{};  // For directed advertisements
  bluetooth::hci::AdvertisingFilterPolicy filter_policy_{};
  bluetooth::hci::AdvertisingType type_{};
  std::vector<uint8_t> advertisement_;
  std::vector<uint8_t> scan_response_;
  std::chrono::steady_clock::duration interval_{};
  std::chrono::steady_clock::time_point ending_time_{};
  std::chrono::steady_clock::time_point last_le_advertisement_{};
  static constexpr uint8_t kTxPowerUnavailable = 0x7f;
  uint8_t tx_power_{kTxPowerUnavailable};
  uint8_t num_events_{0};
  bool extended_{false};
  bool enabled_{false};
  bool limited_{false};  // Set if the advertising set has a timeout.
  unsigned advertising_handle_{0};
};

}  // namespace rootcanal
