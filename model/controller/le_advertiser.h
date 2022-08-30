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

#include "hci/address_with_type.h"
#include "hci/hci_packets.h"
#include "packets/link_layer_packets.h"

namespace rootcanal {

// Track a single advertising instance
class LeAdvertiser {
 public:
  LeAdvertiser() = default;
  virtual ~LeAdvertiser() = default;

  void Initialize(bluetooth::hci::OwnAddressType address_type,
                  bluetooth::hci::AddressWithType public_address,
                  bluetooth::hci::AddressWithType peer_address,
                  bluetooth::hci::LeScanningFilterPolicy filter_policy,
                  model::packets::AdvertisementType type,
                  const std::vector<uint8_t>& advertisement,
                  const std::vector<uint8_t>& scan_response,
                  std::chrono::steady_clock::duration interval);

  void InitializeExtended(
      unsigned advertising_handle, bluetooth::hci::OwnAddressType address_type,
      bluetooth::hci::AddressWithType public_address,
      bluetooth::hci::AddressWithType peer_address,
      bluetooth::hci::LeScanningFilterPolicy filter_policy,
      model::packets::AdvertisementType type,
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
      bluetooth::hci::Address scanned_address,
      bluetooth::hci::Address scanner_address);

  void Clear();
  void Disable();
  void Enable();
  void EnableExtended(std::chrono::milliseconds duration);

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
  bluetooth::hci::LeScanningFilterPolicy filter_policy_{};
  model::packets::AdvertisementType type_{};
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
