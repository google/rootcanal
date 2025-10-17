/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include "hci/address.h"
#include "packets/hci_packets.h"

namespace rootcanal {

using bluetooth::hci::Address;

enum AclConnectionState {
  kActiveMode,
  kHoldMode,
  kSniffMode,
};

// Model the BR/EDR connection of a device to the controller.
class AclConnection final {
public:
  const uint16_t handle;
  const Address address;
  const Address own_address;

  AclConnection(uint16_t handle, Address address, Address own_address, bluetooth::hci::Role role);
  ~AclConnection() = default;

  void Encrypt();
  bool IsEncrypted() const;

  void SetLinkPolicySettings(uint16_t settings);
  uint16_t GetLinkPolicySettings() const { return link_policy_settings_; }
  bool IsRoleSwitchEnabled() const { return (link_policy_settings_ & 0x1) != 0; }
  bool IsHoldModeEnabled() const { return (link_policy_settings_ & 0x2) != 0; }
  bool IsSniffModeEnabled() const { return (link_policy_settings_ & 0x4) != 0; }

  AclConnectionState GetMode() const { return state_; }

  bluetooth::hci::Role GetRole() const;
  void SetRole(bluetooth::hci::Role role);

  int8_t GetRssi() const;
  void SetRssi(int8_t rssi);

  std::chrono::steady_clock::duration TimeUntilNearExpiring() const;
  std::chrono::steady_clock::duration TimeUntilExpired() const;
  void ResetLinkTimer();
  bool IsNearExpiring() const;
  bool HasExpired() const;

private:
  // Reports the RSSI measured for the last packet received on
  // this connection.
  int8_t rssi_{0};

  // State variables
  bool encrypted_{false};
  uint16_t link_policy_settings_{0};
  AclConnectionState state_{kActiveMode};
  bluetooth::hci::Role role_{bluetooth::hci::Role::CENTRAL};
  std::chrono::steady_clock::time_point last_packet_timestamp_;
  std::chrono::steady_clock::duration timeout_;
};

}  // namespace rootcanal
