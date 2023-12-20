/*
 * Copyright 2018 The Android Open Source Project
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

#include "model/controller/acl_connection.h"

#include <chrono>
#include <cstdint>

#include "packets/hci_packets.h"
#include "phy.h"

namespace rootcanal {
AclConnection::AclConnection(AddressWithType address,
                             AddressWithType own_address,
                             AddressWithType resolved_address,
                             Phy::Type phy_type, bluetooth::hci::Role role)
    : address_(address),
      own_address_(own_address),
      resolved_address_(resolved_address),
      type_(phy_type),
      role_(role),
      last_packet_timestamp_(std::chrono::steady_clock::now()),
      timeout_(std::chrono::seconds(3)) {}

void AclConnection::Encrypt() { encrypted_ = true; }

bool AclConnection::IsEncrypted() const { return encrypted_; }

void AclConnection::SetLinkPolicySettings(uint16_t settings) {
  link_policy_settings_ = settings;
}

bluetooth::hci::Role AclConnection::GetRole() const { return role_; }

void AclConnection::SetRole(bluetooth::hci::Role role) { role_ = role; }

int8_t AclConnection::GetRssi() const { return rssi_; }

void AclConnection::SetRssi(int8_t rssi) { rssi_ = rssi; }

void AclConnection::ResetLinkTimer() {
  last_packet_timestamp_ = std::chrono::steady_clock::now();
}

std::chrono::steady_clock::duration AclConnection::TimeUntilNearExpiring()
    const {
  return (last_packet_timestamp_ + timeout_ / 2) -
         std::chrono::steady_clock::now();
}

bool AclConnection::IsNearExpiring() const {
  return TimeUntilNearExpiring() < std::chrono::steady_clock::duration::zero();
}

std::chrono::steady_clock::duration AclConnection::TimeUntilExpired() const {
  return (last_packet_timestamp_ + timeout_) - std::chrono::steady_clock::now();
}

bool AclConnection::HasExpired() const {
  return TimeUntilExpired() < std::chrono::steady_clock::duration::zero();
}

}  // namespace rootcanal
