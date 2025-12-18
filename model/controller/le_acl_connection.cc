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

#include "model/controller/le_acl_connection.h"

#include <chrono>
#include <cstdint>

#include "packets/hci_packets.h"

namespace rootcanal {

LeAclConnection::LeAclConnection(uint16_t handle, AddressWithType address,
                                 AddressWithType own_address, AddressWithType resolved_address,
                                 bluetooth::hci::Role role,
                                 LeAclConnectionParameters connection_parameters,
                                 LeAclSubrateParameters subrate_parameters)
    : handle(handle),
      address(address),
      own_address(own_address),
      resolved_address(resolved_address),
      role(role),
      parameters(connection_parameters),
      subrate_parameters(subrate_parameters),
      last_packet_timestamp_(std::chrono::steady_clock::now()),
      timeout_(std::chrono::seconds(3)) {}

void LeAclConnection::Encrypt() { encrypted_ = true; }

bool LeAclConnection::IsEncrypted() const { return encrypted_; }

int8_t LeAclConnection::GetRssi() const { return rssi_; }

void LeAclConnection::SetRssi(int8_t rssi) { rssi_ = rssi; }

void LeAclConnection::ResetLinkTimer() {
  last_packet_timestamp_ = std::chrono::steady_clock::now();
}

std::chrono::steady_clock::duration LeAclConnection::TimeUntilNearExpiring() const {
  return (last_packet_timestamp_ + timeout_ / 2) - std::chrono::steady_clock::now();
}

bool LeAclConnection::IsNearExpiring() const {
  return TimeUntilNearExpiring() < std::chrono::steady_clock::duration::zero();
}

std::chrono::steady_clock::duration LeAclConnection::TimeUntilExpired() const {
  return (last_packet_timestamp_ + timeout_) - std::chrono::steady_clock::now();
}

bool LeAclConnection::HasExpired() const {
  return TimeUntilExpired() < std::chrono::steady_clock::duration::zero();
}

}  // namespace rootcanal
