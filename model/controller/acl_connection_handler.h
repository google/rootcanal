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

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>
#include <vector>

#include "hci/address.h"
#include "hci/address_with_type.h"
#include "model/controller/acl_connection.h"
#include "model/controller/sco_connection.h"
#include "packets/hci_packets.h"
#include "phy.h"

namespace rootcanal {
static constexpr uint16_t kReservedHandle = 0xF00;
static constexpr uint16_t kCisHandleRangeStart = 0xE00;
static constexpr uint16_t kCisHandleRangeEnd = 0xEFE;

class AclConnectionHandler {
 public:
  AclConnectionHandler() = default;
  virtual ~AclConnectionHandler() = default;

  using TaskId = uint32_t;

  // Reset the connection manager state, stopping any pending
  // SCO connections.
  void Reset(std::function<void(TaskId)> stopStream);

  bool CreatePendingConnection(bluetooth::hci::Address addr,
                               bool authenticate_on_connect,
                               bool allow_role_switch);
  bool HasPendingConnection(bluetooth::hci::Address addr) const;
  bool CancelPendingConnection(bluetooth::hci::Address addr);
  bool AuthenticatePendingConnection() const;

  bool HasPendingScoConnection(bluetooth::hci::Address addr) const;
  ScoState GetScoConnectionState(bluetooth::hci::Address addr) const;
  bool IsLegacyScoConnection(bluetooth::hci::Address addr) const;
  void CreateScoConnection(bluetooth::hci::Address addr,
                           ScoConnectionParameters const& parameters,
                           ScoState state, ScoDatapath datapath,
                           bool legacy = false);
  void CancelPendingScoConnection(bluetooth::hci::Address addr);
  bool AcceptPendingScoConnection(bluetooth::hci::Address addr,
                                  ScoLinkParameters const& parameters,
                                  std::function<TaskId()> startStream);
  bool AcceptPendingScoConnection(bluetooth::hci::Address addr,
                                  ScoConnectionParameters const& parameters,
                                  std::function<TaskId()> startStream);
  uint16_t GetScoHandle(bluetooth::hci::Address addr) const;
  ScoConnectionParameters GetScoConnectionParameters(
      bluetooth::hci::Address addr) const;
  ScoLinkParameters GetScoLinkParameters(bluetooth::hci::Address addr) const;

  bool CreatePendingLeConnection(bluetooth::hci::AddressWithType peer,
                                 bluetooth::hci::AddressWithType resolved_peer,
                                 bluetooth::hci::AddressWithType local_address);
  bool HasPendingLeConnection(bluetooth::hci::AddressWithType addr) const;
  bool CancelPendingLeConnection(bluetooth::hci::AddressWithType addr);

  // \p pending is true if the connection is expected to be
  // in pending state.
  uint16_t CreateConnection(bluetooth::hci::Address addr,
                            bluetooth::hci::Address own_addr,
                            bool pending = true);
  uint16_t CreateLeConnection(bluetooth::hci::AddressWithType addr,
                              bluetooth::hci::AddressWithType own_addr,
                              bluetooth::hci::Role role);
  bool Disconnect(uint16_t handle, std::function<void(TaskId)> stopStream);
  bool HasHandle(uint16_t handle) const;
  bool HasScoHandle(uint16_t handle) const;

  // Return the connection handle for a classic ACL connection only.
  // \p bd_addr is the peer address.
  std::optional<uint16_t> GetAclConnectionHandle(
      bluetooth::hci::Address bd_addr) const;

  uint16_t GetHandle(bluetooth::hci::AddressWithType addr) const;
  uint16_t GetHandleOnlyAddress(bluetooth::hci::Address addr) const;
  bluetooth::hci::AddressWithType GetAddress(uint16_t handle) const;
  std::optional<AddressWithType> GetAddressSafe(uint16_t handle) const;
  bluetooth::hci::Address GetScoAddress(uint16_t handle) const;
  bluetooth::hci::AddressWithType GetOwnAddress(uint16_t handle) const;
  bluetooth::hci::AddressWithType GetResolvedAddress(uint16_t handle) const;

  // Return the AclConnection for the selected connection handle, asserts
  // if the handle is not currently used.
  AclConnection& GetAclConnection(uint16_t handle);

  void Encrypt(uint16_t handle);
  bool IsEncrypted(uint16_t handle) const;

  void SetRssi(uint16_t handle, int8_t rssi);
  int8_t GetRssi(uint16_t handle) const;

  Phy::Type GetPhyType(uint16_t handle) const;

  uint16_t GetAclLinkPolicySettings(uint16_t handle) const;
  void SetAclLinkPolicySettings(uint16_t handle, uint16_t settings);

  bluetooth::hci::Role GetAclRole(uint16_t handle) const;
  void SetAclRole(uint16_t handle, bluetooth::hci::Role role);

  std::vector<uint16_t> GetAclHandles() const;

  void ResetLinkTimer(uint16_t handle);
  std::chrono::steady_clock::duration TimeUntilLinkNearExpiring(
      uint16_t handle) const;
  bool IsLinkNearExpiring(uint16_t handle) const;
  std::chrono::steady_clock::duration TimeUntilLinkExpired(
      uint16_t handle) const;
  bool HasLinkExpired(uint16_t handle) const;
  bool IsRoleSwitchAllowedForPendingConnection() const;

 private:
  std::unordered_map<uint16_t, AclConnection> acl_connections_;
  std::unordered_map<uint16_t, ScoConnection> sco_connections_;

  bool classic_connection_pending_{false};
  bluetooth::hci::Address pending_connection_address_{
      bluetooth::hci::Address::kEmpty};
  bool authenticate_pending_classic_connection_{false};
  bool pending_classic_connection_allow_role_switch_{false};
  bool le_connection_pending_{false};
  bluetooth::hci::AddressWithType pending_le_connection_address_{
      bluetooth::hci::Address::kEmpty,
      bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS};
  bluetooth::hci::AddressWithType pending_le_connection_own_address_{
      bluetooth::hci::Address::kEmpty,
      bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS};
  bluetooth::hci::AddressWithType pending_le_connection_resolved_address_{
      bluetooth::hci::Address::kEmpty,
      bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS};

  uint16_t GetUnusedHandle();
  uint16_t last_handle_{kReservedHandle - 2};
};

}  // namespace rootcanal
