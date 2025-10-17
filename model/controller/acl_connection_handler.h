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
#include "model/controller/connection_handle.h"
#include "model/controller/le_acl_connection.h"
#include "model/controller/sco_connection.h"
#include "packets/hci_packets.h"

namespace rootcanal {

class AclConnectionHandler {
public:
  AclConnectionHandler() = default;
  AclConnectionHandler& operator=(AclConnectionHandler const&) = delete;
  virtual ~AclConnectionHandler() = default;

  using TaskId = uint32_t;

  // Reset the connection manager state, stopping any pending
  // SCO connections.
  void Reset(std::function<void(TaskId)> stopStream);

  bool HasPendingScoConnection(bluetooth::hci::Address addr) const;
  ScoState GetScoConnectionState(bluetooth::hci::Address addr) const;
  bool IsLegacyScoConnection(bluetooth::hci::Address addr) const;
  void CreateScoConnection(bluetooth::hci::Address addr, ScoConnectionParameters const& parameters,
                           ScoState state, ScoDatapath datapath, bool legacy = false);
  void CancelPendingScoConnection(bluetooth::hci::Address addr);
  bool AcceptPendingScoConnection(bluetooth::hci::Address addr, ScoLinkParameters const& parameters,
                                  std::function<TaskId()> startStream);
  bool AcceptPendingScoConnection(bluetooth::hci::Address addr,
                                  ScoConnectionParameters const& parameters,
                                  std::function<TaskId()> startStream);
  ScoConnectionParameters GetScoConnectionParameters(bluetooth::hci::Address addr) const;
  ScoLinkParameters GetScoLinkParameters(bluetooth::hci::Address addr) const;

  uint16_t CreateConnection(bluetooth::hci::Address addr, bluetooth::hci::Address own_addr);
  uint16_t CreateLeConnection(bluetooth::hci::AddressWithType addr,
                              bluetooth::hci::AddressWithType resolved_addr,
                              bluetooth::hci::AddressWithType own_addr, bluetooth::hci::Role role,
                              LeAclConnectionParameters connection_parameters);

  bool Disconnect(uint16_t handle, std::function<void(TaskId)> stopStream);

  bool HasAclHandle(uint16_t handle) const;
  bool HasLeAclHandle(uint16_t handle) const;
  bool HasScoHandle(uint16_t handle) const;

  // Return the connection handle for a classic ACL connection only.
  // \p bd_addr is the peer address.
  std::optional<uint16_t> GetAclConnectionHandle(bluetooth::hci::Address bd_addr) const;

  // Return the connection handle for a LE ACL connection identified with
  // local and remote addresses.
  std::optional<uint16_t> GetLeAclConnectionHandle(bluetooth::hci::Address local_address,
                                                   bluetooth::hci::Address remote_address) const;

  // Return the connection handle for a classic SCO connection identified
  // with the peer address \p bd_addr.
  std::optional<uint16_t> GetScoConnectionHandle(bluetooth::hci::Address bd_addr) const;

  bluetooth::hci::Address GetScoAddress(uint16_t handle) const;

  // Return the AclConnection for the selected connection handle, asserts
  // if the handle is not currently used.
  AclConnection& GetAclConnection(uint16_t handle);

  // Return the AclConnection for the selected connection handle, asserts
  // if the handle is not currently used.
  LeAclConnection& GetLeAclConnection(uint16_t handle);

  std::vector<uint16_t> GetScoHandles() const;
  std::vector<uint16_t> GetAclHandles() const;
  std::vector<uint16_t> GetLeAclHandles() const;

private:
  std::unordered_map<uint16_t, AclConnection> acl_connections_;
  std::unordered_map<uint16_t, LeAclConnection> le_acl_connections_;
  std::unordered_map<uint16_t, ScoConnection> sco_connections_;

  uint16_t last_acl_handle_{ConnectionHandle::kAclRangeStart};
  uint16_t last_sco_handle_{ConnectionHandle::kScoRangeStart};
  uint16_t last_le_acl_handle_{ConnectionHandle::kLeAclRangeStart};
};

}  // namespace rootcanal
