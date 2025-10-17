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

#include "model/controller/acl_connection_handler.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include "hci/address.h"
#include "hci/address_with_type.h"
#include "log.h"
#include "model/controller/acl_connection.h"
#include "model/controller/le_acl_connection.h"
#include "model/controller/sco_connection.h"
#include "packets/hci_packets.h"

namespace rootcanal {

using ::bluetooth::hci::Address;
using ::bluetooth::hci::AddressWithType;

template <typename C>
static uint16_t GetUnusedHandle(std::unordered_map<uint16_t, C> const& connections,
                                uint16_t range_start, uint16_t range_end, uint16_t& last) {
  while (connections.find(last) != connections.end()) {
    if (++last > range_end) {
      last = range_start;
    }
  }

  uint16_t unused_handle = last;
  if (++last > range_end) {
    last = range_start;
  }

  return unused_handle;
}

void AclConnectionHandler::Reset(std::function<void(TaskId)> stopStream) {
  // Leave no dangling periodic task.
  for (auto& [_, sco_connection] : sco_connections_) {
    sco_connection.StopStream(stopStream);
  }

  sco_connections_.clear();
  acl_connections_.clear();
  le_acl_connections_.clear();

  last_acl_handle_ = ConnectionHandle::kAclRangeStart;
  last_sco_handle_ = ConnectionHandle::kScoRangeStart;
  last_le_acl_handle_ = ConnectionHandle::kLeAclRangeStart;
}

bool AclConnectionHandler::HasAclHandle(uint16_t handle) const {
  return acl_connections_.count(handle) != 0;
}

bool AclConnectionHandler::HasLeAclHandle(uint16_t handle) const {
  return le_acl_connections_.count(handle) != 0;
}

bool AclConnectionHandler::HasScoHandle(uint16_t handle) const {
  return sco_connections_.count(handle) != 0;
}

uint16_t AclConnectionHandler::CreateConnection(Address addr, Address own_addr) {
  uint16_t handle = GetUnusedHandle(acl_connections_, ConnectionHandle::kAclRangeStart,
                                    ConnectionHandle::kAclRangeEnd, last_acl_handle_);
  acl_connections_.emplace(handle,
                           AclConnection{handle, addr, own_addr, bluetooth::hci::Role::CENTRAL});
  return handle;
}

uint16_t AclConnectionHandler::CreateLeConnection(AddressWithType addr,
                                                  AddressWithType resolved_peer,
                                                  AddressWithType own_addr,
                                                  bluetooth::hci::Role role,
                                                  LeAclConnectionParameters connection_parameters) {
  uint16_t handle = GetUnusedHandle(le_acl_connections_, ConnectionHandle::kLeAclRangeStart,
                                    ConnectionHandle::kLeAclRangeEnd, last_le_acl_handle_);
  le_acl_connections_.emplace(handle, LeAclConnection{handle, addr, own_addr, resolved_peer, role,
                                                      connection_parameters});
  return handle;
}

bool AclConnectionHandler::Disconnect(uint16_t handle, std::function<void(TaskId)> stopStream) {
  if (HasScoHandle(handle)) {
    sco_connections_.at(handle).StopStream(std::move(stopStream));
    sco_connections_.erase(handle);
    return true;
  }
  if (HasAclHandle(handle)) {
    // It is the responsibility of the caller to remove SCO connections
    // with connected peer first.
    auto sco_handle = GetScoConnectionHandle(acl_connections_.at(handle).address);
    ASSERT(!sco_handle.has_value());
    acl_connections_.erase(handle);
    return true;
  }
  if (HasLeAclHandle(handle)) {
    le_acl_connections_.erase(handle);
    return true;
  }
  return false;
}

std::optional<uint16_t> AclConnectionHandler::GetAclConnectionHandle(
        bluetooth::hci::Address bd_addr) const {
  for (auto const& [handle, connection] : acl_connections_) {
    if (connection.address == bd_addr) {
      return handle;
    }
  }
  return {};
}

std::optional<uint16_t> AclConnectionHandler::GetLeAclConnectionHandle(
        bluetooth::hci::Address local_address, bluetooth::hci::Address remote_address) const {
  for (auto const& [handle, connection] : le_acl_connections_) {
    if (connection.address.GetAddress() == remote_address &&
        connection.own_address.GetAddress() == local_address) {
      return handle;
    }
  }
  return {};
}

std::optional<uint16_t> AclConnectionHandler::GetScoConnectionHandle(
        bluetooth::hci::Address addr) const {
  for (auto const& [handle, connection] : sco_connections_) {
    if (connection.GetAddress() == addr) {
      return handle;
    }
  }
  return {};
}

AclConnection& AclConnectionHandler::GetAclConnection(uint16_t handle) {
  ASSERT_LOG(HasAclHandle(handle), "Unknown handle %d", handle);
  return acl_connections_.at(handle);
}

LeAclConnection& AclConnectionHandler::GetLeAclConnection(uint16_t handle) {
  ASSERT_LOG(HasLeAclHandle(handle), "Unknown handle %d", handle);
  return le_acl_connections_.at(handle);
}

Address AclConnectionHandler::GetScoAddress(uint16_t handle) const {
  ASSERT_LOG(HasScoHandle(handle), "Unknown SCO handle %hd", handle);
  return sco_connections_.at(handle).GetAddress();
}

void AclConnectionHandler::CreateScoConnection(bluetooth::hci::Address addr,
                                               ScoConnectionParameters const& parameters,
                                               ScoState state, ScoDatapath datapath, bool legacy) {
  uint16_t handle = GetUnusedHandle(sco_connections_, ConnectionHandle::kScoRangeStart,
                                    ConnectionHandle::kScoRangeEnd, last_sco_handle_);
  sco_connections_.emplace(handle, ScoConnection(addr, parameters, state, datapath, legacy));
}

bool AclConnectionHandler::HasPendingScoConnection(bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      ScoState state = std::get<ScoConnection>(pair).GetState();
      return state == SCO_STATE_PENDING || state == SCO_STATE_SENT_ESCO_CONNECTION_REQUEST ||
             state == SCO_STATE_SENT_SCO_CONNECTION_REQUEST;
    }
  }
  return false;
}

ScoState AclConnectionHandler::GetScoConnectionState(bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      return std::get<ScoConnection>(pair).GetState();
    }
  }
  return SCO_STATE_CLOSED;
}

bool AclConnectionHandler::IsLegacyScoConnection(bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      return std::get<ScoConnection>(pair).IsLegacy();
    }
  }
  return false;
}

void AclConnectionHandler::CancelPendingScoConnection(bluetooth::hci::Address addr) {
  for (auto it = sco_connections_.begin(); it != sco_connections_.end(); it++) {
    if (std::get<ScoConnection>(*it).GetAddress() == addr) {
      sco_connections_.erase(it);
      return;
    }
  }
}

bool AclConnectionHandler::AcceptPendingScoConnection(bluetooth::hci::Address addr,
                                                      ScoLinkParameters const& parameters,
                                                      std::function<TaskId()> startStream) {
  for (auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      std::get<ScoConnection>(pair).SetLinkParameters(parameters);
      std::get<ScoConnection>(pair).SetState(ScoState::SCO_STATE_OPENED);
      std::get<ScoConnection>(pair).StartStream(std::move(startStream));
      return true;
    }
  }
  return false;
}

bool AclConnectionHandler::AcceptPendingScoConnection(bluetooth::hci::Address addr,
                                                      ScoConnectionParameters const& parameters,
                                                      std::function<TaskId()> startStream) {
  for (auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      bool ok = std::get<ScoConnection>(pair).NegotiateLinkParameters(parameters);
      std::get<ScoConnection>(pair).SetState(ok ? ScoState::SCO_STATE_OPENED
                                                : ScoState::SCO_STATE_CLOSED);
      if (ok) {
        std::get<ScoConnection>(pair).StartStream(std::move(startStream));
      }
      return ok;
    }
  }
  return false;
}

ScoConnectionParameters AclConnectionHandler::GetScoConnectionParameters(
        bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      return std::get<ScoConnection>(pair).GetConnectionParameters();
    }
  }
  return {};
}

ScoLinkParameters AclConnectionHandler::GetScoLinkParameters(bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      return std::get<ScoConnection>(pair).GetLinkParameters();
    }
  }
  return {};
}

std::vector<uint16_t> AclConnectionHandler::GetScoHandles() const {
  std::vector<uint16_t> handles;
  for (auto const& [handle, _] : sco_connections_) {
    handles.push_back(handle);
  }
  return handles;
}

std::vector<uint16_t> AclConnectionHandler::GetAclHandles() const {
  std::vector<uint16_t> handles;
  for (auto const& [handle, _] : acl_connections_) {
    handles.push_back(handle);
  }
  return handles;
}

std::vector<uint16_t> AclConnectionHandler::GetLeAclHandles() const {
  std::vector<uint16_t> handles;
  for (auto const& [handle, _] : le_acl_connections_) {
    handles.push_back(handle);
  }
  return handles;
}

}  // namespace rootcanal
