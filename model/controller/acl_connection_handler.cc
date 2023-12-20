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
#include "model/controller/sco_connection.h"
#include "packets/hci_packets.h"
#include "phy.h"

namespace rootcanal {

using ::bluetooth::hci::Address;
using ::bluetooth::hci::AddressType;
using ::bluetooth::hci::AddressWithType;

void AclConnectionHandler::Reset(std::function<void(TaskId)> stopStream) {
  // Leave no dangling periodic task.
  for (auto& [_, sco_connection] : sco_connections_) {
    sco_connection.StopStream(stopStream);
  }

  sco_connections_.clear();
  acl_connections_.clear();
}

bool AclConnectionHandler::HasHandle(uint16_t handle) const {
  return acl_connections_.count(handle) != 0;
}

bool AclConnectionHandler::HasScoHandle(uint16_t handle) const {
  return sco_connections_.count(handle) != 0;
}

uint16_t AclConnectionHandler::GetUnusedHandle() {
  // Keep a reserved range of handles for CIS connections implemented
  // in the rust module.
  while (HasHandle(last_handle_) || HasScoHandle(last_handle_) ||
         (last_handle_ >= kCisHandleRangeStart &&
          last_handle_ < kCisHandleRangeEnd)) {
    last_handle_ = (last_handle_ + 1) % kReservedHandle;
  }
  uint16_t unused_handle = last_handle_;
  last_handle_ = (last_handle_ + 1) % kReservedHandle;
  return unused_handle;
}

bool AclConnectionHandler::CreatePendingConnection(Address addr,
                                                   bool authenticate_on_connect,
                                                   bool allow_role_switch) {
  if (classic_connection_pending_ || GetAclConnectionHandle(addr).has_value()) {
    return false;
  }
  classic_connection_pending_ = true;
  pending_connection_address_ = addr;
  authenticate_pending_classic_connection_ = authenticate_on_connect;
  pending_classic_connection_allow_role_switch_ = allow_role_switch;
  return true;
}

bool AclConnectionHandler::HasPendingConnection(Address addr) const {
  return classic_connection_pending_ && pending_connection_address_ == addr;
}

bool AclConnectionHandler::AuthenticatePendingConnection() const {
  return authenticate_pending_classic_connection_;
}

bool AclConnectionHandler::CancelPendingConnection(Address addr) {
  if (!classic_connection_pending_ || pending_connection_address_ != addr) {
    return false;
  }
  classic_connection_pending_ = false;
  pending_connection_address_ = Address::kEmpty;
  pending_le_connection_resolved_address_ = AddressWithType();
  return true;
}

bool AclConnectionHandler::CreatePendingLeConnection(
    AddressWithType peer, AddressWithType resolved_peer,
    AddressWithType local_address) {
  for (auto pair : acl_connections_) {
    auto connection = std::get<AclConnection>(pair);
    if (connection.GetAddress() == peer ||
        connection.GetResolvedAddress() == resolved_peer) {
      INFO("{}: {} is already connected", __func__, peer);
      if (connection.GetResolvedAddress() == resolved_peer) {
        INFO("{}: allowing a second connection with {}", __func__,
             resolved_peer);
      } else {
        return false;
      }
    }
  }
  if (le_connection_pending_) {
    INFO("{}: connection already pending", __func__);
    return false;
  }
  le_connection_pending_ = true;
  pending_le_connection_address_ = peer;
  pending_le_connection_own_address_ = local_address;
  pending_le_connection_resolved_address_ = resolved_peer;
  return true;
}

bool AclConnectionHandler::HasPendingLeConnection(AddressWithType addr) const {
  return le_connection_pending_ && pending_le_connection_address_ == addr;
}

bool AclConnectionHandler::CancelPendingLeConnection(AddressWithType addr) {
  if (!le_connection_pending_ || pending_le_connection_address_ != addr) {
    return false;
  }
  le_connection_pending_ = false;
  pending_le_connection_address_ =
      AddressWithType{Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS};
  pending_le_connection_resolved_address_ =
      AddressWithType{Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS};
  return true;
}

uint16_t AclConnectionHandler::CreateConnection(Address addr, Address own_addr,
                                                bool pending) {
  if (!pending || CancelPendingConnection(addr)) {
    uint16_t handle = GetUnusedHandle();
    acl_connections_.emplace(
        handle,
        AclConnection{
            AddressWithType{addr, AddressType::PUBLIC_DEVICE_ADDRESS},
            AddressWithType{own_addr, AddressType::PUBLIC_DEVICE_ADDRESS},
            AddressWithType(), Phy::Type::BR_EDR,
            bluetooth::hci::Role::CENTRAL});
    return handle;
  }
  return kReservedHandle;
}

uint16_t AclConnectionHandler::CreateLeConnection(AddressWithType addr,
                                                  AddressWithType own_addr,
                                                  bluetooth::hci::Role role) {
  AddressWithType resolved_peer = pending_le_connection_resolved_address_;
  if (CancelPendingLeConnection(addr)) {
    uint16_t handle = GetUnusedHandle();
    acl_connections_.emplace(handle,
                             AclConnection{addr, own_addr, resolved_peer,
                                           Phy::Type::LOW_ENERGY, role});
    return handle;
  }
  return kReservedHandle;
}

bool AclConnectionHandler::Disconnect(uint16_t handle,
                                      std::function<void(TaskId)> stopStream) {
  if (HasScoHandle(handle)) {
    sco_connections_.at(handle).StopStream(std::move(stopStream));
    sco_connections_.erase(handle);
    return true;
  }
  if (HasHandle(handle)) {
    // It is the responsibility of the caller to remove SCO connections
    // with connected peer first.
    uint16_t sco_handle = GetScoHandle(GetAddress(handle).GetAddress());
    ASSERT(!HasScoHandle(sco_handle));
    acl_connections_.erase(handle);
    return true;
  }
  return false;
}

uint16_t AclConnectionHandler::GetHandle(AddressWithType addr) const {
  for (auto pair : acl_connections_) {
    if (std::get<AclConnection>(pair).GetAddress() == addr) {
      return std::get<0>(pair);
    }
  }
  return kReservedHandle;
}

uint16_t AclConnectionHandler::GetHandleOnlyAddress(
    bluetooth::hci::Address addr) const {
  for (auto pair : acl_connections_) {
    if (std::get<AclConnection>(pair).GetAddress().GetAddress() == addr) {
      return std::get<0>(pair);
    }
  }
  return kReservedHandle;
}

std::optional<uint16_t> AclConnectionHandler::GetAclConnectionHandle(
    bluetooth::hci::Address bd_addr) const {
  for (auto const& [handle, connection] : acl_connections_) {
    if (connection.GetAddress().GetAddress() == bd_addr &&
        connection.GetPhyType() == Phy::Type::BR_EDR) {
      return handle;
    }
  }
  return {};
}

AclConnection& AclConnectionHandler::GetAclConnection(uint16_t handle) {
  ASSERT_LOG(HasHandle(handle), "Unknown handle %d", handle);
  return acl_connections_.at(handle);
}

AddressWithType AclConnectionHandler::GetAddress(uint16_t handle) const {
  ASSERT_LOG(HasHandle(handle), "Unknown handle %hd", handle);
  return acl_connections_.at(handle).GetAddress();
}

std::optional<AddressWithType> AclConnectionHandler::GetAddressSafe(
    uint16_t handle) const {
  return HasHandle(handle) ? acl_connections_.at(handle).GetAddress()
                           : std::optional<AddressWithType>();
}

Address AclConnectionHandler::GetScoAddress(uint16_t handle) const {
  ASSERT_LOG(HasScoHandle(handle), "Unknown SCO handle %hd", handle);
  return sco_connections_.at(handle).GetAddress();
}

AddressWithType AclConnectionHandler::GetOwnAddress(uint16_t handle) const {
  ASSERT_LOG(HasHandle(handle), "Unknown handle %hd", handle);
  return acl_connections_.at(handle).GetOwnAddress();
}

AddressWithType AclConnectionHandler::GetResolvedAddress(
    uint16_t handle) const {
  ASSERT_LOG(HasHandle(handle), "Unknown handle %hd", handle);
  return acl_connections_.at(handle).GetResolvedAddress();
}

void AclConnectionHandler::Encrypt(uint16_t handle) {
  if (!HasHandle(handle)) {
    return;
  }
  acl_connections_.at(handle).Encrypt();
}

bool AclConnectionHandler::IsEncrypted(uint16_t handle) const {
  if (!HasHandle(handle)) {
    return false;
  }
  return acl_connections_.at(handle).IsEncrypted();
}

void AclConnectionHandler::SetRssi(uint16_t handle, int8_t rssi) {
  if (HasHandle(handle)) {
    acl_connections_.at(handle).SetRssi(rssi);
  }
}

int8_t AclConnectionHandler::GetRssi(uint16_t handle) const {
  return HasHandle(handle) ? acl_connections_.at(handle).GetRssi() : 0;
}

Phy::Type AclConnectionHandler::GetPhyType(uint16_t handle) const {
  if (!HasHandle(handle)) {
    return Phy::Type::BR_EDR;
  }
  return acl_connections_.at(handle).GetPhyType();
}

uint16_t AclConnectionHandler::GetAclLinkPolicySettings(uint16_t handle) const {
  return acl_connections_.at(handle).GetLinkPolicySettings();
}

void AclConnectionHandler::SetAclLinkPolicySettings(uint16_t handle,
                                                    uint16_t settings) {
  acl_connections_.at(handle).SetLinkPolicySettings(settings);
}

bluetooth::hci::Role AclConnectionHandler::GetAclRole(uint16_t handle) const {
  return acl_connections_.at(handle).GetRole();
}

void AclConnectionHandler::SetAclRole(uint16_t handle,
                                      bluetooth::hci::Role role) {
  acl_connections_.at(handle).SetRole(role);
}

void AclConnectionHandler::CreateScoConnection(
    bluetooth::hci::Address addr, ScoConnectionParameters const& parameters,
    ScoState state, ScoDatapath datapath, bool legacy) {
  uint16_t sco_handle = GetUnusedHandle();
  sco_connections_.emplace(
      sco_handle, ScoConnection(addr, parameters, state, datapath, legacy));
}

bool AclConnectionHandler::HasPendingScoConnection(
    bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      ScoState state = std::get<ScoConnection>(pair).GetState();
      return state == SCO_STATE_PENDING ||
             state == SCO_STATE_SENT_ESCO_CONNECTION_REQUEST ||
             state == SCO_STATE_SENT_SCO_CONNECTION_REQUEST;
    }
  }
  return false;
}

ScoState AclConnectionHandler::GetScoConnectionState(
    bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      return std::get<ScoConnection>(pair).GetState();
    }
  }
  return SCO_STATE_CLOSED;
}

bool AclConnectionHandler::IsLegacyScoConnection(
    bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      return std::get<ScoConnection>(pair).IsLegacy();
    }
  }
  return false;
}

void AclConnectionHandler::CancelPendingScoConnection(
    bluetooth::hci::Address addr) {
  for (auto it = sco_connections_.begin(); it != sco_connections_.end(); it++) {
    if (std::get<ScoConnection>(*it).GetAddress() == addr) {
      sco_connections_.erase(it);
      return;
    }
  }
}

bool AclConnectionHandler::AcceptPendingScoConnection(
    bluetooth::hci::Address addr, ScoLinkParameters const& parameters,
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

bool AclConnectionHandler::AcceptPendingScoConnection(
    bluetooth::hci::Address addr, ScoConnectionParameters const& parameters,
    std::function<TaskId()> startStream) {
  for (auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      bool ok =
          std::get<ScoConnection>(pair).NegotiateLinkParameters(parameters);
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

uint16_t AclConnectionHandler::GetScoHandle(
    bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      return std::get<0>(pair);
    }
  }
  return kReservedHandle;
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

ScoLinkParameters AclConnectionHandler::GetScoLinkParameters(
    bluetooth::hci::Address addr) const {
  for (const auto& pair : sco_connections_) {
    if (std::get<ScoConnection>(pair).GetAddress() == addr) {
      return std::get<ScoConnection>(pair).GetLinkParameters();
    }
  }
  return {};
}

std::vector<uint16_t> AclConnectionHandler::GetAclHandles() const {
  std::vector<uint16_t> keys(acl_connections_.size());

  for (const auto& pair : acl_connections_) {
    keys.push_back(pair.first);
  }
  return keys;
}

void AclConnectionHandler::ResetLinkTimer(uint16_t handle) {
  acl_connections_.at(handle).ResetLinkTimer();
}

std::chrono::steady_clock::duration
AclConnectionHandler::TimeUntilLinkNearExpiring(uint16_t handle) const {
  return acl_connections_.at(handle).TimeUntilNearExpiring();
}

bool AclConnectionHandler::IsLinkNearExpiring(uint16_t handle) const {
  return acl_connections_.at(handle).IsNearExpiring();
}

std::chrono::steady_clock::duration AclConnectionHandler::TimeUntilLinkExpired(
    uint16_t handle) const {
  return acl_connections_.at(handle).TimeUntilExpired();
}

bool AclConnectionHandler::HasLinkExpired(uint16_t handle) const {
  return acl_connections_.at(handle).HasExpired();
}

bool AclConnectionHandler::IsRoleSwitchAllowedForPendingConnection() const {
  return pending_classic_connection_allow_role_switch_;
}

}  // namespace rootcanal
