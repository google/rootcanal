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
#include <set>
#include <unordered_map>

#include "acl_connection.h"
#include "hci/address.h"
#include "hci/address_with_type.h"
#include "isochronous_connection_handler.h"
#include "model/setup/async_manager.h"
#include "phy.h"
#include "sco_connection.h"

namespace rootcanal {
static constexpr uint16_t kReservedHandle = 0xF00;

class AclConnectionHandler {
 public:
  AclConnectionHandler() = default;
  virtual ~AclConnectionHandler() = default;

  // Reset the connection manager state, stopping any pending
  // SCO connections.
  void Reset(std::function<void(AsyncTaskId)> stopStream);

  bool CreatePendingConnection(bluetooth::hci::Address addr,
                               bool authenticate_on_connect);
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
                                  std::function<AsyncTaskId()> startStream);
  bool AcceptPendingScoConnection(bluetooth::hci::Address addr,
                                  ScoConnectionParameters const& parameters,
                                  std::function<AsyncTaskId()> startStream);
  uint16_t GetScoHandle(bluetooth::hci::Address addr) const;
  ScoConnectionParameters GetScoConnectionParameters(
      bluetooth::hci::Address addr) const;
  ScoLinkParameters GetScoLinkParameters(bluetooth::hci::Address addr) const;

  bool CreatePendingLeConnection(bluetooth::hci::AddressWithType peer,
                                 bluetooth::hci::AddressWithType resolved_peer,
                                 bluetooth::hci::AddressWithType local_address);
  bool HasPendingLeConnection(bluetooth::hci::AddressWithType addr) const;
  bool CancelPendingLeConnection(bluetooth::hci::AddressWithType addr);

  uint16_t CreateConnection(bluetooth::hci::Address addr,
                            bluetooth::hci::Address own_addr);
  uint16_t CreateLeConnection(bluetooth::hci::AddressWithType addr,
                              bluetooth::hci::AddressWithType own_addr,
                              bluetooth::hci::Role role);
  bool Disconnect(uint16_t handle, std::function<void(AsyncTaskId)> stopStream);
  bool HasHandle(uint16_t handle) const;
  bool HasScoHandle(uint16_t handle) const;

  uint16_t GetHandle(bluetooth::hci::AddressWithType addr) const;
  uint16_t GetHandleOnlyAddress(bluetooth::hci::Address addr) const;
  bluetooth::hci::AddressWithType GetAddress(uint16_t handle) const;
  bluetooth::hci::Address GetScoAddress(uint16_t handle) const;
  bluetooth::hci::AddressWithType GetOwnAddress(uint16_t handle) const;
  bluetooth::hci::AddressWithType GetResolvedAddress(uint16_t handle) const;

  void Encrypt(uint16_t handle);
  bool IsEncrypted(uint16_t handle) const;

  Phy::Type GetPhyType(uint16_t handle) const;

  uint16_t GetAclLinkPolicySettings(uint16_t handle) const;
  void SetAclLinkPolicySettings(uint16_t handle, uint16_t settings);

  bluetooth::hci::Role GetAclRole(uint16_t handle) const;
  void SetAclRole(uint16_t handle, bluetooth::hci::Role role);

  std::unique_ptr<bluetooth::hci::LeSetCigParametersCompleteBuilder>
  SetCigParameters(uint8_t id, uint32_t sdu_interval_m_to_s,
                   uint32_t sdu_interval_s_to_m,
                   bluetooth::hci::ClockAccuracy accuracy,
                   bluetooth::hci::Packing packing,
                   bluetooth::hci::Enable framing,
                   uint16_t max_transport_latency_m_to_s,
                   uint16_t max_transport_latency_s_to_m,
                   std::vector<bluetooth::hci::CisParametersConfig>& streams);

  void CreatePendingCis(bluetooth::hci::CreateCisConfig config);

  bool ConnectCis(uint16_t handle);

  void SetRemoteCisHandle(uint16_t handle, uint16_t remote_handle);

  uint16_t GetPendingAclHandle(uint16_t cis_handle) const;

  bool RejectCis(uint16_t handle);

  bool DisconnectCis(uint16_t handle);

  bluetooth::hci::ErrorCode RemoveCig(uint8_t cig_id);

  bool HasPendingCis() const;

  bool HasPendingCisConnection(uint16_t handle) const;

  bool HasCisHandle(uint16_t handle) const;

  bool HasConnectedCis(uint16_t handle) const;

  uint16_t GetAclHandleForCisHandle(uint16_t cis_handle) const;
  uint16_t GetRemoteCisHandleForCisHandle(uint16_t cis_handle) const;

  StreamParameters GetStreamParameters(uint16_t handle) const;
  GroupParameters GetGroupParameters(uint8_t id) const;

  std::vector<uint16_t> GetAclHandles() const;

  void ResetLinkTimer(uint16_t handle);
  std::chrono::steady_clock::duration TimeUntilLinkNearExpiring(
      uint16_t handle) const;
  bool IsLinkNearExpiring(uint16_t handle) const;
  std::chrono::steady_clock::duration TimeUntilLinkExpired(
      uint16_t handle) const;
  bool HasLinkExpired(uint16_t handle) const;

 private:
  std::unordered_map<uint16_t, AclConnection> acl_connections_;
  std::unordered_map<uint16_t, ScoConnection> sco_connections_;

  bool classic_connection_pending_{false};
  bluetooth::hci::Address pending_connection_address_{
      bluetooth::hci::Address::kEmpty};
  bool authenticate_pending_classic_connection_{false};
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
  IsochronousConnectionHandler isochronous_connection_handler_;
  struct CisHandles {
    uint16_t acl_handle_ = kReservedHandle;
    uint16_t cis_handle_ = kReservedHandle;
    uint16_t remote_cis_handle_ = kReservedHandle;
  };
  std::vector<CisHandles> connected_streams_;
  std::vector<CisHandles> pending_streams_;
};

}  // namespace rootcanal
