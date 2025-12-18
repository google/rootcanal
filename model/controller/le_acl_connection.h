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

#include "hci/address_with_type.h"
#include "packets/hci_packets.h"

namespace rootcanal {

using bluetooth::hci::AddressWithType;

/// Link specification.
/// Records the configuration of the LE-ACL connection.
///
/// Volume 6 Part B § 4.5.1. Connection events.
/// The timing of connection events is determined by the following parameters:
/// connection interval (connInterval), subrate base event (connSubrateBaseEvent),
/// subrate factor (connSubrateFactor), continuation number (connContinuationNumber),
/// and Peripheral latency (connPeripheralLatency).
struct LeAclConnectionParameters {
  // The connInterval shall be a multiple of 1.25 ms in the range 7.5 ms to 4.0 s.
  uint16_t conn_interval{};
  uint16_t conn_subrate_factor{1};
  uint16_t conn_continuation_number{0};

  // The connPeripheralLatency parameter defines the number of consecutive subrated
  // connection events that the Peripheral is not required to listen for the Central.
  // connPeripheralLatency shall be an integer such that
  // connSubrateFactor × (connPeripheralLatency + 1) is less than or equal to 500 and
  // connInterval × connSubrateFactor × (connPeripheralLatency + 1) is less than half
  // connSupervisionTimeout.
  uint16_t conn_peripheral_latency{0};

  // Volume 6 Part B § 4.5.2. Supervision timeout.
  // Supervision timeout for the LE Link. The connSupervisionTimeout shall be a
  // multiple of 10 ms.
  uint16_t conn_supervision_timeout{};
};

/// Ranges for acceptable subrate parameters.
/// LE Default Subrate parameters (Vol 4, Part E § 7.8.123).
struct LeAclSubrateParameters {
  uint16_t subrate_min{1};
  uint16_t subrate_max{1};
  uint16_t max_latency{0};
  uint16_t continuation_number{0};
  uint16_t supervision_timeout{0x0c80};
};

// Model the LE connection of a device to the controller.
class LeAclConnection final {
public:
  const uint16_t handle;
  const AddressWithType address;
  const AddressWithType own_address;
  const AddressWithType resolved_address;
  const bluetooth::hci::Role role;

  LeAclConnectionParameters parameters;
  LeAclSubrateParameters subrate_parameters;

  LeAclConnection(uint16_t handle, AddressWithType address, AddressWithType own_address,
                  AddressWithType resolved_address, bluetooth::hci::Role role,
                  LeAclConnectionParameters parameters, LeAclSubrateParameters subrate_parameters);
  ~LeAclConnection() = default;

  void Encrypt();
  bool IsEncrypted() const;

  int8_t GetRssi() const;
  void SetRssi(int8_t rssi);

  std::chrono::steady_clock::duration TimeUntilNearExpiring() const;
  std::chrono::steady_clock::duration TimeUntilExpired() const;
  void ResetLinkTimer();
  bool IsNearExpiring() const;
  bool HasExpired() const;

  // LE-ACL state.
  void InitiatePhyUpdate() { initiated_phy_update_ = true; }
  void PhyUpdateComplete() { initiated_phy_update_ = false; }
  bool InitiatedPhyUpdate() const { return initiated_phy_update_; }
  bluetooth::hci::PhyType GetTxPhy() const { return tx_phy_; }
  bluetooth::hci::PhyType GetRxPhy() const { return rx_phy_; }
  void SetTxPhy(bluetooth::hci::PhyType phy) { tx_phy_ = phy; }
  void SetRxPhy(bluetooth::hci::PhyType phy) { rx_phy_ = phy; }

private:
  // Reports the RSSI measured for the last packet received on
  // this connection.
  int8_t rssi_{0};

  // State variables
  bool encrypted_{false};
  std::chrono::steady_clock::time_point last_packet_timestamp_;
  std::chrono::steady_clock::duration timeout_;

  // LE-ACL state.
  bluetooth::hci::PhyType tx_phy_{bluetooth::hci::PhyType::LE_1M};
  bluetooth::hci::PhyType rx_phy_{bluetooth::hci::PhyType::LE_1M};
  bool initiated_phy_update_{false};
};

}  // namespace rootcanal
