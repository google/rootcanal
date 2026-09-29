/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "model/controller/controller_properties.h"
#include "packets/hci_packets.h"

namespace rootcanal {

//
// Channel Sounding configuration and settings.
//

const auto kCsProcedureInterval = std::chrono::milliseconds(50);

struct LeCsDefaultSettings {
  uint8_t role_enable{};
  uint8_t cs_sync_antenna_selection{
          static_cast<uint8_t>(bluetooth::hci::CsSyncAntennaSelection::ANTENNA_1)};
  int8_t max_tx_power{20};
};

struct LeCsProcedureParameters {
  uint16_t max_procedure_len;
  uint16_t min_procedure_interval;
  uint16_t max_procedure_interval;
  uint16_t max_procedure_count;
  uint32_t min_subevent_len;
  uint32_t max_subevent_len;
  uint8_t tone_antenna_config_selection;
  bluetooth::hci::CsPhy phy;
  uint8_t tx_power_delta;
  bluetooth::hci::CsPreferredPeerAntenna preferred_peer_antenna;
  bluetooth::hci::CsSnrControl snr_control_initiator;
  bluetooth::hci::CsSnrControl snr_control_reflector;
};

struct LeCsConfig {
  uint8_t config_id;
  std::array<uint8_t, 10> channel_map;
  uint8_t channel_map_repetition;
  uint8_t main_mode_type;
  uint8_t sub_mode_type;
  uint8_t min_main_mode_steps;
  uint8_t max_main_mode_steps;
  uint8_t main_mode_repetition;
  uint8_t mode_0_steps;
  uint8_t cs_sync_phy;
  uint8_t rtt_type;
  uint8_t role;
  uint8_t channel_selection_type;
  uint8_t ch3c_shape;
  uint8_t ch3c_jump;
  bool enabled{};
  std::optional<LeCsProcedureParameters> procedure_parameters;
  uint8_t last_rotated_channel{};
  uint16_t remaining_procedure_count{};
  std::optional<std::chrono::steady_clock::time_point> result_timeout{};
};

struct LeCsParameters {
  std::optional<CsLocalSupportedCapabilities> remote_cs_capabilities;
  std::optional<std::array<uint8_t, 72>> remote_fae_table;
  LeCsDefaultSettings default_settings;
  std::unordered_map<uint8_t, LeCsConfig> config_map;
  uint8_t procedure_count{};

  // CS Security
  bool security_enabled{};
  uint64_t iv{};
  uint32_t in{};
  uint64_t pv{};
};

}  // namespace rootcanal
