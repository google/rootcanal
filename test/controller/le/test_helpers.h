/*
 * Copyright 2022 The Android Open Source Project
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

#include "model/controller/link_layer_controller.h"

enum : unsigned {
  CONNECTABLE = 0x1,
  SCANNABLE = 0x2,
  DIRECTED = 0x4,
  HIGH_DUTY_CYCLE = 0x8,
  LEGACY = 0x10,
  ANONYMOUS = 0x20,
  TX_POWER = 0x40,
};

[[maybe_unused]] static bluetooth::hci::AdvertisingEventProperties
MakeAdvertisingEventProperties(unsigned mask) {
  bluetooth::hci::AdvertisingEventProperties properties;
  properties.connectable_ = (mask & CONNECTABLE) != 0;
  properties.scannable_ = (mask & SCANNABLE) != 0;
  properties.directed_ = (mask & DIRECTED) != 0;
  properties.high_duty_cycle_ = (mask & HIGH_DUTY_CYCLE) != 0;
  properties.legacy_ = (mask & LEGACY) != 0;
  properties.anonymous_ = (mask & ANONYMOUS) != 0;
  properties.tx_power_ = (mask & TX_POWER) != 0;
  return properties;
}

[[maybe_unused]] static bluetooth::hci::EnabledSet MakeEnabledSet(
    uint8_t advertising_handle, uint16_t duration,
    uint8_t max_extended_advertising_events) {
  bluetooth::hci::EnabledSet set;
  set.advertising_handle_ = advertising_handle;
  set.duration_ = duration;
  set.max_extended_advertising_events_ = max_extended_advertising_events;
  return set;
}

[[maybe_unused]] static bluetooth::hci::LeCreateConnPhyScanParameters
MakeInitiatingPhyParameters(uint16_t scan_interval, uint16_t scan_window,
                            uint16_t connection_interval_min,
                            uint16_t connection_interval_max,
                            uint16_t max_latency, uint16_t supervision_timeout,
                            uint16_t min_ce_length, uint16_t max_ce_length) {
  bluetooth::hci::LeCreateConnPhyScanParameters parameters;
  parameters.scan_interval_ = scan_interval;
  parameters.scan_window_ = scan_window;
  parameters.conn_interval_min_ = connection_interval_min;
  parameters.conn_interval_max_ = connection_interval_max;
  parameters.conn_latency_ = max_latency;
  parameters.supervision_timeout_ = supervision_timeout;
  parameters.min_ce_length_ = min_ce_length;
  parameters.max_ce_length_ = max_ce_length;
  return parameters;
}
