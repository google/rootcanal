/*
 * Copyright 2016 The Android Open Source Project
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

#include "model/devices/beacon_swarm.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "model/devices/beacon.h"
#include "model/setup/device_boutique.h"
#include "packets/link_layer_packets.h"

namespace rootcanal {
using namespace model::packets;
using namespace std::chrono_literals;

bool BeaconSwarm::registered_ =
    DeviceBoutique::Register("beacon_swarm", &BeaconSwarm::Create);

BeaconSwarm::BeaconSwarm(const std::vector<std::string>& args) : Beacon(args) {
  advertising_interval_ = 1280ms;
  advertising_type_ = LegacyAdvertisingType::ADV_NONCONN_IND;
  advertising_data_ = {
      0x15 /* Length */,
      0x09 /* TYPE_NAME_COMPLETE */,
      'g',
      'D',
      'e',
      'v',
      'i',
      'c',
      'e',
      '-',
      'b',
      'e',
      'a',
      'c',
      'o',
      'n',
      '_',
      's',
      'w',
      'a',
      'r',
      'm',
      0x02 /* Length */,
      0x01 /* TYPE_FLAG */,
      0x4 /* BREDR_NOT_SUPPORTED */ | 0x2 /* GENERAL_DISCOVERABLE */,
  };

  scan_response_data_ = {
      0x06 /* Length */, 0x08 /* TYPE_NAME_SHORT */, 'c', 'b', 'e', 'a', 'c'};
}

void BeaconSwarm::Tick() {
  // Rotate the advertising address.
  uint8_t* low_order_byte = address_.data();
  *low_order_byte += 1;
  Beacon::Tick();
}

}  // namespace rootcanal
