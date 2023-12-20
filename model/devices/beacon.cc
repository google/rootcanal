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

#include "model/devices/beacon.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "hci/address.h"
#include "model/setup/device_boutique.h"
#include "packets/link_layer_packets.h"
#include "phy.h"

namespace rootcanal {
using namespace model::packets;
using namespace std::chrono_literals;

bool Beacon::registered_ = DeviceBoutique::Register("beacon", &Beacon::Create);

Beacon::Beacon()
    : advertising_type_(LegacyAdvertisingType::ADV_NONCONN_IND),
      advertising_data_({
          0x0F /* Length */, 0x09 /* TYPE_NAME_COMPLETE */, 'g', 'D', 'e', 'v',
          'i', 'c', 'e', '-', 'b', 'e', 'a', 'c', 'o', 'n', 0x02 /* Length */,
          0x01 /* TYPE_FLAG */,
          0x4 /* BREDR_NOT_SUPPORTED */ | 0x2 /* GENERAL_DISCOVERABLE */
      }),
      scan_response_data_(
          {0x05 /* Length */, 0x08 /* TYPE_NAME_SHORT */, 'b', 'e', 'a', 'c'}),
      advertising_interval_(1280ms) {}

Beacon::Beacon(const std::vector<std::string>& args) : Beacon() {
  if (args.size() >= 2) {
    Address::FromString(args[1], address_);
  }

  if (args.size() >= 3) {
    advertising_interval_ = std::chrono::milliseconds(std::stoi(args[2]));
  }
}

void Beacon::Tick() {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  if ((now - advertising_last_) >= advertising_interval_) {
    advertising_last_ = now;
    SendLinkLayerPacket(
        std::move(LeLegacyAdvertisingPduBuilder::Create(
            address_, Address::kEmpty, AddressType::PUBLIC, AddressType::PUBLIC,
            advertising_type_,
            std::vector(advertising_data_.begin(), advertising_data_.end()))),
        Phy::Type::LOW_ENERGY);
  }
}

void Beacon::ReceiveLinkLayerPacket(LinkLayerPacketView packet,
                                    Phy::Type /*type*/, int8_t /*rssi*/) {
  if (packet.GetDestinationAddress() == address_ &&
      packet.GetType() == PacketType::LE_SCAN &&
      (advertising_type_ == LegacyAdvertisingType::ADV_IND ||
       advertising_type_ == LegacyAdvertisingType::ADV_SCAN_IND)) {
    SendLinkLayerPacket(
        std::move(LeScanResponseBuilder::Create(
            address_, packet.GetSourceAddress(), AddressType::PUBLIC,
            std::vector(scan_response_data_.begin(),
                        scan_response_data_.end()))),
        Phy::Type::LOW_ENERGY);
  }
}

}  // namespace rootcanal
