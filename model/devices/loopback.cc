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

#include "loopback.h"

#include "model/setup/device_boutique.h"
#include "os/log.h"

using std::vector;

namespace rootcanal {

bool Loopback::registered_ =
    DeviceBoutique::Register("loopback", &Loopback::Create);

Loopback::Loopback() {
  advertising_interval_ms_ = std::chrono::milliseconds(1280);
  properties_.SetLeAdvertisementType(0x03);  // NON_CONNECT
  properties_.SetLeAdvertisement({
      0x11,  // Length
      0x09,  // NAME_CMPL
      'g',         'D', 'e', 'v', 'i', 'c', 'e', '-',
      'l',         'o', 'o', 'p', 'b', 'a', 'c', 'k',
      0x02,         // Length
      0x01,         // TYPE_FLAG
      0x04 | 0x02,  // BREDR_NOT_SPT | GEN_DISC
  });

  properties_.SetLeScanResponse({0x05,  // Length
                                 0x08,  // NAME_SHORT
                                 'l', 'o', 'o', 'p'});
}

std::string Loopback::GetTypeString() const { return "loopback"; }

std::string Loopback::ToString() const {
  std::string dev =
      GetTypeString() + "@" + properties_.GetLeAddress().ToString();

  return dev;
}

void Loopback::Initialize(const vector<std::string>& args) {
  if (args.size() < 2) return;

  Address addr{};
  if (Address::FromString(args[1], addr)) properties_.SetLeAddress(addr);

  if (args.size() < 3) return;

  SetAdvertisementInterval(std::chrono::milliseconds(std::stoi(args[2])));
}

void Loopback::TimerTick() {}

void Loopback::IncomingPacket(model::packets::LinkLayerPacketView packet) {
  LOG_INFO("Got a packet of type %d", static_cast<int>(packet.GetType()));
  if (packet.GetDestinationAddress() == properties_.GetLeAddress() &&
      packet.GetType() == model::packets::PacketType::LE_SCAN) {
    LOG_INFO("Got a scan");

    auto scan_response = model::packets::LeScanResponseBuilder::Create(
        properties_.GetLeAddress(), packet.GetSourceAddress(),
        model::packets::AddressType::PUBLIC,
        model::packets::AdvertisementType::SCAN_RESPONSE,
        properties_.GetLeScanResponse());
    std::shared_ptr<model::packets::LinkLayerPacketBuilder> to_send =
        std::move(scan_response);

    SendLinkLayerPacket(to_send, Phy::Type::LOW_ENERGY);
  }
}

}  // namespace rootcanal
