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

#include "beacon.h"

#include "model/setup/device_boutique.h"

using std::vector;

namespace rootcanal {

bool Beacon::registered_ = DeviceBoutique::Register("beacon", &Beacon::Create);

Beacon::Beacon() {
  advertising_interval_ms_ = std::chrono::milliseconds(1280);
  properties_.SetLeAdvertisementType(0x03 /* NON_CONNECT */);
  properties_.SetLeAdvertisement(
      {0x0F,  // Length
       0x09 /* TYPE_NAME_CMPL */, 'g', 'D', 'e', 'v', 'i', 'c', 'e', '-', 'b',
       'e', 'a', 'c', 'o', 'n',
       0x02,  // Length
       0x01 /* TYPE_FLAG */,
       0x4 /* BREDR_NOT_SPT */ | 0x2 /* GEN_DISC_FLAG */});

  properties_.SetLeScanResponse({0x05,  // Length
                                 0x08 /* TYPE_NAME_SHORT */, 'b', 'e', 'a',
                                 'c'});
}

std::string Beacon::GetTypeString() const { return "beacon"; }

std::string Beacon::ToString() const {
  std::string dev =
      GetTypeString() + "@" + properties_.GetLeAddress().ToString();

  return dev;
}

void Beacon::Initialize(const vector<std::string>& args) {
  if (args.size() < 2) return;

  Address addr{};
  if (Address::FromString(args[1], addr)) properties_.SetLeAddress(addr);

  if (args.size() < 3) return;

  SetAdvertisementInterval(std::chrono::milliseconds(std::stoi(args[2])));
}

void Beacon::TimerTick() {
  if (IsAdvertisementAvailable()) {
    last_advertisement_ = std::chrono::steady_clock::now();
    auto ad = model::packets::LeAdvertisementBuilder::Create(
        properties_.GetLeAddress(), Address::kEmpty,
        model::packets::AddressType::PUBLIC,
        static_cast<model::packets::AdvertisementType>(
            properties_.GetLeAdvertisementType()),
        properties_.GetLeAdvertisement());
    std::shared_ptr<model::packets::LinkLayerPacketBuilder> to_send =
        std::move(ad);

    SendLinkLayerPacket(to_send, Phy::Type::LOW_ENERGY);
  }
}

void Beacon::IncomingPacket(model::packets::LinkLayerPacketView packet) {
  if (packet.GetDestinationAddress() == properties_.GetLeAddress() &&
      packet.GetType() == model::packets::PacketType::LE_SCAN) {
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
