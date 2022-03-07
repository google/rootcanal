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

#include "keyboard.h"

#include "model/setup/device_boutique.h"

using std::vector;

namespace rootcanal {
bool Keyboard::registered_ =
    DeviceBoutique::Register("keyboard", &Keyboard::Create);

Keyboard::Keyboard() {
  properties_.SetLeAdvertisementType(0x00 /* CONNECTABLE */);
  properties_.SetLeAdvertisement(
      {0x11,  // Length
       0x09 /* TYPE_NAME_CMPL */,
       'g',
       'D',
       'e',
       'v',
       'i',
       'c',
       'e',
       '-',
       'k',
       'e',
       'y',
       'b',
       'o',
       'a',
       'r',
       'd',
       0x03,  // Length
       0x19,
       0xC1,
       0x03,
       0x03,  // Length
       0x03,
       0x12,
       0x18,
       0x02,  // Length
       0x01 /* TYPE_FLAGS */,
       0x04 /* BREDR_NOT_SPT */ | 0x02 /* GEN_DISC_FLAG */});

  properties_.SetLeScanResponse({0x04,  // Length
                                 0x08 /* TYPE_NAME_SHORT */, 'k', 'e', 'y'});
}

std::string Keyboard::GetTypeString() const { return "keyboard"; }

void Keyboard::Initialize(const vector<std::string>& args) {
  if (args.size() < 2) return;

  Address addr{};
  if (Address::FromString(args[1], addr)) properties_.SetLeAddress(addr);

  if (args.size() < 3) return;

  SetAdvertisementInterval(std::chrono::milliseconds(std::stoi(args[2])));
}

void Keyboard::TimerTick() {
  if (!connected_) {
    Beacon::TimerTick();
  }
}

void Keyboard::IncomingPacket(model::packets::LinkLayerPacketView packet) {
  if (!connected_) {
    Beacon::IncomingPacket(packet);
  }
}

}  // namespace rootcanal
