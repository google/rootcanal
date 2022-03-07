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

#include "remote_loopback_device.h"

#include "model/setup/device_boutique.h"
#include "os/log.h"

using std::vector;

namespace rootcanal {

using model::packets::LinkLayerPacketView;
using model::packets::PageResponseBuilder;

bool RemoteLoopbackDevice::registered_ =
    DeviceBoutique::Register("remote_loopback", &RemoteLoopbackDevice::Create);

RemoteLoopbackDevice::RemoteLoopbackDevice() {}

std::string RemoteLoopbackDevice::ToString() const {
  return GetTypeString() + " (no address)";
}

void RemoteLoopbackDevice::Initialize(const std::vector<std::string>& args) {
  if (args.size() < 2) return;

  Address addr{};
  if (Address::FromString(args[1], addr)) properties_.SetAddress(addr);
}

void RemoteLoopbackDevice::IncomingPacket(
    model::packets::LinkLayerPacketView packet) {
  // TODO: Check sender?
  // TODO: Handle other packet types
  Phy::Type phy_type = Phy::Type::BR_EDR;

  model::packets::PacketType type = packet.GetType();
  switch (type) {
    case model::packets::PacketType::PAGE:
      SendLinkLayerPacket(
          PageResponseBuilder::Create(packet.GetSourceAddress(),
                                      packet.GetSourceAddress(), true),
          Phy::Type::BR_EDR);
      break;
    default: {
      LOG_WARN("Resend = %d", static_cast<int>(packet.size()));
      SendLinkLayerPacket(packet, phy_type);
    }
  }
}

}  // namespace rootcanal
