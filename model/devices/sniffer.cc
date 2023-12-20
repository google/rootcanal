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

#include "model/devices/sniffer.h"

#include <cstdint>
#include <string>
#include <vector>

#include "hci/address.h"
#include "log.h"
#include "model/setup/device_boutique.h"
#include "packets/link_layer_packets.h"
#include "phy.h"

namespace rootcanal {

bool Sniffer::registered_ =
    DeviceBoutique::Register("sniffer", &Sniffer::Create);

Sniffer::Sniffer(const std::vector<std::string>& args) {
  if (args.size() >= 2) {
    Address::FromString(args[1], address_);
  }
}

void Sniffer::ReceiveLinkLayerPacket(model::packets::LinkLayerPacketView packet,
                                     Phy::Type /*type*/, int8_t /*rssi*/) {
  Address source = packet.GetSourceAddress();
  Address dest = packet.GetDestinationAddress();
  model::packets::PacketType packet_type = packet.GetType();

  bool match_source = address_ == source;
  bool match_dest = address_ == dest;
  if (!match_source && !match_dest) {
    return;
  }

  INFO("{} {} -> {} (Type {})",
       (match_source ? (match_dest ? "<->" : "<--") : "-->"), source, dest,
       model::packets::PacketTypeText(packet_type));
}

}  // namespace rootcanal
