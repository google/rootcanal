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

#include "model/devices/device.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "log.h"
#include "packets/link_layer_packets.h"
#include "phy.h"

namespace rootcanal {

static uint32_t next_instance_id() {
  static uint32_t instance_counter = 0;
  return instance_counter++;
}

Device::Device() : id_(next_instance_id()) {
  ASSERT(Address::FromString("BB:BB:BB:BB:BB:AD", address_));
}

std::string Device::ToString() const {
  return GetTypeString() + "@" + address_.ToString();
}

void Device::Close() {
  if (close_callback_ != nullptr) {
    close_callback_();
  }
}

void Device::SendLinkLayerPacket(
    std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
    Phy::Type type, int8_t tx_power) {
  SendLinkLayerPacket(packet->SerializeToBytes(), type, tx_power);
}

void Device::SendLinkLayerPacket(std::vector<uint8_t> const& packet,
                                 Phy::Type type, int8_t tx_power) {
  if (send_ll_ != nullptr) {
    send_ll_(packet, type, tx_power);
  }
}

void Device::RegisterCloseCallback(std::function<void()> close_callback) {
  close_callback_ = close_callback;
}

void Device::RegisterLinkLayerChannel(
    std::function<void(std::vector<uint8_t> const&, Phy::Type, int8_t)>
        send_ll) {
  send_ll_ = send_ll;
}

}  // namespace rootcanal
