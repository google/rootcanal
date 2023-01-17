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

#include "phy_device.h"

#include "phy_layer.h"

namespace rootcanal {

PhyDevice::PhyDevice(Identifier id, std::string type,
                     std::shared_ptr<Device> device)
    : id(id), type(std::move(type)), device_(std::move(device)) {
  using namespace std::placeholders;
  ASSERT(device_ != nullptr);
  device_->RegisterLinkLayerChannel(
      std::bind(&PhyDevice::Send, this, _1, _2, _3));
}

void PhyDevice::Register(PhyLayer* phy) { phy_layers_.insert(phy); }

void PhyDevice::Unregister(PhyLayer* phy) { phy_layers_.erase(phy); }

void PhyDevice::Tick() { device_->Tick(); }

void PhyDevice::SetAddress(bluetooth::hci::Address address) {
  device_->SetAddress(std::move(address));
}

void PhyDevice::Receive(std::vector<uint8_t> const& packet, Phy::Type type,
                        int8_t rssi) {
  std::shared_ptr<std::vector<uint8_t>> packet_copy =
      std::make_shared<std::vector<uint8_t>>(packet);
  model::packets::LinkLayerPacketView packet_view =
      model::packets::LinkLayerPacketView::Create(
          bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian>(
              packet_copy));
  if (packet_view.IsValid()) {
    device_->ReceiveLinkLayerPacket(std::move(packet_view), type, rssi);
  } else {
    LOG_WARN("received invalid LL packet");
  }
}

void PhyDevice::Send(std::vector<uint8_t> const& packet, Phy::Type type,
                     int8_t tx_power) {
  for (auto const& phy : phy_layers_) {
    if (phy->type == type) {
      phy->Send(packet, tx_power, id);
    }
  }
}

std::string PhyDevice::ToString() { return device_->ToString(); }

}  // namespace rootcanal
