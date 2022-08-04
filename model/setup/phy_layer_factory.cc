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

#include "phy_layer_factory.h"

#include <sstream>

namespace rootcanal {

PhyLayerFactory::PhyLayerFactory(Phy::Type phy_type, uint32_t factory_id)
    : phy_type_(phy_type), factory_id_(factory_id) {}

Phy::Type PhyLayerFactory::GetType() { return phy_type_; }

uint32_t PhyLayerFactory::GetFactoryId() { return factory_id_; }

std::shared_ptr<PhyLayer> PhyLayerFactory::GetPhyLayer(
    const std::function<void(model::packets::LinkLayerPacketView)>&
        device_receive,
    uint32_t device_id) {
  std::shared_ptr<PhyLayer> new_phy = std::make_shared<PhyLayerImpl>(
      phy_type_, next_id_++, device_receive, device_id, this);
  phy_layers_.push_back(new_phy);
  return new_phy;
}

void PhyLayerFactory::UnregisterPhyLayer(uint32_t id) {
  for (auto phy : phy_layers_) {
    if (phy->GetId() == id) {
      phy_layers_.remove(phy);
      return;
    }
  }
}

void PhyLayerFactory::UnregisterAllPhyLayers() {
  while (!phy_layers_.empty()) {
    if (phy_layers_.begin() != phy_layers_.end()) {
      auto id = (*phy_layers_.begin())->GetId();
      UnregisterPhyLayer(id);
    }
  }
}

void PhyLayerFactory::Send(
    const std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
    uint32_t id, [[maybe_unused]] uint32_t device_id) {
  // Convert from a Builder to a View
  auto bytes = std::make_shared<std::vector<uint8_t>>();
  bluetooth::packet::BitInserter i(*bytes);
  bytes->reserve(packet->size());
  packet->Serialize(i);
  auto packet_view =
      bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian>(bytes);
  auto link_layer_packet_view =
      model::packets::LinkLayerPacketView::Create(packet_view);
  ASSERT(link_layer_packet_view.IsValid());

  Send(link_layer_packet_view, id, device_id);
}

void PhyLayerFactory::Send(model::packets::LinkLayerPacketView packet,
                           uint32_t id, [[maybe_unused]] uint32_t device_id) {
  for (const auto& phy : phy_layers_) {
    if (id != phy->GetId()) {
      phy->Receive(packet);
    }
  }
}

void PhyLayerFactory::TimerTick() {
  for (auto& phy : phy_layers_) {
    phy->TimerTick();
  }
}

std::string PhyLayerFactory::ToString() const {
  std::stringstream factory;
  switch (phy_type_) {
    case Phy::Type::LOW_ENERGY:
      factory << "LOW_ENERGY: ";
      break;
    case Phy::Type::BR_EDR:
      factory << "BR_EDR: ";
      break;
    default:
      factory << "Unknown: ";
  }
  for (auto& phy : phy_layers_) {
    factory << phy->GetDeviceId();
    factory << ",";
  }

  return factory.str();
}

PhyLayerImpl::PhyLayerImpl(
    Phy::Type phy_type, uint32_t id,
    const std::function<void(model::packets::LinkLayerPacketView)>&
        device_receive,
    uint32_t device_id, PhyLayerFactory* factory)
    : PhyLayer(phy_type, id, device_receive, device_id), factory_(factory) {}

PhyLayerImpl::~PhyLayerImpl() {}

void PhyLayerImpl::Send(
    const std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet) {
  factory_->Send(packet, GetId(), GetDeviceId());
}

void PhyLayerImpl::Send(model::packets::LinkLayerPacketView packet) {
  factory_->Send(packet, GetId(), GetDeviceId());
}

void PhyLayerImpl::Unregister() { factory_->UnregisterPhyLayer(GetId()); }

bool PhyLayerImpl::IsFactoryId(uint32_t id) {
  return factory_->GetFactoryId() == id;
}

void PhyLayerImpl::Receive(model::packets::LinkLayerPacketView packet) {
  transmit_to_device_(packet);
}

void PhyLayerImpl::TimerTick() {}

}  // namespace rootcanal
