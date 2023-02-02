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

#include "phy_layer.h"

#include <sstream>

namespace rootcanal {

PhyLayer::PhyLayer(Identifier id, Phy::Type type) : id(id), type(type) {}

void PhyLayer::Register(std::shared_ptr<PhyDevice> device) {
  device->Register(this);
  phy_devices_.push_back(device);
}

void PhyLayer::Unregister(PhyDevice::Identifier id) {
  for (auto& device : phy_devices_) {
    if (device->id == id) {
      device->Unregister(this);
      phy_devices_.remove(device);
      return;
    }
  }
}

void PhyLayer::UnregisterAll() {
  for (auto& device : phy_devices_) {
    device->Unregister(this);
  }
  phy_devices_.clear();
}

int8_t PhyLayer::ComputeRssi(PhyDevice::Identifier sender_id,
                             PhyDevice::Identifier receiver_id,
                             int8_t tx_power) {
  // Perform no RSSI computation by default.
  // Clients overriding this function should use the TX power and
  // positional information to derive correct device-to-device RSSI.
  static uint8_t rssi = 0;
  rssi = (rssi + 5) % 128;
  return static_cast<int8_t>(-rssi);
}

void PhyLayer::Send(std::vector<uint8_t> const& packet, int8_t tx_power,
                    PhyDevice::Identifier sender_id) {
  for (const auto& device : phy_devices_) {
    // Do not send the packet back to the sender.
    if (sender_id != device->id) {
      device->Receive(packet, type,
                      ComputeRssi(sender_id, device->id, tx_power));
    }
  }
}

void PhyLayer::Tick() {
  for (auto& device : phy_devices_) {
    device->Tick();
  }
}

std::string PhyLayer::ToString() const {
  std::stringstream factory;
  switch (type) {
    case Phy::Type::LOW_ENERGY:
      factory << "LOW_ENERGY: ";
      break;
    case Phy::Type::BR_EDR:
      factory << "BR_EDR: ";
      break;
    default:
      factory << "Unknown: ";
  }
  for (auto& device : phy_devices_) {
    factory << device->id;
    factory << ",";
  }

  return factory.str();
}

}  // namespace rootcanal
