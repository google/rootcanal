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

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "hci/address.h"
#include "model/setup/phy_layer.h"
#include "packets/link_layer_packets.h"

namespace rootcanal {

using ::bluetooth::hci::Address;

// Represent a Bluetooth Device
//  - Provide Get*() and Set*() functions for device attributes.
class Device {
 public:
  Device() { ASSERT(Address::FromString("BB:BB:BB:BB:BB:AD", address_)); }
  virtual ~Device() = default;

  // Return a string representation of the type of device.
  virtual std::string GetTypeString() const = 0;

  // Return the string representation of the device.
  virtual std::string ToString() const;

  // Set the device's Bluetooth address.
  void SetAddress(Address address) { address_ = address; }

  // Get the device's Bluetooth address.
  const Address& GetAddress() const { return address_; }

  // Let the device know that time has passed.
  virtual void TimerTick() {}

  void RegisterPhyLayer(std::shared_ptr<PhyLayer> phy);

  void UnregisterPhyLayers();

  void UnregisterPhyLayer(Phy::Type phy_type, uint32_t factory_id);

  virtual void IncomingPacket(model::packets::LinkLayerPacketView){};

  virtual void SendLinkLayerPacket(
      std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
      Phy::Type phy_type);

  virtual void SendLinkLayerPacket(model::packets::LinkLayerPacketView packet,
                                   Phy::Type phy_type);

  virtual void Close();

  void RegisterCloseCallback(std::function<void()>);

 protected:
  // List phy layers this device is listening on.
  std::vector<std::shared_ptr<PhyLayer>> phy_layers_;

  // Unique device address. Used as public device address for
  // Bluetooth activities.
  Address address_;

  // Callback to be invoked when this device is closed.
  std::function<void()> close_callback_;
};

}  // namespace rootcanal
