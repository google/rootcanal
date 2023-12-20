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

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "hci/address.h"
#include "packets/link_layer_packets.h"
#include "phy.h"

namespace rootcanal {

using ::bluetooth::hci::Address;

// Represent a Bluetooth Device
//  - Provide Get*() and Set*() functions for device attributes.
class Device {
 public:
  // Unique device identifier.
  const uint32_t id_;

  Device();
  virtual ~Device() = default;

  // Return a string representation of the type of device.
  virtual std::string GetTypeString() const = 0;

  // Return the string representation of the device.
  virtual std::string ToString() const;

  // Set the device's Bluetooth address.
  void SetAddress(Address address) { address_.address = address.address; }

  // Get the device's Bluetooth address.
  const Address& GetAddress() const { return address_; }

  virtual void Tick() {}
  virtual void Close();

  virtual void ReceiveLinkLayerPacket(
      model::packets::LinkLayerPacketView /*packet*/, Phy::Type /*type*/,
      int8_t /*rssi*/) {}

  void SendLinkLayerPacket(
      std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
      Phy::Type type, int8_t tx_power = 0);

  void SendLinkLayerPacket(std::vector<uint8_t> const& packet, Phy::Type type,
                           int8_t tx_power = 0);

  void RegisterLinkLayerChannel(
      std::function<void(std::vector<uint8_t> const&, Phy::Type, int8_t)>
          send_ll);

  void RegisterCloseCallback(std::function<void()> close_callback);

 protected:
  // Unique device address. Used as public device address for
  // Bluetooth activities.
  Address address_;

  // Callback to be invoked when this device is closed.
  std::function<void()> close_callback_;

  // Callback function to send link layer packets.
  std::function<void(std::vector<uint8_t> const&, Phy::Type, uint8_t)> send_ll_;
};

}  // namespace rootcanal
