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

#pragma once

#include <cstdint>
#include <unordered_set>

#include "model/devices/device.h"
#include "phy.h"

namespace rootcanal {

class PhyLayer;
class Device;

class PhyDevice {
 public:
  using Identifier = uint32_t;

  PhyDevice(std::string type, std::shared_ptr<Device> device);
  PhyDevice(PhyDevice &&) = delete;
  ~PhyDevice() = default;

  void Register(PhyLayer* phy);
  void Unregister(PhyLayer* phy);

  void Tick();
  void Receive(std::vector<uint8_t> const& packet, Phy::Type type, int8_t rssi);
  void Send(std::vector<uint8_t> const& packet, Phy::Type type,
            int8_t tx_power);

  bluetooth::hci::Address GetAddress() const;
  std::shared_ptr<Device> GetDevice() const;
  void SetAddress(bluetooth::hci::Address address);
  std::string ToString();

  // Id and type are public but immutable.
  const Identifier id;
  const std::string type;

 private:
  const std::shared_ptr<Device> device_;
  std::unordered_set<PhyLayer*> phy_layers_;
};

}  // namespace rootcanal
