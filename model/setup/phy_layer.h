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

#pragma once

#include <list>
#include <memory>
#include <vector>

#include "phy.h"
#include "phy_device.h"

namespace rootcanal {

using rootcanal::PhyDevice;

class PhyLayer {
 public:
  using Identifier = uint32_t;

  PhyLayer(Identifier id, Phy::Type type);
  virtual ~PhyLayer() {}

  void Tick();
  virtual void Send(std::vector<uint8_t> const& packet, int8_t tx_power,
                    PhyDevice::Identifier sender_id);

  // Compute the RSSI for a packet sent from one device to the other
  // with the specified TX power.
  virtual int8_t ComputeRssi(PhyDevice::Identifier sender_id,
                             PhyDevice::Identifier receiver_id,
                             int8_t tx_power);

  void Register(std::shared_ptr<PhyDevice> device);
  void Unregister(PhyDevice::Identifier device_id);
  void UnregisterAll();

  std::string ToString() const;

  // Id and type are public but immutable.
  const Identifier id;
  const Phy::Type type;

 protected:
  // List of devices currently connected to the phy.
  std::list<std::shared_ptr<rootcanal::PhyDevice>> phy_devices_;
};

}  // namespace rootcanal
