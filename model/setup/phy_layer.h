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

#include "include/phy.h"
#include "packets/link_layer_packets.h"
namespace rootcanal {

class PhyLayer {
 public:
  PhyLayer(Phy::Type phy_type, uint32_t id,
           const std::function<void(model::packets::LinkLayerPacketView)>&
               device_receive,
           uint32_t device_id)
      : phy_type_(phy_type),
        id_(id),
        device_id_(device_id),
        transmit_to_device_(device_receive) {}

  virtual void Send(
      std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet) = 0;
  virtual void Send(model::packets::LinkLayerPacketView packet) = 0;

  virtual void Receive(model::packets::LinkLayerPacketView packet) = 0;

  virtual void TimerTick() = 0;

  virtual bool IsFactoryId(uint32_t factory_id) = 0;

  virtual void Unregister() = 0;

  Phy::Type GetType() { return phy_type_; }

  uint32_t GetId() { return id_; }

  uint32_t GetDeviceId() { return device_id_; }

  virtual ~PhyLayer() = default;

 private:
  Phy::Type phy_type_;
  uint32_t id_;
  uint32_t device_id_;

 protected:
  const std::function<void(model::packets::LinkLayerPacketView)>
      transmit_to_device_;
};

}  // namespace rootcanal
