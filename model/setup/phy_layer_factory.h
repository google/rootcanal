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

#include "include/phy.h"
#include "packets/link_layer_packets.h"
#include "phy_layer.h"

namespace rootcanal {

class PhyLayerFactory {
  friend class PhyLayerImpl;

 public:
  PhyLayerFactory(Phy::Type phy_type, uint32_t factory_id);

  virtual ~PhyLayerFactory() = default;

  Phy::Type GetType() const;

  uint32_t GetFactoryId() const;

  std::shared_ptr<PhyLayer> GetPhyLayer(
      const std::function<void(model::packets::LinkLayerPacketView, int8_t)>&
          device_receive,
      uint32_t device_id);

  void UnregisterPhyLayer(uint32_t id);

  void UnregisterAllPhyLayers();

  virtual void TimerTick();

  virtual std::string ToString() const;

 protected:
  virtual void Send(
      std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
      uint32_t phy_id, uint32_t device_id, int8_t tx_power);
  virtual void Send(model::packets::LinkLayerPacketView packet, uint32_t phy_id,
                    uint32_t device_id, int8_t tx_power);
  std::list<std::shared_ptr<PhyLayer>> phy_layers_;

  // Compute the RSSI for a packet sent from one device to the other
  // with the specified TX power.
  virtual int8_t ComputeRssi(uint32_t sender_id, uint32_t receiver_id,
                             int8_t tx_power);

 private:
  Phy::Type phy_type_;
  uint32_t next_id_{1};
  const uint32_t factory_id_;
};

class PhyLayerImpl : public PhyLayer {
 public:
  PhyLayerImpl(Phy::Type phy_type, uint32_t id,
               const std::function<void(model::packets::LinkLayerPacketView,
                                        int8_t)>& device_receive,
               uint32_t device_id, PhyLayerFactory* factory);
  ~PhyLayerImpl() override;

  void Send(std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
            int8_t tx_power) override;
  void Send(model::packets::LinkLayerPacketView packet,
            int8_t tx_power) override;
  void Receive(model::packets::LinkLayerPacketView packet,
               int8_t rssi) override;
  void Unregister() override;
  bool IsFactoryId(uint32_t factory_id) override;
  void TimerTick() override;

 private:
  PhyLayerFactory* factory_;
};
}  // namespace rootcanal
