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

#include <cstdint>
#include <vector>

#include "device.h"
#include "hci/address.h"
#include "packets/link_layer_packets.h"

namespace rootcanal {

using ::bluetooth::hci::Address;

class Sniffer : public Device {
 public:
  Sniffer(const std::vector<std::string>& args);
  ~Sniffer() = default;

  static std::shared_ptr<Sniffer> Create(const std::vector<std::string>& args) {
    return std::make_shared<Sniffer>(args);
  }

  virtual std::string GetTypeString() const override { return "sniffer"; }

  virtual void ReceiveLinkLayerPacket(
      model::packets::LinkLayerPacketView packet, Phy::Type type,
      int8_t rssi) override;

 private:
  static bool registered_;
};

}  // namespace rootcanal
