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

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "model/devices/device.h"
#include "packets/link_layer_packets.h"
#include "phy.h"

namespace rootcanal {

// Simple device that advertises with non-connectable advertising in general
// discoverable mode, and responds to LE scan requests.
class Beacon : public Device {
 public:
  Beacon();
  Beacon(const std::vector<std::string>& args);
  virtual ~Beacon() = default;

  static std::shared_ptr<Device> Create(const std::vector<std::string>& args) {
    return std::make_shared<Beacon>(args);
  }

  virtual std::string GetTypeString() const override { return "beacon"; }

  virtual void Tick() override;
  virtual void ReceiveLinkLayerPacket(
      model::packets::LinkLayerPacketView packet, Phy::Type type,
      int8_t rssi) override;

 protected:
  model::packets::LegacyAdvertisingType advertising_type_{};
  std::array<uint8_t, 31> advertising_data_{};
  std::array<uint8_t, 31> scan_response_data_{};
  std::chrono::steady_clock::duration advertising_interval_{};
  std::chrono::steady_clock::time_point advertising_last_{};

 private:
  static bool registered_;
};

}  // namespace rootcanal
