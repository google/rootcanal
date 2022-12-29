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
#include <fstream>

#include "device.h"

namespace rootcanal {

namespace bredr_bb {
namespace {
class BaseBandPacketBuilder;
}
}  // namespace bredr_bb

using ::bluetooth::hci::Address;

class BaseBandSniffer : public Device {
 public:
  BaseBandSniffer(const std::string& filename);
  ~BaseBandSniffer() = default;

  static std::shared_ptr<BaseBandSniffer> Create(const std::string& filename) {
    return std::make_shared<BaseBandSniffer>(filename);
  }

  // Return a string representation of the type of device.
  virtual std::string GetTypeString() const override {
    return "baseband_sniffer";
  }

  virtual void IncomingPacket(model::packets::LinkLayerPacketView packet,
                              int8_t rssi) override;

  virtual void TimerTick() override;

 private:
  void AppendRecord(std::unique_ptr<bredr_bb::BaseBandPacketBuilder> packet);
  std::ofstream output_;
};

}  // namespace rootcanal
