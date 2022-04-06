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
#include <vector>

#include "beacon.h"
#include "device.h"

namespace rootcanal {

class Keyboard : public Beacon {
 public:
  Keyboard(const std::vector<std::string>& args);
  virtual ~Keyboard() = default;

  static std::shared_ptr<Device> Create(const std::vector<std::string>& args) {
    return std::make_shared<Keyboard>(args);
  }

  // Return a string representation of the type of device.
  virtual std::string GetTypeString() const override;

  virtual void IncomingPacket(
      model::packets::LinkLayerPacketView packet) override;

  virtual void TimerTick() override;

 private:
  bool connected_{false};
  static bool registered_;
};
}  // namespace rootcanal
