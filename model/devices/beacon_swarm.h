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

#include <memory>
#include <string>
#include <vector>

#include "model/devices/beacon.h"
#include "model/devices/device.h"

namespace rootcanal {

// Pretend to be a lot of beacons by changing the advertising address.
class BeaconSwarm : public Beacon {
 public:
  BeaconSwarm(const std::vector<std::string>& args);
  virtual ~BeaconSwarm() = default;

  static std::shared_ptr<Device> Create(const std::vector<std::string>& args) {
    return std::make_shared<BeaconSwarm>(args);
  }

  // Return a string representation of the type of device.
  virtual std::string GetTypeString() const override { return "beacon_swarm"; }

  virtual void Tick() override;

 private:
  static bool registered_;
};

}  // namespace rootcanal
