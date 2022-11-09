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
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "model/devices/device.h"

namespace rootcanal {

// Create customized devices from a centralized shop.
class DeviceBoutique {
 public:
  DeviceBoutique();
  virtual ~DeviceBoutique() = default;

  // Register a constructor for a device type.
  static bool Register(
      std::string const& device_type,
      std::function<std::shared_ptr<Device>(const std::vector<std::string>&)>
          method);

  // Call the function that matches arg[0] with args
  static std::shared_ptr<Device> Create(const std::vector<std::string>& args);

 private:
  static std::unordered_map<std::string, std::function<std::shared_ptr<Device>(
                                             const std::vector<std::string>&)>>&
  GetMap();
};

}  // namespace rootcanal
