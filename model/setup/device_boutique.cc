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

#include "device_boutique.h"

#include "log.h"

using std::vector;

namespace rootcanal {

std::unordered_map<std::string, std::function<std::shared_ptr<Device>(
                                    const vector<std::string>&)>>&
DeviceBoutique::GetMap() {
  static std::unordered_map<std::string, std::function<std::shared_ptr<Device>(
                                             const vector<std::string>&)>>
      impl;
  return impl;
}

// Register a constructor for a device type.
bool DeviceBoutique::Register(
    const std::string& device_type,
    const std::function<std::shared_ptr<Device>(const vector<std::string>&)>
        method) {
  INFO("Registering {}", device_type);
  GetMap()[device_type] = method;
  return true;
}

std::shared_ptr<Device> DeviceBoutique::Create(
    const vector<std::string>& args) {
  ASSERT(!args.empty());

  auto device = GetMap().find(args[0]);

  if (device == GetMap().end()) {
    WARNING("No constructor registered for {}", args[0]);
    return std::shared_ptr<Device>(nullptr);
  }

  return device->second(args);
}

}  // namespace rootcanal
