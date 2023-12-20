/*
 * Copyright 2022 The Android Open Source Project
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

#include "model/controller/controller_properties.h"
#include "model/controller/dual_mode_controller.h"
#include "model/hci/hci_transport.h"

namespace rootcanal {

class HciDevice : public DualModeController {
 public:
  HciDevice(std::shared_ptr<HciTransport> transport,
            ControllerProperties const& properties);
  ~HciDevice() = default;

  static std::shared_ptr<HciDevice> Create(
      std::shared_ptr<HciTransport> transport,
      ControllerProperties const& properties) {
    return std::make_shared<HciDevice>(transport, properties);
  }

  std::string GetTypeString() const override { return "hci_device"; }

  void Tick() override;

  void Close() override;

 private:
  std::shared_ptr<HciTransport> transport_;
};

}  // namespace rootcanal
