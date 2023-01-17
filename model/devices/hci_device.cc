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

#include "hci_device.h"

#include "log.h"

namespace rootcanal {

HciDevice::HciDevice(std::shared_ptr<HciTransport> transport,
                     const std::string& properties_filename)
    : DualModeController(properties_filename), transport_(transport) {
  link_layer_controller_.SetLocalName(std::vector<uint8_t>({
      'g',
      'D',
      'e',
      'v',
      'i',
      'c',
      'e',
      '-',
      'H',
      'C',
      'I',
  }));
  link_layer_controller_.SetExtendedInquiryResponse(std::vector<uint8_t>({
      12,  // Length
      9,   // Type: Device Name
      'g',
      'D',
      'e',
      'v',
      'i',
      'c',
      'e',
      '-',
      'h',
      'c',
      'i',
  }));

  RegisterEventChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    transport_->SendEvent(*packet);
  });
  RegisterAclChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    transport_->SendAcl(*packet);
  });
  RegisterScoChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    transport_->SendSco(*packet);
  });
  RegisterIsoChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    transport_->SendIso(*packet);
  });

  transport_->RegisterCallbacks(
      [this](const std::shared_ptr<std::vector<uint8_t>> command) {
        HandleCommand(command);
      },
      [this](const std::shared_ptr<std::vector<uint8_t>> acl) {
        HandleAcl(acl);
      },
      [this](const std::shared_ptr<std::vector<uint8_t>> sco) {
        HandleSco(sco);
      },
      [this](const std::shared_ptr<std::vector<uint8_t>> iso) {
        HandleIso(iso);
      },
      [this]() {
        LOG_INFO("HCI transport closed");
        Close();
      });
}

void HciDevice::Tick() {
  transport_->Tick();
  DualModeController::Tick();
}

void HciDevice::Close() {
  transport_->Close();
  DualModeController::Close();
}

}  // namespace rootcanal
