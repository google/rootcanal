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

#include "model/devices/hci_device.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "log.h"
#include "model/controller/controller_properties.h"
#include "model/controller/dual_mode_controller.h"
#include "model/hci/hci_transport.h"
#include "packets/link_layer_packets.h"

namespace rootcanal {

HciDevice::HciDevice(std::shared_ptr<HciTransport> transport,
                     ControllerProperties const& properties)
    : DualModeController(ControllerProperties(properties)),
      transport_(transport) {
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
    transport_->Send(PacketType::EVENT, *packet);
  });
  RegisterAclChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    transport_->Send(PacketType::ACL, *packet);
  });
  RegisterScoChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    transport_->Send(PacketType::SCO, *packet);
  });
  RegisterIsoChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    transport_->Send(PacketType::ISO, *packet);
  });

  transport_->RegisterCallbacks(
      [this](PacketType packet_type,
             const std::shared_ptr<std::vector<uint8_t>> packet) {
        switch (packet_type) {
          case PacketType::COMMAND:
            HandleCommand(packet);
            break;
          case PacketType::ACL:
            HandleAcl(packet);
            break;
          case PacketType::SCO:
            HandleSco(packet);
            break;
          case PacketType::ISO:
            HandleIso(packet);
            break;
          default:
            ASSERT(false);
            break;
        }
      },
      [this]() {
        INFO(id_, "HCI transport closed");
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
