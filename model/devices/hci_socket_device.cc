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

#include "hci_socket_device.h"

#include <chrono>       // for milliseconds
#include <type_traits>  // for remove_extent_t

#include "model/devices/device_properties.h"  // for DeviceProperties
#include "os/log.h"                           // for LOG_INFO, LOG_ALWAYS_FATAL

using std::vector;

namespace rootcanal {

HciSocketDevice::HciSocketDevice(std::shared_ptr<AsyncDataChannel> socket,
                                 const std::string& properties_filename)
    : DualModeController(properties_filename), socket_(socket) {
  advertising_interval_ms_ = std::chrono::milliseconds(1000);

  page_scan_delay_ms_ = std::chrono::milliseconds(600);

  properties_.SetPageScanRepetitionMode(0);
  properties_.SetClassOfDevice(0x600420);
  properties_.SetExtendedInquiryData({
      16,  // length
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
      '_',
      'n',
      'e',
      't',
  });
  properties_.SetName({
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
      '_',
      'N',
      'e',
      't',
  });

  h4_ = H4DataChannelPacketizer(
      socket,
      [this](const std::vector<uint8_t>& raw_command) {
        std::shared_ptr<std::vector<uint8_t>> packet_copy =
            std::make_shared<std::vector<uint8_t>>(raw_command);
        HandleCommand(packet_copy);
      },
      [](const std::vector<uint8_t>&) {
        LOG_ALWAYS_FATAL("Unexpected Event in HciSocketDevice!");
      },
      [this](const std::vector<uint8_t>& raw_acl) {
        std::shared_ptr<std::vector<uint8_t>> packet_copy =
            std::make_shared<std::vector<uint8_t>>(raw_acl);
        HandleAcl(packet_copy);
      },
      [this](const std::vector<uint8_t>& raw_sco) {
        std::shared_ptr<std::vector<uint8_t>> packet_copy =
            std::make_shared<std::vector<uint8_t>>(raw_sco);
        HandleSco(packet_copy);
      },
      [this](const std::vector<uint8_t>& raw_iso) {
        std::shared_ptr<std::vector<uint8_t>> packet_copy =
            std::make_shared<std::vector<uint8_t>>(raw_iso);
        HandleIso(packet_copy);
      },
      [this]() {
        LOG_INFO("HCI socket device disconnected");
        Close();
      });

  RegisterEventChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    SendHci(PacketType::EVENT, packet);
  });
  RegisterAclChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    SendHci(PacketType::ACL, packet);
  });
  RegisterScoChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    SendHci(PacketType::SCO, packet);
  });
  RegisterIsoChannel([this](std::shared_ptr<std::vector<uint8_t>> packet) {
    SendHci(PacketType::ISO, packet);
  });
}

void HciSocketDevice::TimerTick() {
  h4_.OnDataReady(socket_);
  DualModeController::TimerTick();
}

void HciSocketDevice::SendHci(
    PacketType packet_type,
    const std::shared_ptr<std::vector<uint8_t>> packet) {
  if (!socket_ || !socket_->Connected()) {
    LOG_INFO("Closed socket. Dropping packet of type %d",
             static_cast<int>(packet_type));
    return;
  }
  uint8_t type = static_cast<uint8_t>(packet_type);
  h4_.Send(type, packet->data(), packet->size());
}

void HciSocketDevice::Close() {
  if (socket_) {
    socket_->Close();
  }
  DualModeController::Close();
}

}  // namespace rootcanal
