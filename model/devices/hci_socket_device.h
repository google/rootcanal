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

#include <cstdint>     // for uint8_t
#include <functional>  // for __base, function
#include <memory>      // for shared_ptr, make_...
#include <string>      // for string
#include <vector>      // for vector

#include "model/controller/dual_mode_controller.h"     // for DualModeController
#include "model/devices/h4_data_channel_packetizer.h"  // for ClientDisconnectC...
#include "model/devices/hci_protocol.h"                // for PacketReadCallback
#include "net/async_data_channel.h"                    // for AsyncDataChannel

namespace rootcanal {

using android::net::AsyncDataChannel;

class HciSocketDevice : public DualModeController {
 public:
  HciSocketDevice(std::shared_ptr<AsyncDataChannel> socket,
                  const std::string& properties_filename);
  ~HciSocketDevice() = default;

  static std::shared_ptr<HciSocketDevice> Create(
      std::shared_ptr<AsyncDataChannel> socket,
      const std::string& properties_filename) {
    return std::make_shared<HciSocketDevice>(socket, properties_filename);
  }

  std::string GetTypeString() const override { return "hci_socket_device"; }

  void TimerTick() override;

  void SendHci(PacketType packet_type,
               const std::shared_ptr<std::vector<uint8_t>> packet);

  void Close() override;

 private:
  std::shared_ptr<AsyncDataChannel> socket_;
  H4DataChannelPacketizer h4_{socket_,
                              [](const std::vector<uint8_t>&) {},
                              [](const std::vector<uint8_t>&) {},
                              [](const std::vector<uint8_t>&) {},
                              [](const std::vector<uint8_t>&) {},
                              [](const std::vector<uint8_t>&) {},
                              [] {}};
};

}  // namespace rootcanal
