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

#include <memory>  // for shared_ptr, make_...

#include "model/hci/h4_data_channel_packetizer.h"  // for H4DataChannelP...
#include "model/hci/hci_transport.h"               // for HciTransport
#include "net/async_data_channel.h"                // for AsyncDataChannel

namespace rootcanal {

using android::net::AsyncDataChannel;

class HciSocketTransport : public HciTransport {
 public:
  HciSocketTransport(std::shared_ptr<AsyncDataChannel> socket);
  ~HciSocketTransport() = default;

  static std::shared_ptr<HciTransport> Create(
      std::shared_ptr<AsyncDataChannel> socket) {
    return std::make_shared<HciSocketTransport>(socket);
  }

  void SendEvent(const std::vector<uint8_t>& packet) override;

  void SendAcl(const std::vector<uint8_t>& packet) override;

  void SendSco(const std::vector<uint8_t>& packet) override;

  void SendIso(const std::vector<uint8_t>& packet) override;

  void RegisterCallbacks(PacketCallback command_callback,
                         PacketCallback acl_callback,
                         PacketCallback sco_callback,
                         PacketCallback iso_callback,
                         CloseCallback close_callback) override;

  void Tick() override;

  void Close() override;

 private:
  void SendHci(PacketType packet_type, const std::vector<uint8_t>& packet);

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
