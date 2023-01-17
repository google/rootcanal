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

#include "hci_socket_transport.h"

#include "log.h"  // for LOG_INFO, LOG_ALWAYS_FATAL

namespace rootcanal {

HciSocketTransport::HciSocketTransport(std::shared_ptr<AsyncDataChannel> socket)
    : socket_(socket) {}

void HciSocketTransport::RegisterCallbacks(PacketCallback command_callback,
                                           PacketCallback acl_callback,
                                           PacketCallback sco_callback,
                                           PacketCallback iso_callback,
                                           CloseCallback close_callback) {
  // TODO: Avoid the copy here by using new buffer in H4DataChannel
  h4_ = H4DataChannelPacketizer(
      socket_,
      [command_callback](const std::vector<uint8_t>& raw_command) {
        std::shared_ptr<std::vector<uint8_t>> packet_copy =
            std::make_shared<std::vector<uint8_t>>(raw_command);
        command_callback(packet_copy);
      },
      [](const std::vector<uint8_t>&) {
        LOG_ALWAYS_FATAL("Unexpected Event in HciSocketTransport!");
      },
      [acl_callback](const std::vector<uint8_t>& raw_acl) {
        std::shared_ptr<std::vector<uint8_t>> packet_copy =
            std::make_shared<std::vector<uint8_t>>(raw_acl);
        acl_callback(packet_copy);
      },
      [sco_callback](const std::vector<uint8_t>& raw_sco) {
        std::shared_ptr<std::vector<uint8_t>> packet_copy =
            std::make_shared<std::vector<uint8_t>>(raw_sco);
        sco_callback(packet_copy);
      },
      [iso_callback](const std::vector<uint8_t>& raw_iso) {
        std::shared_ptr<std::vector<uint8_t>> packet_copy =
            std::make_shared<std::vector<uint8_t>>(raw_iso);
        iso_callback(packet_copy);
      },
      close_callback);
}

void HciSocketTransport::Tick() { h4_.OnDataReady(socket_); }

void HciSocketTransport::SendHci(PacketType packet_type,
                                 const std::vector<uint8_t>& packet) {
  if (!socket_ || !socket_->Connected()) {
    LOG_INFO("Closed socket. Dropping packet of type %d",
             static_cast<int>(packet_type));
    return;
  }
  uint8_t type = static_cast<uint8_t>(packet_type);
  h4_.Send(type, packet.data(), packet.size());
}

void HciSocketTransport::SendEvent(const std::vector<uint8_t>& packet) {
  SendHci(PacketType::EVENT, packet);
}

void HciSocketTransport::SendAcl(const std::vector<uint8_t>& packet) {
  SendHci(PacketType::ACL, packet);
}

void HciSocketTransport::SendSco(const std::vector<uint8_t>& packet) {
  SendHci(PacketType::SCO, packet);
}

void HciSocketTransport::SendIso(const std::vector<uint8_t>& packet) {
  SendHci(PacketType::ISO, packet);
}

void HciSocketTransport::Close() { socket_->Close(); }

}  // namespace rootcanal
