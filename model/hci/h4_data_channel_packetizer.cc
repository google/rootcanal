//
// Copyright 2017 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "h4_data_channel_packetizer.h"

#include <string.h>  // for strerror, size_t
#include <unistd.h>  // for ssize_t

#include <cerrno>       // for errno, EAGAIN, ECONNRESET
#include <cstdint>      // for uint8_t
#include <functional>   // for function
#include <type_traits>  // for remove_extent_t
#include <utility>      // for move
#include <vector>       // for vector

#include "log.h"                     // for LOG_ERROR, LOG_ALWAYS_FATAL
#include "model/hci/h4_parser.h"     // for H4Parser, ClientDisconnectCa...
#include "model/hci/hci_protocol.h"  // for PacketReadCallback, AsyncDataChannel
#include "net/async_data_channel.h"  // for AsyncDataChannel

namespace rootcanal {

H4DataChannelPacketizer::H4DataChannelPacketizer(
    std::shared_ptr<AsyncDataChannel> socket, PacketReadCallback command_cb,
    PacketReadCallback event_cb, PacketReadCallback acl_cb,
    PacketReadCallback sco_cb, PacketReadCallback iso_cb,
    ClientDisconnectCallback disconnect_cb)
    : uart_socket_(socket),
      h4_parser_(command_cb, event_cb, acl_cb, sco_cb, iso_cb, true),
      disconnect_cb_(std::move(disconnect_cb)) {}

size_t H4DataChannelPacketizer::Send(uint8_t type, const uint8_t* data,
                                     size_t length) {
  ssize_t ret = uart_socket_->Send(&type, sizeof(type));
  if (ret == -1) {
    LOG_ERROR("Error writing to UART (%s)", strerror(errno));
  }
  size_t to_be_written = ret;

  ret = uart_socket_->Send(data, length);
  if (ret == -1) {
    LOG_ERROR("Error writing to UART (%s)", strerror(errno));
  }
  to_be_written += ret;

  if (to_be_written != length + sizeof(type)) {
    LOG_ERROR("%d / %d bytes written - something went wrong...",
              static_cast<int>(to_be_written),
              static_cast<int>(length + sizeof(type)));
  }
  return to_be_written;
}

void H4DataChannelPacketizer::OnDataReady(
    std::shared_ptr<AsyncDataChannel> socket) {
  ssize_t bytes_to_read = h4_parser_.BytesRequested();
  std::vector<uint8_t> buffer(bytes_to_read);

  ssize_t bytes_read = socket->Recv(buffer.data(), bytes_to_read);
  if (bytes_read == 0) {
    LOG_INFO("remote disconnected!");
    disconnected_ = true;
    disconnect_cb_();
    return;
  }
  if (bytes_read < 0) {
    if (errno == EAGAIN) {
      // No data, try again later.
      return;
    }
    if (errno == ECONNRESET) {
      // They probably rejected our packet
      disconnected_ = true;
      disconnect_cb_();
      return;
    }
    LOG_ALWAYS_FATAL("Read error in %u: %s", h4_parser_.CurrentState(),
                     strerror(errno));
  }
  h4_parser_.Consume(buffer.data(), bytes_read);
}

}  // namespace rootcanal
