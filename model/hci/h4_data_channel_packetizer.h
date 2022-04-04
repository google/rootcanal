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

#pragma once

#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t

#include <memory>  // for shared_ptr

#include "h4_parser.h"     // for ClientDisconnectCallback, H4Parser
#include "hci_protocol.h"  // for PacketReadCallback, AsyncDataChannel, HciProtocol
#include "net/async_data_channel.h"  // for AsyncDataChannel

namespace rootcanal {

using android::net::AsyncDataChannel;

// A socket based H4DataChannelPacketizer. Call OnDataReady whenever
// data can be read from the socket.
class H4DataChannelPacketizer : public HciProtocol {
 public:
  H4DataChannelPacketizer(std::shared_ptr<AsyncDataChannel> socket,
                          PacketReadCallback command_cb,
                          PacketReadCallback event_cb,
                          PacketReadCallback acl_cb, PacketReadCallback sco_cb,
                          PacketReadCallback iso_cb,
                          ClientDisconnectCallback disconnect_cb);

  size_t Send(uint8_t type, const uint8_t* data, size_t length) override;

  void OnDataReady(std::shared_ptr<AsyncDataChannel> socket);

 private:
  std::shared_ptr<AsyncDataChannel> uart_socket_;
  H4Parser h4_parser_;

  ClientDisconnectCallback disconnect_cb_;
  bool disconnected_{false};
};

}  // namespace rootcanal
