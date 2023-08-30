//
// Copyright 2022 The Android Open Source Project
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

#include <functional>
#include <memory>
#include <vector>

#include "model/hci/h4.h"

namespace rootcanal {

using PacketCallback = std::function<void(
    PacketType, const std::shared_ptr<std::vector<uint8_t>>)>;
using CloseCallback = std::function<void()>;

class HciTransport {
 public:
  virtual ~HciTransport() = default;

  /// Send the input HCI packet with the selected H4 packet type.
  /// The packet data contains the H4 header but not the IDC byte.
  virtual void Send(PacketType packet_type,
                    std::vector<uint8_t> const& packet) = 0;

  /// Register the handler for received HCI packets.
  virtual void RegisterCallbacks(PacketCallback packet_callback,
                                 CloseCallback close_callback) = 0;

  virtual void Tick() = 0;
  virtual void Close() = 0;
};

}  // namespace rootcanal
