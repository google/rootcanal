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

#include <functional>
#include <vector>

#include "net/async_data_channel.h"

namespace rootcanal {

using PacketReadCallback = std::function<void(const std::vector<uint8_t>&)>;
using android::net::AsyncDataChannel;

// Implementation of HCI protocol bits common to different transports
class HciProtocol {
 public:
  HciProtocol() = default;
  virtual ~HciProtocol(){};

  // Protocol-specific implementation of sending packets.
  virtual size_t Send(uint8_t type, const uint8_t* data, size_t length) = 0;

 protected:
  static size_t WriteSafely(AsyncDataChannel* socket, const uint8_t* data,
                            size_t length);
};

}  // namespace rootcanal
