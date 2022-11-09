
// Copyright (C) 2021 The Android Open Source Project
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
#pragma once
#include <chrono>
#include <string>

#include "net/async_data_channel.h"

namespace android {
namespace net {

using namespace std::chrono_literals;

// An AsyncDataChannelConnector is capable of connecting to a remote server.
class AsyncDataChannelConnector {
 public:
  virtual ~AsyncDataChannelConnector() = default;

  // Blocks and waits until a connection to the remote server has been
  // established, or a timeout has been reached. This function should
  // not return nullptr, but a DataChannel in disconnected state in case of
  // failure.
  //
  // In case of a disconnected DataChannel (socket->Connected() == false)
  // the errno variable can be set with the encountered error.
  virtual std::shared_ptr<AsyncDataChannel> ConnectToRemoteServer(
      const std::string& server, int port,
      std::chrono::milliseconds timeout = 5000ms) = 0;
};
}  // namespace net
}  // namespace android
