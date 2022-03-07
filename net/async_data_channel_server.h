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

#include <functional>
#include <memory>

#include "net/async_data_channel.h"

namespace android {
namespace net {

class AsyncDataChannelServer;

// Callback thas is called when a new client connection has been accepted.
using ConnectCallback = std::function<void(std::shared_ptr<AsyncDataChannel>,
                                           AsyncDataChannelServer* server)>;

// An AsyncDataChannelServer is capable of listening to incoming connections.
//
// A Callback will be invoked whenever a new connection has been accepted.
class AsyncDataChannelServer {
 public:
  // Destructor.
  virtual ~AsyncDataChannelServer() = default;

  // Start listening for new connections. The callback will be invoked
  // when a new socket has been accepted.
  //
  // errno will be set in case of failure.
  virtual bool StartListening() = 0;

  // Stop listening for new connections. The callback will not be
  // invoked, and sockets will not be accepted.
  //
  // This DOES not disconnect the server, and connections can still
  // be queued up.
  virtual void StopListening() = 0;

  // Disconnects the server, no new connections are possible.
  // The callback will never be invoked again.
  virtual void Close() = 0;

  // True if this server is connected and can accept incoming
  // connections.
  virtual bool Connected() = 0;

  // Registers the callback that should be invoked whenever a new socket was
  // accepted.
  //
  // Before the callback the server should have stopped listening for new
  // incoming connections. The callee is responsible for calling StartListening
  // if needed.
  void SetOnConnectCallback(const ConnectCallback& callback) {
    callback_ = callback;
  };

 protected:
  ConnectCallback callback_;
};

}  // namespace net
}  // namespace android
