/*
 * Copyright 2015 The Android Open Source Project
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

#include <functional>  // for function
#include <memory>      // for shared_ptr
#include <string>      // for string
#include <vector>      // for vector

#include "net/async_data_channel.h"  // for AsyncDataChannel
#include "net/async_data_channel_server.h"  // for AsyncDataChannelServer (ptr only), Con...

namespace rootcanal {

using android::net::AsyncDataChannel;
using android::net::AsyncDataChannelServer;
using android::net::ConnectCallback;

// Manages communications between test channel and the controller. Mirrors the
// HciTransport for the test channel.
class TestChannelTransport {
 public:
  TestChannelTransport() {}

  ~TestChannelTransport() {}

  // Opens a port and returns and starts listening for incoming connections.
  bool SetUp(std::shared_ptr<AsyncDataChannelServer> server,
             ConnectCallback connection_callback);

  // Closes the port (if succesfully opened in SetUp).
  void CleanUp();

  // Sets the callback that fires when data is read in WatchFd().
  void RegisterCommandHandler(
      const std::function<void(const std::string&,
                               const std::vector<std::string>&)>& callback);

  // Send data back to the test channel.
  static void SendResponse(std::shared_ptr<AsyncDataChannel> socket,
                           const std::string& response);

  void OnCommandReady(AsyncDataChannel* socket,
                      std::function<void(void)> unwatch);

 private:
  std::function<void(const std::string&, const std::vector<std::string>&)>
      command_handler_;
  std::function<void(std::shared_ptr<AsyncDataChannel>)> connection_callback_;
  std::shared_ptr<AsyncDataChannelServer> socket_server_;

  TestChannelTransport(const TestChannelTransport& cmdPckt) = delete;
  TestChannelTransport& operator=(const TestChannelTransport& cmdPckt) = delete;
};

}  // namespace rootcanal
