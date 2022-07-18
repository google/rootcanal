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

#include <chrono>      // for milliseconds
#include <functional>  // for __base, function
#include <future>      // for promise
#include <memory>      // for shared_ptr, make_...
#include <string>      // for string

#include "model/controller/dual_mode_controller.h"  // for DualModeController
#include "model/setup/async_manager.h"              // for AsyncTaskId, Asyn...
#include "model/setup/test_channel_transport.h"     // for TestChannelTransport
#include "model/setup/test_command_handler.h"       // for TestCommandHandler
#include "model/setup/test_model.h"                 // for TestModel
#include "net/async_data_channel_server.h"          // for AsyncDataChannelS...

namespace android {
namespace net {
class AsyncDataChannel;
class AsyncDataChannelConnector;
}  // namespace net

namespace bluetooth {
namespace root_canal {

using android::net::AsyncDataChannel;
using android::net::AsyncDataChannelConnector;
using android::net::AsyncDataChannelServer;
using android::net::ConnectCallback;

using rootcanal::Device;
using rootcanal::Phy;

class TestEnvironment {
 public:
  TestEnvironment(std::shared_ptr<AsyncDataChannelServer> test_port,
                  std::shared_ptr<AsyncDataChannelServer> hci_server_port,
                  std::shared_ptr<AsyncDataChannelServer> link_server_port,
                  std::shared_ptr<AsyncDataChannelServer> link_ble_server_port,
                  std::shared_ptr<AsyncDataChannelConnector> connector,
                  const std::string& controller_properties_file = "",
                  const std::string& default_commands_file = "",
                  bool enable_hci_sniffer = false,
                  bool enable_baseband_sniffer = false)
      : test_socket_server_(test_port),
        hci_socket_server_(hci_server_port),
        link_socket_server_(link_server_port),
        link_ble_socket_server_(link_ble_server_port),
        connector_(connector),
        controller_properties_file_(controller_properties_file),
        default_commands_file_(default_commands_file),
        enable_hci_sniffer_(enable_hci_sniffer),
        enable_baseband_sniffer_(enable_baseband_sniffer),
        controller_(std::make_shared<rootcanal::DualModeController>(
            controller_properties_file)) {}

  void initialize(std::promise<void> barrier);

  void close();

 private:
  rootcanal::AsyncManager async_manager_;
  std::shared_ptr<AsyncDataChannelServer> test_socket_server_;
  std::shared_ptr<AsyncDataChannelServer> hci_socket_server_;
  std::shared_ptr<AsyncDataChannelServer> link_socket_server_;
  std::shared_ptr<AsyncDataChannelServer> link_ble_socket_server_;
  std::shared_ptr<AsyncDataChannelConnector> connector_;
  std::string controller_properties_file_;
  std::string default_commands_file_;
  bool enable_hci_sniffer_;
  bool enable_baseband_sniffer_;
  bool test_channel_open_{false};
  std::promise<void> barrier_;

  void SetUpTestChannel();
  void SetUpHciServer(ConnectCallback on_connect);
  void SetUpLinkLayerServer();
  void SetUpLinkBleLayerServer();
  std::shared_ptr<Device> ConnectToRemoteServer(const std::string& server,
                                                int port, Phy::Type phy_type);

  std::shared_ptr<rootcanal::DualModeController> controller_;

  rootcanal::TestChannelTransport test_channel_transport_;
  rootcanal::TestChannelTransport remote_hci_transport_;
  rootcanal::TestChannelTransport remote_link_layer_transport_;
  rootcanal::TestChannelTransport remote_link_ble_layer_transport_;

  rootcanal::TestModel test_model_{
      [this]() { return async_manager_.GetNextUserId(); },
      [this](rootcanal::AsyncUserId user_id, std::chrono::milliseconds delay,
             const rootcanal::TaskCallback& task) {
        return async_manager_.ExecAsync(user_id, delay, task);
      },

      [this](rootcanal::AsyncUserId user_id, std::chrono::milliseconds delay,
             std::chrono::milliseconds period,
             const rootcanal::TaskCallback& task) {
        return async_manager_.ExecAsyncPeriodically(user_id, delay, period,
                                                    task);
      },

      [this](rootcanal::AsyncUserId user) {
        async_manager_.CancelAsyncTasksFromUser(user);
      },

      [this](rootcanal::AsyncTaskId task) {
        async_manager_.CancelAsyncTask(task);
      },

      [this](const std::string& server, int port, Phy::Type phy_type) {
        return ConnectToRemoteServer(server, port, phy_type);
      }};

  rootcanal::TestCommandHandler test_channel_{test_model_};
};
}  // namespace root_canal
}  // namespace bluetooth
}  // namespace android
