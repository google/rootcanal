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

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <vector>

#include "model/controller/controller_properties.h"
#include "model/setup/async_manager.h"
#include "model/setup/test_channel_transport.h"
#include "model/setup/test_command_handler.h"
#include "model/setup/test_model.h"
#include "net/async_data_channel_server.h"

namespace android::net {
class AsyncDataChannel;
class AsyncDataChannelConnector;
}  // namespace android::net

namespace rootcanal {

using android::net::AsyncDataChannel;
using android::net::AsyncDataChannelConnector;
using android::net::AsyncDataChannelServer;
using android::net::ConnectCallback;

using rootcanal::AsyncManager;
using rootcanal::Device;
using rootcanal::Phy;

class TestEnvironment {
 public:
  TestEnvironment(
      std::function<std::shared_ptr<AsyncDataChannelServer>(AsyncManager*, int)>
          open_server,
      std::function<std::shared_ptr<AsyncDataChannelConnector>(AsyncManager*)>
          open_connector,
      int test_port, int hci_port, int link_port, int link_ble_port,
      std::string const& config_str,
      bool enable_hci_sniffer = false, bool enable_baseband_sniffer = false,
      bool enable_pcap_filter = false, bool disable_address_reuse = false);

  void initialize(std::promise<void> barrier);
  void close();

 private:
  rootcanal::AsyncManager async_manager_;
  rootcanal::TestChannelTransport test_channel_transport_;
  std::shared_ptr<AsyncDataChannelServer> test_socket_server_;
  std::vector<std::shared_ptr<AsyncDataChannelServer>> hci_socket_servers_;
  std::shared_ptr<AsyncDataChannelServer> link_socket_server_;
  std::shared_ptr<AsyncDataChannelServer> link_ble_socket_server_;
  std::shared_ptr<AsyncDataChannelConnector> connector_;
  bool enable_hci_sniffer_;
  bool enable_baseband_sniffer_;
  bool enable_pcap_filter_;
  bool test_channel_open_{false};
  std::promise<void> barrier_;
  rootcanal::AsyncUserId socket_user_id_{};

  void SetUpTestChannel();
  void SetUpHciServer(
      std::function<std::shared_ptr<AsyncDataChannelServer>(AsyncManager*, int)>
          open_server,
      int tcp_port, rootcanal::ControllerProperties properties);
  void SetUpLinkLayerServer();
  void SetUpLinkBleLayerServer();

  std::shared_ptr<Device> ConnectToRemoteServer(const std::string& server,
                                                int port, Phy::Type phy_type);

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

}  // namespace rootcanal
