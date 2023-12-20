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

#include "desktop/test_environment.h"

#include <google/protobuf/text_format.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <ios>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "hci/pcap_filter.h"
#include "log.h"
#include "model/controller/controller_properties.h"
#include "model/devices/baseband_sniffer.h"
#include "model/devices/device.h"
#include "model/devices/hci_device.h"
#include "model/devices/link_layer_socket_device.h"
#include "model/hci/hci_sniffer.h"
#include "model/hci/hci_socket_transport.h"
#include "model/setup/async_manager.h"
#include "model/setup/test_channel_transport.h"
#include "net/async_data_channel.h"
#include "net/async_data_channel_connector.h"
#include "phy.h"
#include "rootcanal/configuration.pb.h"

namespace rootcanal {

using rootcanal::AsyncTaskId;
using rootcanal::BaseBandSniffer;
using rootcanal::HciDevice;
using rootcanal::HciSniffer;
using rootcanal::HciSocketTransport;
using rootcanal::LinkLayerSocketDevice;
using rootcanal::TaskCallback;

TestEnvironment::TestEnvironment(
    std::function<std::shared_ptr<AsyncDataChannelServer>(AsyncManager*, int)>
        open_server,
    std::function<std::shared_ptr<AsyncDataChannelConnector>(AsyncManager*)>
        open_connector,
    int test_port, int hci_port, int link_port, int link_ble_port,
    const std::string& config_str,
    bool enable_hci_sniffer, bool enable_baseband_sniffer,
    bool enable_pcap_filter, bool disable_address_reuse)
    : enable_hci_sniffer_(enable_hci_sniffer),
      enable_baseband_sniffer_(enable_baseband_sniffer),
      enable_pcap_filter_(enable_pcap_filter) {
  test_socket_server_ = open_server(&async_manager_, test_port);
  link_socket_server_ = open_server(&async_manager_, link_port);
  link_ble_socket_server_ = open_server(&async_manager_, link_ble_port);
  connector_ = open_connector(&async_manager_);
  test_model_.SetReuseDeviceAddresses(!disable_address_reuse);

  // Get a user ID for tasks scheduled within the test environment.
  socket_user_id_ = async_manager_.GetNextUserId();

  rootcanal::configuration::Configuration* config =
      new rootcanal::configuration::Configuration();
  if (!google::protobuf::TextFormat::ParseFromString(config_str, config) ||
      config->tcp_server_size() == 0) {
    // Default configuration with default hci port if the input
    // configuration cannot be used.
    SetUpHciServer(open_server, hci_port, rootcanal::ControllerProperties());
  } else {
    // Open an HCI server for all configurations requested by
    // the caller.
    int num_controllers = config->tcp_server_size();
    for (int index = 0; index < num_controllers; index++) {
      rootcanal::configuration::TcpServer const& tcp_server =
          config->tcp_server(index);
      SetUpHciServer(open_server, tcp_server.tcp_port(),
                     rootcanal::ControllerProperties(tcp_server.configuration()));
    }
  }
}

// Open an HCI server listening on the port `tcp_port`. Established connections
// are bound to a controller with the specified `properties`.
void TestEnvironment::SetUpHciServer(
    std::function<std::shared_ptr<AsyncDataChannelServer>(AsyncManager*, int)>
        open_server,
    int tcp_port, rootcanal::ControllerProperties properties) {
  INFO("Opening an HCI with port {}", tcp_port);

  std::shared_ptr<AsyncDataChannelServer> server =
      open_server(&async_manager_, tcp_port);
  server->SetOnConnectCallback([this, properties = std::move(properties)](
                                   std::shared_ptr<AsyncDataChannel> socket,
                                   AsyncDataChannelServer* server) {
    // AddHciConnection needs to be executed in task thread to
    // prevent data races on test model.
    async_manager_.ExecAsync(socket_user_id_, std::chrono::milliseconds(0),
                             [=]() {
      auto transport = HciSocketTransport::Create(socket);
      if (enable_hci_sniffer_) {
        transport = HciSniffer::Create(transport);
      }
      auto device = HciDevice::Create(transport, properties);
      test_model_.AddHciConnection(device);

      if (enable_hci_sniffer_) {
        auto filename = device->GetAddress().ToString() + ".pcap";
        for (auto i = 0; std::filesystem::exists(filename); i++) {
          filename =
              device->GetAddress().ToString() + "_" + std::to_string(i) + ".pcap";
        }
        auto file = std::make_shared<std::ofstream>(filename, std::ios::binary);
        auto sniffer = std::static_pointer_cast<HciSniffer>(transport);

        // Add PCAP output stream.
        sniffer->SetOutputStream(file);

        // Add a PCAP filter if the option is enabled.
        // TODO: ideally the filter should be shared between all transport
        // instances to use the same user information remapping between traces.
        if (enable_pcap_filter_) {
          sniffer->SetPcapFilter(std::make_shared<rootcanal::PcapFilter>());
        }
      }
    });

    server->StartListening();
  });
  hci_socket_servers_.emplace_back(std::move(server));
}

void TestEnvironment::initialize(std::promise<void> barrier) {
  INFO("Initialized barrier");

  barrier_ = std::move(barrier);

  test_channel_transport_.RegisterCommandHandler(
      [this](const std::string& name, const std::vector<std::string>& args) {
        async_manager_.ExecAsync(socket_user_id_, std::chrono::milliseconds(0),
                                 [this, name, args]() {
                                   if (name == "END_SIMULATION") {
                                     barrier_.set_value();
                                   } else {
                                     test_channel_.HandleCommand(name, args);
                                   }
                                 });
      });

  SetUpTestChannel();
  SetUpLinkLayerServer();
  SetUpLinkBleLayerServer();

  for (auto& server : hci_socket_servers_) {
    server->StartListening();
  }

  if (enable_baseband_sniffer_) {
    std::string filename = "baseband.pcap";
    for (auto i = 0; std::filesystem::exists(filename); i++) {
      filename = "baseband_" + std::to_string(i) + ".pcap";
    }

    test_model_.AddLinkLayerConnection(BaseBandSniffer::Create(filename),
                                       Phy::Type::BR_EDR);
  }

  INFO("{}: Finished", __func__);
}

void TestEnvironment::close() {
  INFO("{}", __func__);
  test_model_.Reset();
}

void TestEnvironment::SetUpLinkBleLayerServer() {
  link_ble_socket_server_->SetOnConnectCallback(
      [this](std::shared_ptr<AsyncDataChannel> socket,
             AsyncDataChannelServer* srv) {
        auto phy_type = Phy::Type::LOW_ENERGY;
        test_model_.AddLinkLayerConnection(
            LinkLayerSocketDevice::Create(socket, phy_type), phy_type);
        srv->StartListening();
      });
  link_ble_socket_server_->StartListening();
}

void TestEnvironment::SetUpLinkLayerServer() {
  link_socket_server_->SetOnConnectCallback(
      [this](std::shared_ptr<AsyncDataChannel> socket,
             AsyncDataChannelServer* srv) {
        auto phy_type = Phy::Type::BR_EDR;
        test_model_.AddLinkLayerConnection(
            LinkLayerSocketDevice::Create(socket, phy_type), phy_type);
        srv->StartListening();
      });
  link_socket_server_->StartListening();
}

std::shared_ptr<Device> TestEnvironment::ConnectToRemoteServer(
    const std::string& server, int port, Phy::Type phy_type) {
  auto socket = connector_->ConnectToRemoteServer(server, port);
  if (!socket->Connected()) {
    return nullptr;
  }
  return LinkLayerSocketDevice::Create(socket, phy_type);
}

void TestEnvironment::SetUpTestChannel() {
  bool transport_configured = test_channel_transport_.SetUp(
      test_socket_server_, [this](std::shared_ptr<AsyncDataChannel> conn_fd,
                                  AsyncDataChannelServer* server) {
        INFO("Test channel connection accepted.");
        server->StartListening();
        if (test_channel_open_) {
          WARNING("Only one connection at a time is supported");
          rootcanal::TestChannelTransport::SendResponse(
              conn_fd, "The connection is broken");
          return false;
        }
        test_channel_open_ = true;
        test_channel_.RegisterSendResponse(
            [conn_fd](const std::string& response) {
              rootcanal::TestChannelTransport::SendResponse(conn_fd, response);
            });

        conn_fd->WatchForNonBlockingRead([this](AsyncDataChannel* conn_fd) {
          test_channel_transport_.OnCommandReady(
              conn_fd, [this]() { test_channel_open_ = false; });
        });
        return false;
      });

  test_channel_.AddPhy({"BR_EDR"});
  test_channel_.AddPhy({"LOW_ENERGY"});
  test_channel_.AddDevice({"beacon", "be:ac:01:55:00:01", "1000"});
  test_channel_.AddDeviceToPhy({"0", "1"});
  test_channel_.AddDevice({"beacon", "be:ac:01:55:00:02", "1000"});
  test_channel_.AddDeviceToPhy({"1", "1"});
  test_channel_.SetTimerPeriod({"5"});
  test_channel_.StartTimer({});

  if (!transport_configured) {
    ERROR("Test channel SetUp failed.");
    return;
  }

  INFO("Test channel SetUp() successful");
}

}  // namespace rootcanal
