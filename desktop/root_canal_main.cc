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

// clang-format off
// This needs to be included before Backtrace.h to avoid a redefinition
// of DISALLOW_COPY_AND_ASSIGN
#include "log.h"
// clang-format on

#include <gflags/gflags.h>

#include <fstream>
#include <future>
#include <optional>
#include <cstdio>

#include "model/setup/async_manager.h"
#include "net/posix/posix_async_socket_connector.h"
#include "net/posix/posix_async_socket_server.h"
#include "test_environment.h"

using ::android::net::PosixAsyncSocketConnector;
using ::android::net::PosixAsyncSocketServer;
using rootcanal::AsyncManager;
using rootcanal::TestEnvironment;
using namespace rootcanal;

DEFINE_string(controller_properties_file, "", "deprecated");
DEFINE_string(configuration, "", "controller configuration (see config.proto)");
DEFINE_string(configuration_file, "",
              "controller configuration file path (see config.proto)");
DEFINE_string(default_commands_file, "", "deprecated");
DEFINE_bool(enable_log_color, false, "enable log colors");
DEFINE_bool(enable_hci_sniffer, false, "enable hci sniffer");
DEFINE_bool(enable_baseband_sniffer, false, "enable baseband sniffer");
DEFINE_bool(enable_pcap_filter, false, "enable PCAP filter");
DEFINE_bool(disable_address_reuse, false,
            "prevent rootcanal from reusing device addresses");
DEFINE_uint32(test_port, 6401, "test tcp port");
DEFINE_uint32(hci_port, 6402, "hci server tcp port");
DEFINE_uint32(link_port, 6403, "link server tcp port");
DEFINE_uint32(link_ble_port, 6404, "le link server tcp port");

int main(int argc, char** argv) {
  // always use line buffer mode so log messages are available when redirected
  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);

  gflags::ParseCommandLineFlags(&argc, &argv, true);
  rootcanal::log::SetLogColorEnable(FLAGS_enable_log_color);

  INFO("starting rootcanal");

  if (FLAGS_test_port > UINT16_MAX) {
    ERROR("test_port out of range: {}", FLAGS_test_port);
    return -1;
  }

  if (FLAGS_hci_port > UINT16_MAX) {
    ERROR("hci_port out of range: {}", FLAGS_hci_port);
    return -1;
  }

  if (FLAGS_link_port > UINT16_MAX) {
    ERROR("link_port out of range: {}", FLAGS_link_port);
    return -1;
  }

  if (FLAGS_link_ble_port > UINT16_MAX) {
    ERROR("link_ble_port out of range: {}", FLAGS_link_ble_port);
    return -1;
  }

  std::string configuration_str;
  if (!FLAGS_configuration.empty()) {
    configuration_str = FLAGS_configuration;
  } else if (!FLAGS_configuration_file.empty()) {
    std::ifstream file(FLAGS_configuration_file);
    std::stringstream buffer;
    buffer << file.rdbuf();
    configuration_str.assign(buffer.str());
  }

  TestEnvironment root_canal(
      [](AsyncManager* am, int port) {
        return std::make_shared<PosixAsyncSocketServer>(port, am);
      },
      [](AsyncManager* am) {
        return std::make_shared<PosixAsyncSocketConnector>(am);
      },
      static_cast<int>(FLAGS_test_port), static_cast<int>(FLAGS_hci_port),
      static_cast<int>(FLAGS_link_port), static_cast<int>(FLAGS_link_ble_port),
      configuration_str, FLAGS_enable_hci_sniffer,
      FLAGS_enable_baseband_sniffer, FLAGS_enable_pcap_filter,
      FLAGS_disable_address_reuse);

  std::promise<void> barrier;
  std::future<void> barrier_future = barrier.get_future();
  root_canal.initialize(std::move(barrier));
  barrier_future.wait();
  root_canal.close();
  return 0;
}
