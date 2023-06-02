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

#include <client/linux/handler/exception_handler.h>
#include <gflags/gflags.h>
#include <unwindstack/AndroidUnwinder.h>

#include <fstream>
#include <future>
#include <optional>

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

extern "C" const char* __asan_default_options() {
  return "detect_container_overflow=0";
}

bool crash_callback(const void* crash_context, size_t crash_context_size,
                    void* /* context */) {
  std::optional<pid_t> tid;
  if (crash_context_size >=
      sizeof(google_breakpad::ExceptionHandler::CrashContext)) {
    auto* ctx =
        static_cast<const google_breakpad::ExceptionHandler::CrashContext*>(
            crash_context);
    tid = ctx->tid;
    int signal_number = ctx->siginfo.si_signo;
    ERROR("Process crashed, signal: {}[{}], tid: {}", strsignal(signal_number),
          signal_number, ctx->tid);
  } else {
    ERROR("Process crashed, signal: unknown, tid: unknown");
  }
  unwindstack::AndroidLocalUnwinder unwinder;
  unwindstack::AndroidUnwinderData data;
  if (!unwinder.Unwind(tid, data)) {
    ERROR("Unwind failed");
    return false;
  }
  ERROR("Backtrace:");
  for (const auto& frame : data.frames) {
    ERROR("{}", unwinder.FormatFrame(frame));
  }
  return true;
}

int main(int argc, char** argv) {
  google_breakpad::MinidumpDescriptor descriptor(
      google_breakpad::MinidumpDescriptor::kMicrodumpOnConsole);
  google_breakpad::ExceptionHandler eh(descriptor, nullptr, nullptr, nullptr,
                                       true, -1);
  eh.set_crash_handler(crash_callback);

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
