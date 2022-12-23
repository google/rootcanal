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

#include <future>
#include <optional>

#include "model/setup/async_manager.h"
#include "net/posix/posix_async_socket_connector.h"
#include "net/posix/posix_async_socket_server.h"
#include "test_environment.h"

using ::android::bluetooth::root_canal::TestEnvironment;
using ::android::net::PosixAsyncSocketConnector;
using ::android::net::PosixAsyncSocketServer;
using rootcanal::AsyncManager;

DEFINE_string(controller_properties_file, "",
              "controller_properties.json file path");
DEFINE_string(default_commands_file, "",
              "commands file which root-canal runs it as default");
DEFINE_bool(enable_hci_sniffer, false, "enable hci sniffer");
DEFINE_bool(enable_baseband_sniffer, false, "enable baseband sniffer");

constexpr uint16_t kTestPort = 6401;
constexpr uint16_t kHciServerPort = 6402;
constexpr uint16_t kLinkServerPort = 6403;
constexpr uint16_t kLinkBleServerPort = 6404;

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
    LOG_ERROR("Process crashed, signal: %s[%d], tid: %d",
              strsignal(signal_number), signal_number, ctx->tid);
  } else {
    LOG_ERROR("Process crashed, signal: unknown, tid: unknown");
  }
  unwindstack::AndroidLocalUnwinder unwinder;
  unwindstack::AndroidUnwinderData data;
  if (!unwinder.Unwind(tid, data)) {
    LOG_ERROR("Unwind failed");
    return false;
  }
  LOG_ERROR("Backtrace:");
  for (const auto& frame : data.frames) {
    LOG_ERROR("%s", unwinder.FormatFrame(frame).c_str());
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
  android::base::InitLogging(argv);

  LOG_INFO("main");
  uint16_t test_port = kTestPort;
  uint16_t hci_server_port = kHciServerPort;
  uint16_t link_server_port = kLinkServerPort;
  uint16_t link_ble_server_port = kLinkBleServerPort;

  for (int arg = 0; arg < argc; arg++) {
    int port = (int)strtol(argv[arg], nullptr, 0);
    LOG_INFO("%d: %s (%d)", arg, argv[arg], port);
    if (port < 0 || port > 0xffff) {
      LOG_WARN("%s out of range", argv[arg]);
    } else {
      switch (arg) {
        case 0:  // executable name
          break;
        case 1:
          test_port = port;
          break;
        case 2:
          hci_server_port = port;
          break;
        case 3:
          link_server_port = port;
          break;
        case 4:
          link_ble_server_port = port;
          break;
        default:
          LOG_WARN("Ignored option %s", argv[arg]);
      }
    }
  }
  AsyncManager am;
  TestEnvironment root_canal(
      std::make_shared<PosixAsyncSocketServer>(test_port, &am),
      std::make_shared<PosixAsyncSocketServer>(hci_server_port, &am),
      std::make_shared<PosixAsyncSocketServer>(link_server_port, &am),
      std::make_shared<PosixAsyncSocketServer>(link_ble_server_port, &am),
      std::make_shared<PosixAsyncSocketConnector>(&am),
      FLAGS_controller_properties_file, FLAGS_default_commands_file,
      FLAGS_enable_hci_sniffer, FLAGS_enable_baseband_sniffer);
  std::promise<void> barrier;
  std::future<void> barrier_future = barrier.get_future();
  root_canal.initialize(std::move(barrier));
  barrier_future.wait();
  root_canal.close();
}
