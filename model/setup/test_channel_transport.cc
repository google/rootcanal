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

#include "test_channel_transport.h"

#include <errno.h>   // for errno, EBADF
#include <stddef.h>  // for size_t

#include <cstdint>      // for uint8_t
#include <cstring>      // for strerror
#include <type_traits>  // for remove_extent_t

#include "log.h"                     // for LOG_INFO, ASSERT_LOG, LOG_WARN
#include "net/async_data_channel.h"  // for AsyncDataChannel

using std::vector;

namespace rootcanal {

bool TestChannelTransport::SetUp(std::shared_ptr<AsyncDataChannelServer> server,
                                 ConnectCallback connection_callback) {
  socket_server_ = server;
  socket_server_->SetOnConnectCallback(connection_callback);
  socket_server_->StartListening();
  return socket_server_.get() != nullptr;
}

void TestChannelTransport::CleanUp() {
  socket_server_->StopListening();
  socket_server_->Close();
}

void TestChannelTransport::OnCommandReady(AsyncDataChannel* socket,
                                          std::function<void(void)> unwatch) {
  uint8_t command_name_size = 0;
  ssize_t bytes_read = socket->Recv(&command_name_size, 1);
  if (bytes_read != 1) {
    LOG_INFO("Unexpected (command_name_size) bytes_read: %zd != %d, %s",
             bytes_read, 1, strerror(errno));
    socket->Close();
  }
  vector<uint8_t> command_name_raw;
  command_name_raw.resize(command_name_size);
  bytes_read = socket->Recv(&command_name_raw[0], command_name_size);
  if (bytes_read != command_name_size) {
    LOG_INFO("Unexpected (command_name) bytes_read: %zd != %d, %s", bytes_read,
             command_name_size, strerror(errno));
  }
  std::string command_name(command_name_raw.begin(), command_name_raw.end());

  if (command_name == "CLOSE_TEST_CHANNEL" || command_name == "") {
    LOG_INFO("Test channel closed");
    unwatch();
    socket->Close();
    return;
  }

  uint8_t num_args = 0;
  bytes_read = socket->Recv(&num_args, 1);
  if (bytes_read != 1) {
    LOG_INFO("Unexpected (num_args) bytes_read: %zd != %d, %s", bytes_read, 1,
             strerror(errno));
  }
  vector<std::string> args;
  for (uint8_t i = 0; i < num_args; ++i) {
    uint8_t arg_size = 0;
    bytes_read = socket->Recv(&arg_size, 1);
    if (bytes_read != 1) {
      LOG_INFO("Unexpected (arg_size) bytes_read: %zd != %d, %s", bytes_read, 1,
               strerror(errno));
    }
    vector<uint8_t> arg;
    arg.resize(arg_size);
    bytes_read = socket->Recv(&arg[0], arg_size);
    if (bytes_read != arg_size) {
      LOG_INFO("Unexpected (arg) bytes_read: %zd != %d, %s", bytes_read,
               arg_size, strerror(errno));
    }
    args.push_back(std::string(arg.begin(), arg.end()));
  }

  command_handler_(command_name, args);
}

void TestChannelTransport::SendResponse(
    std::shared_ptr<AsyncDataChannel> socket,
    const std::string& response) const {
  size_t size = response.size();
  // Cap to 64K
  if (size > 0xffff) {
    size = 0xffff;
  }
  uint8_t size_buf[4] = {static_cast<uint8_t>(size & 0xff),
                         static_cast<uint8_t>((size >> 8) & 0xff),
                         static_cast<uint8_t>((size >> 16) & 0xff),
                         static_cast<uint8_t>((size >> 24) & 0xff)};
  ssize_t written = socket->Send(size_buf, 4);
  if (written == -1 && errno == EBADF) {
    LOG_WARN("Unable to send a response.  EBADF");
    return;
  }
  ASSERT_LOG(written == 4, "What happened? written = %zd errno = %d", written,
             errno);
  written =
      socket->Send(reinterpret_cast<const uint8_t*>(response.c_str()), size);
  ASSERT_LOG(written == static_cast<int>(size),
             "What happened? written = %zd errno = %d", written, errno);
}

void TestChannelTransport::RegisterCommandHandler(
    const std::function<void(const std::string&,
                             const std::vector<std::string>&)>& callback) {
  command_handler_ = callback;
}

}  // namespace rootcanal
