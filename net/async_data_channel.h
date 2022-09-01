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

#include <sys/types.h>

#include <cstdint>
#include <functional>
#include <memory>

#ifdef _WIN32
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h>
#endif

namespace android {
namespace net {

class AsyncDataChannel;

// Callback function that will be used to notify that new data
// can be read.
using ReadCallback = std::function<void(AsyncDataChannel*)>;

// A connected asynchronous socket abstraction.
//
// This is really a simple data channel that can be used to read and write
// data. Async Sockets are usually non-blocking posix/win sockets, but could be
// other types of datachannels (gRPC, qemu pipe)
class AsyncDataChannel {
 public:
  virtual ~AsyncDataChannel() = default;

  // Receive data in the given buffer. Properly handling EINTR where
  // applicable.
  //
  // Returns:
  // - >0: The number of bytes read.
  // -  0: The socket is closed, no further reads/write are possible
  // - <0: An error occurred. Details can be found in errno:
  //    -  EAGAIN: No data, try again later.
  //
  // Implementors should take care of translating EWOULDBLOCK into EAGAIN
  // if needed.
  virtual ssize_t Recv(uint8_t* buffer, uint64_t bufferSize) = 0;

  // Send data in the given buffer. Properly handling EINTR, EPIPE where
  // applicable.
  //
  // Returns:
  // - >0: The number of bytes written, this can be < bufferSize.
  // - <0: An error occurred. Details can be found in errno:
  //    - EAGAIN: The write would block, try again later.
  //    - EBADF: The connection is closed.
  //
  // Implementors should take care of translating EWOULDBLOCK into EAGAIN
  // if needed.
  virtual ssize_t Send(const uint8_t* buffer, uint64_t bufferSize) = 0;

  // True if this socket is connected
  virtual bool Connected() = 0;

  // Closes this socket. Upon return the following will hold:
  //
  // - No more ReadCallbacks will be invoked.
  // - Send/Recv calls will return 0.
  virtual void Close() = 0;

  // Registers the given callback to be invoked when a recv call can be made
  // to read data from this socket. The expectation is that a call to Recv will
  // not return EAGAIN. Returns false if registration of the watcher failed.
  //
  // Only one callback can be registered per socket.
  virtual bool WatchForNonBlockingRead(
      const ReadCallback& on_read_ready_callback) = 0;

  // Stops watching this socket, you will not receive any callbacks any longer.
  virtual void StopWatching() = 0;
};

}  // namespace net
}  // namespace android
