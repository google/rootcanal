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
#include "net/posix/posix_async_socket.h"

#include <errno.h>       // for errno
#include <fcntl.h>       // for fcntl, FD_CLOEXEC, F_GETFL
#include <string.h>      // for strerror
#include <sys/socket.h>  // for getsockopt, send, MSG_NOSIGNAL
#include <unistd.h>      // for close, read

#include <functional>  // for __base

#include "log.h"                        // for LOG_INFO
#include "model/setup/async_manager.h"  // for AsyncManager

#ifdef _WIN32
#include "msvc-posix.h"
#endif

/* set  for very verbose debugging */
#ifndef DEBUG
#define DD(...) (void)0
#else
#define DD(...) LOG_INFO(__VA_ARGS__)
#endif

namespace android {
namespace net {

PosixAsyncSocket::PosixAsyncSocket(int fd, AsyncManager* am)
    : fd_(fd), am_(am), watching_(false) {
  int flags = fcntl(fd, F_GETFL);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  flags = fcntl(fd, F_GETFD);
  fcntl(fd, F_SETFD, flags | FD_CLOEXEC);

#ifdef SO_NOSIGPIPE
  // Disable SIGPIPE generation on Darwin.
  // When writing to a broken pipe, send() will return -1 and
  // set errno to EPIPE.
  flags = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (const char*)&flags, sizeof(flags));
#endif
}

PosixAsyncSocket::PosixAsyncSocket(PosixAsyncSocket&& other) {
  fd_ = other.fd_;
  watching_ = other.watching_.load();
  am_ = other.am_;

  other.fd_ = -1;
  other.watching_ = false;
}
PosixAsyncSocket::~PosixAsyncSocket() { Close(); }

ssize_t PosixAsyncSocket::Recv(uint8_t* buffer, uint64_t bufferSize) {
  if (fd_ == -1) {
    // Socket was closed locally.
    return 0;
  }

  errno = 0;
  ssize_t res = 0;
  REPEAT_UNTIL_NO_INTR(res = read(fd_, buffer, bufferSize));

  if (res < 0) {
    DD("Recv < 0: %s (%d)", strerror(errno), fd_);
  }
  DD("%zd bytes (%d)", res, fd_);
  return res;
};

ssize_t PosixAsyncSocket::Send(const uint8_t* buffer, uint64_t bufferSize) {
  errno = 0;
  ssize_t res = 0;
#ifdef MSG_NOSIGNAL
  // Prevent SIGPIPE generation on Linux when writing to a broken pipe.
  // ::send() will return -1/EPIPE instead.
  const int sendFlags = MSG_NOSIGNAL;
#else
  // For Darwin, this is handled by setting SO_NOSIGPIPE when creating
  // the socket.
  const int sendFlags = 0;
#endif

  REPEAT_UNTIL_NO_INTR(res = send(fd_, buffer, bufferSize, sendFlags));

  DD("%zd bytes (%d)", res, fd_);
  return res;
}

bool PosixAsyncSocket::Connected() {
  if (fd_ == -1) {
    return false;
  }
  char buf;
  if (recv(fd_, &buf, 1, MSG_PEEK | MSG_DONTWAIT) != 1) {
    DD("Recv not 1, could be connected: %s (%d)", strerror(errno), fd_);
    return errno == EAGAIN || errno == EWOULDBLOCK;
  }

  // We saw a byte in the queue, we are likely connected.
  return true;
}

void PosixAsyncSocket::Close() {
  if (fd_ == -1) {
    return;
  }

  StopWatching();

  // Clear out error
  int error_code = 0;
  socklen_t error_code_size = sizeof(error_code);
  getsockopt(fd_, SOL_SOCKET, SO_ERROR, reinterpret_cast<void*>(&error_code),
             &error_code_size);

  // shutdown sockets if possible,
  REPEAT_UNTIL_NO_INTR(shutdown(fd_, SHUT_RDWR));

  error_code = ::close(fd_);
  if (error_code == -1) {
    LOG_INFO("Failed to close: %s (%d)", strerror(errno), fd_);
  }
  LOG_INFO("(%d)", fd_);
  fd_ = -1;
}

bool PosixAsyncSocket::WatchForNonBlockingRead(
    const ReadCallback& on_read_ready_callback) {
  bool expected = false;
  if (watching_.compare_exchange_strong(expected, true)) {
    return am_->WatchFdForNonBlockingReads(
               fd_, [on_read_ready_callback, this](int /* fd */) {
                 on_read_ready_callback(this);
               }) == 0;
  }
  return false;
}

void PosixAsyncSocket::StopWatching() {
  bool expected = true;
  if (watching_.compare_exchange_strong(expected, false)) {
    am_->StopWatchingFileDescriptor(fd_);
  }
}
}  // namespace net
}  // namespace android
