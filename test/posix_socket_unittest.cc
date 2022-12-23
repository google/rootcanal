
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
#include <errno.h>
#include <gtest/gtest.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <vector>

#include "log.h"  // for LOG_INFO
#include "model/setup/async_manager.h"
#include "net/posix/posix_async_socket_connector.h"
#include "net/posix/posix_async_socket_server.h"

namespace android {
namespace net {

using clock = std::chrono::system_clock;

class SigPipeSignalHandler {
 public:
  SigPipeSignalHandler() {
    sSignal = -1;
    struct sigaction act = {};
    act.sa_handler = myHandler;
    ::sigaction(SIGPIPE, &act, &mOldAction);
  }

  ~SigPipeSignalHandler() { ::sigaction(SIGPIPE, &mOldAction, nullptr); }

  int signaled() const { return sSignal; }

 private:
  struct sigaction mOldAction;

  static int sSignal;

  static void myHandler(int sig) { sSignal = sig; }
};

// static
int SigPipeSignalHandler::sSignal = 0;

using SocketCon = std::shared_ptr<AsyncDataChannel>;

class PosixSocketTest : public testing::Test {
 public:
  PosixSocketTest() : pasc_(&async_manager_), pass_(0, &async_manager_) {}

  ~PosixSocketTest() { pass_.Close(); }

  std::tuple<SocketCon, SocketCon> connectPair(
      std::chrono::milliseconds timeout = 500ms) {
    std::mutex m;
    std::condition_variable cv;

    std::shared_ptr<AsyncDataChannel> sock1;
    std::shared_ptr<AsyncDataChannel> sock2;

    pass_.SetOnConnectCallback(
        [&](std::shared_ptr<AsyncDataChannel> sock, AsyncDataChannelServer*) {
          std::unique_lock<std::mutex> guard(m);
          sock1 = std::move(sock);
          cv.notify_all();
        });
    EXPECT_TRUE(pass_.StartListening());

    sock2 = pasc_.ConnectToRemoteServer("localhost", pass_.port(), 1000ms);
    EXPECT_TRUE(sock2.get() != nullptr);
    EXPECT_TRUE(sock2->Connected());

    std::unique_lock<std::mutex> lk(m);
    EXPECT_TRUE(
        cv.wait_for(lk, timeout, [&] { return sock1.get() != nullptr; }));
    EXPECT_TRUE(sock1);
    EXPECT_TRUE(sock1->Connected());

    return {sock1, sock2};
  }

 protected:
  AsyncManager async_manager_;
  PosixAsyncSocketConnector pasc_;
  PosixAsyncSocketServer pass_;
};

TEST_F(PosixSocketTest, canConnect) {
  auto [sock1, sock2] = connectPair();
  ASSERT_TRUE(sock1->Connected());
  ASSERT_TRUE(sock2->Connected());

  sock1->Close();
  sock2->Close();

  ASSERT_FALSE(sock1->Connected());
  ASSERT_FALSE(sock2->Connected());
}

TEST_F(PosixSocketTest, socketSendDoesNotGenerateSigPipe) {
  // Check that writing to a broken pipe does not generate a SIGPIPE
  // signal.
  SigPipeSignalHandler handler;
  ASSERT_EQ(-1, handler.signaled());
  auto [sock1, sock2] = connectPair();

  // s1 and s2 are now connected. Close s1 immediately, then try to
  // send data through s2.
  sock1->Close();
  ASSERT_FALSE(sock1->Connected());
  // The EPIPE might not happen on the first send due to
  // TCP packet buffering in the kernel. Perform multiple send()
  // in a loop to work-around this.
  errno = 0;
  const int kMaxSendCount = 1000;
  int n = 0;
  while (n < kMaxSendCount) {
    int ret = sock2->Send((uint8_t*)"xxxx", 4);
    if (ret < 0) {
#ifdef __APPLE__
      // On OS X, errno is sometimes EPROTOTYPE instead of EPIPE
      // when this happens.
      ASSERT_TRUE(errno == EPIPE || errno == EPROTOTYPE) << strerror(errno);
#else
      ASSERT_EQ(EPIPE, errno) << strerror(errno);
#endif
      break;
    }
    n++;
  }

  // On MacOS you usually have n < 30
  ASSERT_LT(n, kMaxSendCount);

  // No signals were raised.
  ASSERT_EQ(-1, handler.signaled());
}

TEST_F(PosixSocketTest, can_send_data_around_poll) {
  auto [sock1, sock2] = connectPair();
  std::string word = "Hello World";
  std::string input = "           ";

  ASSERT_EQ(word.size(), input.size());
  ASSERT_NE(word, input);

  ssize_t snd = sock1->Send((uint8_t*)word.data(), word.size());
  ASSERT_EQ((ssize_t)word.size(), snd);

  uint8_t* buffer = (uint8_t*)input.data();
  int buflen = input.size();

  // Poll for at most 250ms.
  clock::time_point until = clock::now() + 250ms;
  do {
    int recv = sock2->Recv(buffer, buflen);
    if (recv > 0) {
      buflen -= recv;
      buffer += recv;
    }
  } while (buflen > 0 && clock::now() < until);

  ASSERT_EQ(word, input);
}

TEST_F(PosixSocketTest, data_results_in_read_event) {
  auto [sock1, sock2] = connectPair();
  std::mutex m;
  std::condition_variable cv;
  std::string word = "Hello World";
  std::string input = "           ";

  bool received = false;

  // Register a callback that only gets called once..
  sock2->WatchForNonBlockingRead([&](auto sock) {
    std::unique_lock<std::mutex> guard(m);
    received = true;
    // Unregister, to prevent surprises..
    sock->StopWatching();
    cv.notify_all();
  });

  ssize_t snd = sock1->Send((uint8_t*)word.data(), word.size());
  ASSERT_EQ((ssize_t)word.size(), snd);

  {
    std::unique_lock<std::mutex> lk(m);

    // The callback will be called within 250ms.
    ASSERT_TRUE(cv.wait_for(lk, 250ms, [&] { return received; }));

    uint8_t* buffer = (uint8_t*)input.data();
    int buflen = input.size();

    // At least 1 byte is coming in. (Note, we might get just a few
    // bytes. vs the whole thing as you never know what happens in the
    // ip stack.)
    ASSERT_GT(sock2->Recv(buffer, buflen), 0);
  }
}

TEST_F(PosixSocketTest, connectFails) {
  int port = pass_.port();

  // Close the port, we should not be able to connect
  pass_.Close();
  ASSERT_FALSE(pass_.Connected());

  // Max 250ms to go to nowhere...
  auto socket = pasc_.ConnectToRemoteServer("localhost", port, 250ms);
  ASSERT_FALSE(socket->Connected());
}

TEST_F(PosixSocketTest, canConnectMultiple) {
  int port = pass_.port();
  int CONNECTION_COUNT = 10;
  std::mutex m;
  std::condition_variable cv;
  std::vector<std::shared_ptr<AsyncDataChannel>> connections;
  bool connected = false;

  pass_.SetOnConnectCallback([&](std::shared_ptr<AsyncDataChannel> const& sock,
                                 AsyncDataChannelServer*) {
    std::unique_lock<std::mutex> guard(m);
    connections.push_back(sock);
    connected = true;
    ASSERT_TRUE(pass_.StartListening());
    cv.notify_all();
  });
  ASSERT_TRUE(pass_.StartListening());

  for (int i = 0; i < CONNECTION_COUNT; i++) {
    connected = false;
    auto socket = pasc_.ConnectToRemoteServer("localhost", port, 250ms);
    ASSERT_TRUE(socket->Connected());
    std::unique_lock<std::mutex> lk(m);
    ASSERT_TRUE(cv.wait_for(lk, 250ms, [&] { return connected; }));
    connected = false;
  }

  ASSERT_EQ(CONNECTION_COUNT, (int)connections.size());
}

TEST_F(PosixSocketTest, noConnectWhenNotCallingStart) {
  int port = pass_.port();
  std::mutex m;
  std::condition_variable cv;
  std::vector<std::shared_ptr<AsyncDataChannel>> connections;
  bool connected = false;

  pass_.SetOnConnectCallback(
      [&](std::shared_ptr<AsyncDataChannel> sock, AsyncDataChannelServer*) {
        std::unique_lock<std::mutex> guard(m);
        connections.push_back(sock);
        connected = true;
        cv.notify_all();
      });
  ASSERT_TRUE(pass_.StartListening());

  {
    connected = false;
    auto socket = pasc_.ConnectToRemoteServer("localhost", port, 250ms);
    ASSERT_TRUE(socket->Connected());
    std::unique_lock<std::mutex> lk(m);
    ASSERT_TRUE(cv.wait_for(lk, 250ms, [&] { return connected; }));
  }

  // After the first connection there was no call to startListening, and hence
  // no new sockets should be accepted.
  {
    connected = false;
    auto socket = pasc_.ConnectToRemoteServer("localhost", port, 250ms);

    // We should have a partial connection, so we don't know yet that it is not
    // working..
    ASSERT_TRUE(socket->Connected());
    std::unique_lock<std::mutex> lk(m);

    // Should timeout, as we never invoke the callback that accepts the socket.
    ASSERT_FALSE(cv.wait_for(lk, 250ms, [&] { return connected; }));
  }

  ASSERT_EQ(1, (int)connections.size());
}
}  // namespace net
}  // namespace android
