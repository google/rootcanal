/*
 * Copyright 2016 The Android Open Source Project
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

#include "model/setup/async_manager.h"

#include <fcntl.h>        // for fcntl, F_SETFL, O_NONBLOCK
#include <gtest/gtest.h>  // for Message, TestPartResult, SuiteApi...
#include <netdb.h>        // for gethostbyname, h_addr, hostent
#include <netinet/in.h>   // for sockaddr_in, in_addr, INADDR_ANY
#include <stdio.h>        // for printf
#include <sys/socket.h>   // for socket, AF_INET, accept, bind
#include <sys/types.h>    // for in_addr_t
#include <time.h>         // for NULL, size_t
#include <unistd.h>       // for close, write, read

#include <condition_variable>  // for condition_variable
#include <cstdint>             // for uint16_t
#include <cstring>             // for memset, strcmp, strcpy, strlen
#include <mutex>               // for mutex
#include <ratio>               // for ratio
#include <string>              // for string
#include <thread>
#include <tuple>  // for tuple

namespace rootcanal {

class Event {
 public:
  void set(bool set = true) {
    std::unique_lock<std::mutex> lk(m_);
    set_ = set;
    cv_.notify_all();
  }

  void reset() { set(false); }

  bool wait_for(std::chrono::microseconds timeout) {
    std::unique_lock<std::mutex> lk(m_);
    return cv_.wait_for(lk, timeout, [&] { return set_; });
  }

  bool operator*() { return set_; }

 private:
  std::mutex m_;
  std::condition_variable cv_;
  bool set_{false};
};

class AsyncManagerSocketTest : public ::testing::Test {
 public:
  static const uint16_t kPort = 6111;
  static const size_t kBufferSize = 16;

  bool CheckBufferEquals() {
    return strcmp(server_buffer_, client_buffer_) == 0;
  }

 protected:
  int StartServer() {
    struct sockaddr_in serv_addr = {};
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_FALSE(fd < 0);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(kPort);
    int reuse_flag = 1;
    EXPECT_FALSE(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_flag,
                            sizeof(reuse_flag)) < 0);
    EXPECT_FALSE(bind(fd, (sockaddr*)&serv_addr, sizeof(serv_addr)) < 0);

    listen(fd, 1);
    return fd;
  }

  int AcceptConnection(int fd) {
    struct sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(cli_addr));
    socklen_t clilen = sizeof(cli_addr);

    int connection_fd = accept(fd, (struct sockaddr*)&cli_addr, &clilen);
    EXPECT_FALSE(connection_fd < 0);

    return connection_fd;
  }

  std::tuple<int, int> ConnectSocketPair() {
    int cli = ConnectClient();
    WriteFromClient(cli);
    AwaitServerResponse(cli);
    int ser = connection_fd_;
    connection_fd_ = -1;
    return {cli, ser};
  }

  void ReadIncomingMessage(int fd) {
    int n;
    do {
      n = read(fd, server_buffer_, kBufferSize - 1);
    } while (n == -1 && errno == EAGAIN);

    if (n == 0 || errno == EBADF) {
      // Got EOF, or file descriptor disconnected.
      async_manager_.StopWatchingFileDescriptor(fd);
      close(fd);
    } else {
      ASSERT_GE(n, 0) << strerror(errno);
      n = write(fd, "1", 1);
    }
  }

  void SetUp() override {
    memset(server_buffer_, 0, kBufferSize);
    memset(client_buffer_, 0, kBufferSize);
    socket_fd_ = -1;
    connection_fd_ = -1;

    socket_fd_ = StartServer();

    async_manager_.WatchFdForNonBlockingReads(socket_fd_, [this](int fd) {
      connection_fd_ = AcceptConnection(fd);

      async_manager_.WatchFdForNonBlockingReads(
          connection_fd_, [this](int fd) { ReadIncomingMessage(fd); });
    });
  }

  void TearDown() override {
    async_manager_.StopWatchingFileDescriptor(socket_fd_);
    close(socket_fd_);
    close(connection_fd_);
    ASSERT_EQ(std::string_view(server_buffer_, kBufferSize),
              std::string_view(client_buffer_, kBufferSize));
  }

  int ConnectClient() {
    int socket_cli_fd = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(socket_cli_fd, 0) << strerror(errno);

    struct hostent* server;
    server = gethostbyname("localhost");
    EXPECT_FALSE(server == NULL) << strerror(errno);

    struct sockaddr_in serv_addr;
    memset((void*)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = *(reinterpret_cast<in_addr_t*>(server->h_addr));
    serv_addr.sin_port = htons(kPort);

    int result =
        connect(socket_cli_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    EXPECT_GE(result, 0) << strerror(errno);

    return socket_cli_fd;
  }

  void WriteFromClient(int socket_cli_fd) {
    strcpy(client_buffer_, "1");
    int n = write(socket_cli_fd, client_buffer_, strlen(client_buffer_));
    ASSERT_GT(n, 0) << strerror(errno);
  }

  void AwaitServerResponse(int socket_cli_fd) {
    int n = read(socket_cli_fd, client_buffer_, 1);
    ASSERT_GT(n, 0) << strerror(errno);
  }

 protected:
  AsyncManager async_manager_;
  int socket_fd_;
  int connection_fd_;
  char server_buffer_[kBufferSize];
  char client_buffer_[kBufferSize];
};

TEST_F(AsyncManagerSocketTest, TestOneConnection) {
  int socket_cli_fd = ConnectClient();

  WriteFromClient(socket_cli_fd);

  AwaitServerResponse(socket_cli_fd);

  close(socket_cli_fd);
}

TEST_F(AsyncManagerSocketTest, CanUnsubscribeInCallback) {
  using namespace std::chrono_literals;

  int socket_cli_fd = ConnectClient();
  WriteFromClient(socket_cli_fd);
  AwaitServerResponse(socket_cli_fd);
  fcntl(connection_fd_, F_SETFL, O_NONBLOCK);

  std::string data('x', 32);

  bool stopped = false;
  async_manager_.WatchFdForNonBlockingReads(connection_fd_, [&](int fd) {
    async_manager_.StopWatchingFileDescriptor(fd);
    char buf[32];
    while (read(fd, buf, sizeof(buf)) > 0)
      ;
    stopped = true;
  });

  while (!stopped) {
    write(socket_cli_fd, data.data(), data.size());
    std::this_thread::sleep_for(5ms);
  }

  SUCCEED();
  close(socket_cli_fd);
}

TEST_F(AsyncManagerSocketTest, CanUnsubscribeTaskFromWithinTask) {
  Event running;
  using namespace std::chrono_literals;
  async_manager_.ExecAsyncPeriodically(1, 1ms, 2ms, [&running, this]() {
    EXPECT_TRUE(async_manager_.CancelAsyncTask(1))
        << "We were scheduled, so cancel should return true";
    EXPECT_FALSE(async_manager_.CancelAsyncTask(1))
        << "We were not scheduled, so cancel should return false";
    running.set(true);
  });

  EXPECT_TRUE(running.wait_for(100ms));
}

TEST_F(AsyncManagerSocketTest, UnsubScribeWaitsUntilCompletion) {
  using namespace std::chrono_literals;
  Event running;
  std::atomic<bool> cancel_done = false;
  std::atomic<bool> task_complete = false;
  AsyncTaskId task_id = async_manager_.ExecAsyncPeriodically(
      1, 1ms, 2ms, [&running, &cancel_done, &task_complete]() {
        // Let the other thread now we are in the callback..
        running.set(true);
        // Wee bit of a hack that relies on timing..
        std::this_thread::sleep_for(20ms);
        EXPECT_FALSE(cancel_done.load())
            << "Task cancellation did not wait for us to complete!";
        task_complete.store(true);
      });

  EXPECT_TRUE(running.wait_for(100ms));
  auto start = std::chrono::system_clock::now();

  // There is a 20ms wait.. so we know that this should take some time.
  EXPECT_TRUE(async_manager_.CancelAsyncTask(task_id))
      << "We were scheduled, so cancel should return true";
  cancel_done.store(true);
  EXPECT_TRUE(task_complete.load())
      << "We managed to cancel a task while it was not yet finished.";
  auto end = std::chrono::system_clock::now();
  auto passed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  EXPECT_GT(passed_ms.count(), 10);
}

TEST_F(AsyncManagerSocketTest, NoEventsAfterUnsubscribe) {
  // This tests makes sure the AsyncManager never fires an event
  // after calling StopWatchingFileDescriptor.
  using clock = std::chrono::system_clock;
  using namespace std::chrono_literals;

  clock::time_point time_fast_called;
  clock::time_point time_slow_called;
  clock::time_point time_stopped_listening;

  int round = 0;
  auto [slow_cli_fd, slow_s_fd] = ConnectSocketPair();
  fcntl(slow_s_fd, F_SETFL, O_NONBLOCK);

  auto [fast_cli_fd, fast_s_fd] = ConnectSocketPair();
  fcntl(fast_s_fd, F_SETFL, O_NONBLOCK);

  std::string data(1, 'x');

  // The idea here is as follows:
  // We want to make sure that an unsubscribed callback never gets called.
  // This is to make sure we can safely do things like this:
  //
  // class Foo {
  //   Foo(int fd, AsyncManager* am) : fd_(fd), am_(am) {
  //     am_->WatchFdForNonBlockingReads(
  //         fd, [&](int fd) { printf("This shouldn't crash! %p\n", this); });
  //   }
  //   ~Foo() { am_->StopWatchingFileDescriptor(fd_); }
  //
  //   AsyncManager* am_;
  //   int fd_;
  // };
  //
  // We are going to force a failure as follows:
  //
  // The slow callback needs to be called first, if it does not we cannot
  // force failure, so we have to try multiple times.
  //
  // t1, is the thread doing the loop.
  // t2, is the async manager handler thread.
  //
  // t1 will block until the slowcallback.
  // t2 will now block (for at most 250 ms).
  // t1 will unsubscribe the fast callback.
  // 2 cases:
  //   with bug:
  //      - t1 takes a timestamp, unblocks t2,
  //      - t2 invokes the fast callback, and gets a timestamp.
  //      - Now the unsubscribe time is before the callback time.
  //   without bug.:
  //      - t1 locks un unsusbcribe in asyn manager
  //      - t2 unlocks due to timeout,
  //      - t2 invokes the fast callback, and gets a timestamp.
  //      - t1 is unlocked and gets a timestamp.
  //      - Now the unsubscribe time is after the callback time..

  do {
    Event unblock_slow, inslow, infast;
    time_fast_called = {};
    time_slow_called = {};
    time_stopped_listening = {};
    printf("round: %d\n", round++);

    // Register fd events
    async_manager_.WatchFdForNonBlockingReads(slow_s_fd, [&](int /*fd*/) {
      if (*inslow) return;
      time_slow_called = clock::now();
      printf("slow: %lld\n",
             time_slow_called.time_since_epoch().count() % 10000);
      inslow.set();
      unblock_slow.wait_for(25ms);
    });

    async_manager_.WatchFdForNonBlockingReads(fast_s_fd, [&](int /*fd*/) {
      if (*infast) return;
      time_fast_called = clock::now();
      printf("fast: %lld\n",
             time_fast_called.time_since_epoch().count() % 10000);
      infast.set();
    });

    // Generate fd events
    write(fast_cli_fd, data.data(), data.size());
    write(slow_cli_fd, data.data(), data.size());

    // Block in the right places.
    if (inslow.wait_for(25ms)) {
      async_manager_.StopWatchingFileDescriptor(fast_s_fd);
      time_stopped_listening = clock::now();
      printf("stop: %lld\n",
             time_stopped_listening.time_since_epoch().count() % 10000);
      unblock_slow.set();
    }

    infast.wait_for(25ms);

    // Unregister.
    async_manager_.StopWatchingFileDescriptor(fast_s_fd);
    async_manager_.StopWatchingFileDescriptor(slow_s_fd);
  } while (time_fast_called < time_slow_called);

  // fast before stop listening.
  ASSERT_LT(time_fast_called.time_since_epoch().count(),
            time_stopped_listening.time_since_epoch().count());

  // Cleanup
  close(fast_cli_fd);
  close(fast_s_fd);
  close(slow_cli_fd);
  close(slow_s_fd);
}

TEST_F(AsyncManagerSocketTest, TestRepeatedConnections) {
  static const int num_connections = 30;
  for (int i = 0; i < num_connections; i++) {
    int socket_cli_fd = ConnectClient();
    WriteFromClient(socket_cli_fd);
    AwaitServerResponse(socket_cli_fd);
    close(socket_cli_fd);
  }
}

TEST_F(AsyncManagerSocketTest, TestMultipleConnections) {
  static const int num_connections = 30;
  int socket_cli_fd[num_connections];
  for (int i = 0; i < num_connections; i++) {
    socket_cli_fd[i] = ConnectClient();
    ASSERT_TRUE(socket_cli_fd[i] > 0);
    WriteFromClient(socket_cli_fd[i]);
  }
  for (int i = 0; i < num_connections; i++) {
    AwaitServerResponse(socket_cli_fd[i]);
    close(socket_cli_fd[i]);
  }
}

class AsyncManagerTest : public ::testing::Test {
 public:
  AsyncManager async_manager_;
};

TEST_F(AsyncManagerTest, TestSetupTeardown) {}

TEST_F(AsyncManagerTest, TestCancelTask) {
  AsyncUserId user1 = async_manager_.GetNextUserId();
  bool task1_ran = false;
  bool* task1_ran_ptr = &task1_ran;
  AsyncTaskId task1_id =
      async_manager_.ExecAsync(user1, std::chrono::milliseconds(2),
                               [task1_ran_ptr]() { *task1_ran_ptr = true; });
  ASSERT_TRUE(async_manager_.CancelAsyncTask(task1_id));
  ASSERT_FALSE(task1_ran);
}

TEST_F(AsyncManagerTest, TestCancelLongTask) {
  AsyncUserId user1 = async_manager_.GetNextUserId();
  bool task1_ran = false;
  bool* task1_ran_ptr = &task1_ran;
  AsyncTaskId task1_id =
      async_manager_.ExecAsync(user1, std::chrono::milliseconds(2),
                               [task1_ran_ptr]() { *task1_ran_ptr = true; });
  bool task2_ran = false;
  bool* task2_ran_ptr = &task2_ran;
  AsyncTaskId task2_id =
      async_manager_.ExecAsync(user1, std::chrono::seconds(2),
                               [task2_ran_ptr]() { *task2_ran_ptr = true; });
  ASSERT_FALSE(task1_ran);
  ASSERT_FALSE(task2_ran);
  while (!task1_ran)
    ;
  ASSERT_FALSE(async_manager_.CancelAsyncTask(task1_id));
  ASSERT_FALSE(task2_ran);
  ASSERT_TRUE(async_manager_.CancelAsyncTask(task2_id));
}

TEST_F(AsyncManagerTest, TestCancelAsyncTasksFromUser) {
  AsyncUserId user1 = async_manager_.GetNextUserId();
  AsyncUserId user2 = async_manager_.GetNextUserId();
  bool task1_ran = false;
  bool* task1_ran_ptr = &task1_ran;
  bool task2_ran = false;
  bool* task2_ran_ptr = &task2_ran;
  bool task3_ran = false;
  bool* task3_ran_ptr = &task3_ran;
  bool task4_ran = false;
  bool* task4_ran_ptr = &task4_ran;
  bool task5_ran = false;
  bool* task5_ran_ptr = &task5_ran;
  AsyncTaskId task1_id =
      async_manager_.ExecAsync(user1, std::chrono::milliseconds(2),
                               [task1_ran_ptr]() { *task1_ran_ptr = true; });
  AsyncTaskId task2_id =
      async_manager_.ExecAsync(user1, std::chrono::seconds(2),
                               [task2_ran_ptr]() { *task2_ran_ptr = true; });
  AsyncTaskId task3_id =
      async_manager_.ExecAsync(user1, std::chrono::milliseconds(2),
                               [task3_ran_ptr]() { *task3_ran_ptr = true; });
  AsyncTaskId task4_id =
      async_manager_.ExecAsync(user1, std::chrono::seconds(2),
                               [task4_ran_ptr]() { *task4_ran_ptr = true; });
  AsyncTaskId task5_id =
      async_manager_.ExecAsync(user2, std::chrono::milliseconds(2),
                               [task5_ran_ptr]() { *task5_ran_ptr = true; });
  ASSERT_FALSE(task1_ran);
  while (!task1_ran || !task3_ran || !task5_ran)
    ;
  ASSERT_TRUE(task1_ran);
  ASSERT_FALSE(task2_ran);
  ASSERT_TRUE(task3_ran);
  ASSERT_FALSE(task4_ran);
  ASSERT_TRUE(task5_ran);
  async_manager_.CancelAsyncTasksFromUser(user1);
  ASSERT_FALSE(async_manager_.CancelAsyncTask(task1_id));
  ASSERT_FALSE(async_manager_.CancelAsyncTask(task2_id));
  ASSERT_FALSE(async_manager_.CancelAsyncTask(task3_id));
  ASSERT_FALSE(async_manager_.CancelAsyncTask(task4_id));
  ASSERT_FALSE(async_manager_.CancelAsyncTask(task5_id));
}

}  // namespace rootcanal
