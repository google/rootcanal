/*
 * Copyright 2018 The Android Open Source Project
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

#pragma once

#include <stddef.h>  // for size_t

#include <chrono>      // for milliseconds
#include <functional>  // for function
#include <memory>      // for shared_ptr
#include <string>      // for string
#include <vector>      // for vector

#include "hci/address.h"                       // for Address
#include "model/devices/device_properties.h"   // for Address
#include "model/setup/async_manager.h"         // for AsyncUserId, AsyncTaskId
#include "net/async_data_channel.h"            // for AsyncDataChannel
#include "net/async_data_channel_connector.h"  // for AsyncDataChannelConnector
#include "phy.h"                               // for Phy, Phy::Type
#include "phy_layer_factory.h"                 // for PhyLayerFactory
#include "test_channel_transport.h"            // for AsyncDataChannel

namespace rootcanal {
class Device;

using android::net::AsyncDataChannel;
using android::net::AsyncDataChannelConnector;

class TestModel {
 public:
  TestModel(
      std::function<AsyncUserId()> getNextUserId,
      std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                                const TaskCallback&)>
          evtScheduler,
      std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                                std::chrono::milliseconds, const TaskCallback&)>
          periodicEvtScheduler,
      std::function<void(AsyncUserId)> cancel_user_tasks,
      std::function<void(AsyncTaskId)> cancel,
      std::function<std::shared_ptr<AsyncDataChannel>(const std::string&, int)>
          connect_to_remote);
  ~TestModel() = default;

  TestModel(TestModel& model) = delete;
  TestModel& operator=(const TestModel& model) = delete;

  // Commands:

  // Add a device, return its index
  size_t Add(std::shared_ptr<Device> device);

  // Remove devices by index
  void Del(size_t device_index);

  // Add phy, return its index
  size_t AddPhy(Phy::Type phy_type);

  // Remove phy by index
  void DelPhy(size_t phy_index);

  // Add device to phy
  void AddDeviceToPhy(size_t device_index, size_t phy_index);

  // Remove device from phy
  void DelDeviceFromPhy(size_t device_index, size_t phy_index);

  // Handle incoming remote connections
  void AddLinkLayerConnection(std::shared_ptr<AsyncDataChannel> socket_fd,
                              Phy::Type phy_type);
  void IncomingLinkLayerConnection(std::shared_ptr<AsyncDataChannel> socket_fd);
  void IncomingLinkBleLayerConnection(
      std::shared_ptr<AsyncDataChannel> socket_fd);
  void IncomingHciConnection(std::shared_ptr<AsyncDataChannel> socket_fd,
                             std::string properties_filename = "");

  // Handle closed remote connections (both hci & link layer)
  void OnConnectionClosed(std::shared_ptr<AsyncDataChannel> socket_fd,
                          size_t index, AsyncUserId user_id);

  // Connect to a remote device
  void AddRemote(const std::string& server, int port, Phy::Type phy_type);

  // Set the device's Bluetooth address
  void SetDeviceAddress(size_t device_index, Address device_address);

  // Let devices know about the passage of time
  void TimerTick();
  void StartTimer();
  void StopTimer();
  void SetTimerPeriod(std::chrono::milliseconds new_period);

  // List the devices that the test knows about
  const std::string& List();

  // Clear all devices and phys.
  void Reset();

 private:
  std::vector<PhyLayerFactory> phys_;
  std::vector<std::shared_ptr<Device>> devices_;
  std::string list_string_;

  // Callbacks to schedule tasks.
  std::function<AsyncUserId()> get_user_id_;
  std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                            const TaskCallback&)>
      schedule_task_;
  std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                            std::chrono::milliseconds, const TaskCallback&)>
      schedule_periodic_task_;
  std::function<void(AsyncTaskId)> cancel_task_;
  std::function<void(AsyncUserId)> cancel_tasks_from_user_;
  std::function<std::shared_ptr<AsyncDataChannel>(const std::string&, int)>
      connect_to_remote_;

  AsyncUserId model_user_id_;
  AsyncTaskId timer_tick_task_{kInvalidTaskId};
  std::chrono::milliseconds timer_period_{};

  std::vector<std::shared_ptr<Device>> example_devices_;
  std::shared_ptr<AsyncDataChannelConnector> socket_connector_;
};

}  // namespace rootcanal
