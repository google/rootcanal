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
#include "model/devices/hci_device.h"          // for HciDevice
#include "model/setup/async_manager.h"         // for AsyncUserId, AsyncTaskId
#include "phy.h"                               // for Phy, Phy::Type
#include "phy_layer_factory.h"                 // for PhyLayerFactory

namespace rootcanal {
class Device;

using ::bluetooth::hci::Address;

class TestModel {
 public:
  TestModel(
      std::function<AsyncUserId()> get_user_id,
      std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                                const TaskCallback&)>
          event_scheduler,
      std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                                std::chrono::milliseconds, const TaskCallback&)>
          periodic_event_scheduler,
      std::function<void(AsyncUserId)> cancel_tasks_from_user,
      std::function<void(AsyncTaskId)> cancel,
      std::function<std::shared_ptr<Device>(const std::string&, int, Phy::Type)>
          connect_to_remote,
      std::array<uint8_t, 5> bluetooth_address_prefix = {0xda, 0x4c, 0x10, 0xde,
                                                         0x17});
  virtual ~TestModel();

  TestModel(TestModel& model) = delete;
  TestModel& operator=(const TestModel& model) = delete;

  // Commands:

  // Add a device, return its index
  size_t Add(std::shared_ptr<Device> device);

  // Remove devices by index
  void Del(size_t device_index);

  // Add phy, return its index
  size_t AddPhy(Phy::Type phy_type);

  // Allow derived classes to use custom phy layer
  virtual std::unique_ptr<PhyLayerFactory> CreatePhy(Phy::Type phy_type,
                                                     size_t factory_id);

  // Remove phy by index
  void DelPhy(size_t phy_index);

  // Add device to phy
  void AddDeviceToPhy(size_t device_index, size_t phy_index);

  // Remove device from phy
  void DelDeviceFromPhy(size_t device_index, size_t phy_index);

  // Handle incoming remote connections
  void AddLinkLayerConnection(std::shared_ptr<Device> dev, Phy::Type phy_type);
  // Add an HCI device, return its index
  size_t AddHciConnection(std::shared_ptr<HciDevice> dev);

  // Handle closed remote connections (both hci & link layer)
  void OnConnectionClosed(size_t index, AsyncUserId user_id);

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
  std::vector<std::unique_ptr<PhyLayerFactory>> phys_;
  std::vector<std::shared_ptr<Device>> devices_;
  std::string list_string_;

  // Prefix used to generate public device addresses for hosts
  // connecting over TCP.
  std::array<uint8_t, 5> bluetooth_address_prefix_;

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
  std::function<std::shared_ptr<Device>(const std::string&, int, Phy::Type)>
      connect_to_remote_;

  AsyncUserId model_user_id_;
  AsyncTaskId timer_tick_task_{kInvalidTaskId};
  std::chrono::milliseconds timer_period_{};
};

}  // namespace rootcanal
