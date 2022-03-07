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

#include "test_model.h"

#include <stdlib.h>  // for size_t

#include <iomanip>      // for operator<<, setfill
#include <iostream>     // for basic_ostream
#include <memory>       // for shared_ptr, make...
#include <type_traits>  // for remove_extent_t
#include <utility>      // for move

#include "include/phy.h"
#include "include/phy.h"  // for Phy, Phy::Type
#include "model/devices/hci_socket_device.h"
#include "model/devices/link_layer_socket_device.h"
#include "os/log.h"
// TODO: Remove when registration works
#include "model/devices/beacon.h"                    // for Beacon
#include "model/devices/beacon_swarm.h"              // for BeaconSwarm
#include "model/devices/car_kit.h"                   // for CarKit
#include "model/devices/classic.h"                   // for Classic
#include "model/devices/hci_socket_device.h"         // for HciSocketDevice
#include "model/devices/keyboard.h"                  // for Keyboard
#include "model/devices/link_layer_socket_device.h"  // for LinkLayerSocketD...
#include "model/devices/remote_loopback_device.h"    // for RemoteLoopbackDe...
#include "model/devices/scripted_beacon.h"           // for ScriptedBeacon
#include "model/devices/sniffer.h"                   // for Sniffer
#include "model/setup/phy_layer_factory.h"           // for PhyLayerFactory
#include "model/setup/test_channel_transport.h"      // for AsyncDataChannel
#include "net/async_data_channel.h"                  // for AsyncDataChannel
#include "os/log.h"                                  // for LOG_WARN, LOG_INFO
#include "packets/link_layer_packets.h"              // for LinkLayerPacketView

namespace rootcanal {
class Device;

TestModel::TestModel(
    std::function<AsyncUserId()> get_user_id,
    std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                              const TaskCallback&)>
        event_scheduler,

    std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                              std::chrono::milliseconds, const TaskCallback&)>
        periodic_event_scheduler,

    std::function<void(AsyncUserId)> cancel_tasks_from_user,
    std::function<void(AsyncTaskId)> cancel,
    std::function<std::shared_ptr<AsyncDataChannel>(const std::string&, int)>
        connect_to_remote)
    : get_user_id_(std::move(get_user_id)),
      schedule_task_(std::move(event_scheduler)),
      schedule_periodic_task_(std::move(periodic_event_scheduler)),
      cancel_task_(std::move(cancel)),
      cancel_tasks_from_user_(std::move(cancel_tasks_from_user)),
      connect_to_remote_(std::move(connect_to_remote)) {
  model_user_id_ = get_user_id_();
  // TODO: Remove when registration works!
  example_devices_.push_back(std::make_shared<Beacon>());
  example_devices_.push_back(std::make_shared<BeaconSwarm>());
  example_devices_.push_back(std::make_shared<Keyboard>());
  example_devices_.push_back(std::make_shared<CarKit>());
  example_devices_.push_back(std::make_shared<Classic>());
  example_devices_.push_back(std::make_shared<Sniffer>());
  example_devices_.push_back(std::make_shared<ScriptedBeacon>());
  example_devices_.push_back(std::make_shared<RemoteLoopbackDevice>());
}

void TestModel::SetTimerPeriod(std::chrono::milliseconds new_period) {
  timer_period_ = new_period;

  if (timer_tick_task_ == kInvalidTaskId) return;

  // Restart the timer with the new period
  StopTimer();
  StartTimer();
}

void TestModel::StartTimer() {
  LOG_INFO("StartTimer()");
  timer_tick_task_ = schedule_periodic_task_(
      model_user_id_, std::chrono::milliseconds(0), timer_period_,
      [this]() { TestModel::TimerTick(); });
}

void TestModel::StopTimer() {
  LOG_INFO("StopTimer()");
  cancel_task_(timer_tick_task_);
  timer_tick_task_ = kInvalidTaskId;
}

size_t TestModel::Add(std::shared_ptr<Device> new_dev) {
  devices_.push_back(std::move(new_dev));
  return devices_.size() - 1;
}

void TestModel::Del(size_t dev_index) {
  if (dev_index >= devices_.size() || devices_[dev_index] == nullptr) {
    LOG_WARN("Unknown device %zu", dev_index);
    return;
  }
  schedule_task_(model_user_id_, std::chrono::milliseconds(0),
                 [this, dev_index]() {
                   devices_[dev_index]->UnregisterPhyLayers();
                   devices_[dev_index] = nullptr;
                 });
}

size_t TestModel::AddPhy(Phy::Type phy_type) {
  size_t factory_id = phys_.size();
  phys_.emplace_back(phy_type, factory_id);
  return factory_id;
}

void TestModel::DelPhy(size_t phy_index) {
  if (phy_index >= phys_.size()) {
    LOG_WARN("Unknown phy at index %zu", phy_index);
    return;
  }
  schedule_task_(
      model_user_id_, std::chrono::milliseconds(0),
      [this, phy_index]() { phys_[phy_index].UnregisterAllPhyLayers(); });
}

void TestModel::AddDeviceToPhy(size_t dev_index, size_t phy_index) {
  if (dev_index >= devices_.size() || devices_[dev_index] == nullptr) {
    LOG_WARN("Unknown device %zu", dev_index);
    return;
  }
  if (phy_index >= phys_.size()) {
    LOG_WARN("Can't find phy %zu", phy_index);
    return;
  }
  auto dev = devices_[dev_index];
  dev->RegisterPhyLayer(phys_[phy_index].GetPhyLayer(
      [dev](model::packets::LinkLayerPacketView packet) {
        dev->IncomingPacket(std::move(packet));
      },
      dev_index));
}

void TestModel::DelDeviceFromPhy(size_t dev_index, size_t phy_index) {
  if (dev_index >= devices_.size() || devices_[dev_index] == nullptr) {
    LOG_WARN("Unknown device %zu", dev_index);
    return;
  }
  if (phy_index >= phys_.size()) {
    LOG_WARN("Can't find phy %zu", phy_index);
    return;
  }
  schedule_task_(model_user_id_, std::chrono::milliseconds(0),
                 [this, dev_index, phy_index]() {
                   devices_[dev_index]->UnregisterPhyLayer(
                       phys_[phy_index].GetType(),
                       phys_[phy_index].GetFactoryId());
                 });
}

void TestModel::AddLinkLayerConnection(std::shared_ptr<AsyncDataChannel> socket,
                                       Phy::Type phy_type) {
  LOG_INFO("Adding a new link layer connection of type: %s",
           phy_type == Phy::Type::BR_EDR ? "BR_EDR" : "LOW_ENERGY");
  std::shared_ptr<Device> dev = LinkLayerSocketDevice::Create(socket, phy_type);

  int index = Add(dev);
  AsyncUserId user_id = get_user_id_();

  for (size_t i = 0; i < phys_.size(); i++) {
    if (phy_type == phys_[i].GetType()) {
      AddDeviceToPhy(index, i);
    }
  }

  dev->RegisterCloseCallback([this, socket, index, user_id] {
    schedule_task_(user_id, std::chrono::milliseconds(0),
                   [this, socket, index, user_id]() {
                     OnConnectionClosed(socket, index, user_id);
                   });
  });
}

void TestModel::IncomingLinkLayerConnection(
    std::shared_ptr<AsyncDataChannel> socket) {
  LOG_INFO("A new link layer connection has arrived.");
  AddLinkLayerConnection(socket, Phy::Type::BR_EDR);
}

void TestModel::IncomingLinkBleLayerConnection(
    std::shared_ptr<AsyncDataChannel> socket) {
  LOG_INFO("A new low energery link layer (BLE) connection has arrived.");
  AddLinkLayerConnection(socket, Phy::Type::LOW_ENERGY);
}

void TestModel::AddRemote(const std::string& server, int port,
                          Phy::Type phy_type) {
  LOG_INFO("Connecting to %s:%d", server.c_str(), port);
  std::shared_ptr<AsyncDataChannel> socket = connect_to_remote_(server, port);
  if (!socket->Connected()) {
    return;
  }
  AddLinkLayerConnection(socket, phy_type);
}

void TestModel::IncomingHciConnection(std::shared_ptr<AsyncDataChannel> socket,
                                      std::string properties_filename) {
  auto dev = HciSocketDevice::Create(socket, properties_filename);
  size_t index = Add(std::static_pointer_cast<Device>(dev));
  std::string addr = "da:4c:10:de:17:";  // Da HCI dev
  std::stringstream stream;
  stream << std::setfill('0') << std::setw(2) << std::hex << (index % 256);
  addr += stream.str();

  dev->Initialize({"IgnoredTypeName", addr});
  LOG_INFO("initialized %s", addr.c_str());
  for (size_t i = 0; i < phys_.size(); i++) {
    AddDeviceToPhy(index, i);
  }
  AsyncUserId user_id = get_user_id_();
  dev->RegisterTaskScheduler([user_id, this](std::chrono::milliseconds delay,
                                             TaskCallback task_callback) {
    return schedule_task_(user_id, delay, std::move(task_callback));
  });
  dev->RegisterTaskCancel(cancel_task_);
  dev->RegisterCloseCallback([this, socket, index, user_id] {
    schedule_task_(user_id, std::chrono::milliseconds(0),
                   [this, socket, index, user_id]() {
                     OnConnectionClosed(socket, index, user_id);
                   });
  });
}

void TestModel::OnConnectionClosed(std::shared_ptr<AsyncDataChannel> socket,
                                   size_t index, AsyncUserId user_id) {
  if (index >= devices_.size() || devices_[index] == nullptr) {
    LOG_WARN("Unknown device %zu", index);
    return;
  }
  socket->Close();

  cancel_tasks_from_user_(user_id);
  devices_[index]->UnregisterPhyLayers();
  devices_[index] = nullptr;
}

void TestModel::SetDeviceAddress(size_t index, Address address) {
  if (index >= devices_.size() || devices_[index] == nullptr) {
    LOG_WARN("Can't find device %zu", index);
    return;
  }
  devices_[index]->SetAddress(std::move(address));
}

const std::string& TestModel::List() {
  list_string_ = "";
  list_string_ += " Devices: \r\n";
  for (size_t i = 0; i < devices_.size(); i++) {
    list_string_ += "  " + std::to_string(i) + ":";
    if (devices_[i] == nullptr) {
      list_string_ += " deleted \r\n";
    } else {
      list_string_ += devices_[i]->ToString() + " \r\n";
    }
  }
  list_string_ += " Phys: \r\n";
  for (size_t i = 0; i < phys_.size(); i++) {
    list_string_ += "  " + std::to_string(i) + ":";
    list_string_ += phys_[i].ToString() + " \r\n";
  }
  return list_string_;
}

void TestModel::TimerTick() {
  for (size_t i = 0; i < devices_.size(); i++) {
    if (devices_[i] != nullptr) {
      devices_[i]->TimerTick();
    }
  }
}

void TestModel::Reset() {
  StopTimer();
  schedule_task_(model_user_id_, std::chrono::milliseconds(0), [this]() {
    LOG_INFO("Running Reset task");
    for (size_t i = 0; i < devices_.size(); i++) {
      if (devices_[i] != nullptr) {
        devices_[i]->UnregisterPhyLayers();
      }
    }
    devices_.clear();
  });
}

}  // namespace rootcanal
