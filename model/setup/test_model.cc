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
#include <optional>
#include <type_traits>  // for remove_extent_t
#include <utility>      // for move

#include "include/phy.h"  // for Phy, Phy::Type
#include "log.h"          // for LOG_WARN, LOG_INFO
#include "phy_layer.h"

namespace rootcanal {

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
    std::function<std::shared_ptr<Device>(const std::string&, int, Phy::Type)>
        connect_to_remote,
    std::array<uint8_t, 5> bluetooth_address_prefix)
    : bluetooth_address_prefix_(std::move(bluetooth_address_prefix)),
      get_user_id_(std::move(get_user_id)),
      schedule_task_(std::move(event_scheduler)),
      schedule_periodic_task_(std::move(periodic_event_scheduler)),
      cancel_task_(std::move(cancel)),
      cancel_tasks_from_user_(std::move(cancel_tasks_from_user)),
      connect_to_remote_(std::move(connect_to_remote)) {
  model_user_id_ = get_user_id_();
}

TestModel::~TestModel() {
  StopTimer();
}

void TestModel::SetTimerPeriod(std::chrono::milliseconds new_period) {
  timer_period_ = new_period;

  if (timer_tick_task_ == kInvalidTaskId) {
    return;
  }

  // Restart the timer with the new period
  StopTimer();
  StartTimer();
}

void TestModel::StartTimer() {
  LOG_INFO("StartTimer()");
  timer_tick_task_ =
      schedule_periodic_task_(model_user_id_, std::chrono::milliseconds(0),
                              timer_period_, [this]() { TestModel::Tick(); });
}

void TestModel::StopTimer() {
  LOG_INFO("StopTimer()");
  cancel_task_(timer_tick_task_);
  timer_tick_task_ = kInvalidTaskId;
}

std::unique_ptr<PhyLayer> TestModel::CreatePhyLayer(PhyLayer::Identifier id,
                                                    Phy::Type type) {
  return std::make_unique<PhyLayer>(id, type);
}

std::shared_ptr<PhyDevice> TestModel::CreatePhyDevice(
    PhyDevice::Identifier id, std::string type,
    std::shared_ptr<Device> device) {
  return std::make_shared<PhyDevice>(id, std::move(type), std::move(device));
}

// Add a device to the test model.
PhyDevice::Identifier TestModel::AddDevice(std::shared_ptr<Device> device) {
  std::optional<PhyDevice::Identifier> device_id{};
  if (reuse_device_ids_) {
    // Find the first unused identifier.
    // The identifier is used to generate the bluetooth address,
    // and reusing the first unused identifier lets a re-connecting
    // get the same identifier and address.
    for (PhyDevice::Identifier id = 0; id < next_device_id_; id++) {
      if (phy_devices_.count(id) == 0) {
        device_id = id;
        break;
      }
    }
  }

  if (!device_id.has_value()) {
    device_id = next_device_id_++;
  }

  std::string device_type = device->GetTypeString();
  std::shared_ptr<PhyDevice> phy_device =
      CreatePhyDevice(device_id.value(), device_type, std::move(device));
  phy_devices_[phy_device->id] = phy_device;
  return phy_device->id;
}

// Remove a device from the test model.
void TestModel::RemoveDevice(PhyDevice::Identifier device_id) {
  for (auto& [_, phy_layer] : phy_layers_) {
    phy_layer->Unregister(device_id);
  }
  phy_devices_.erase(device_id);
}

// Add a phy to the test model.
PhyLayer::Identifier TestModel::AddPhy(Phy::Type type) {
  static PhyLayer::Identifier next_id = 0;
  std::shared_ptr<PhyLayer> phy_layer = CreatePhyLayer(next_id++, type);
  phy_layers_[phy_layer->id] = phy_layer;
  return phy_layer->id;
}

// Remove a phy from the test model.
void TestModel::RemovePhy(PhyLayer::Identifier phy_id) {
  if (phy_layers_.find(phy_id) != phy_layers_.end()) {
    phy_layers_[phy_id]->UnregisterAll();
    phy_layers_.erase(phy_id);
  }
}

// Add the selected device to the selected phy.
void TestModel::AddDeviceToPhy(PhyDevice::Identifier device_id,
                               PhyLayer::Identifier phy_id) {
  if (phy_layers_.find(phy_id) != phy_layers_.end() &&
      phy_devices_.find(device_id) != phy_devices_.end()) {
    phy_layers_[phy_id]->Register(phy_devices_[device_id]);
  }
}

// Remove the selected device from the selected phy.
void TestModel::RemoveDeviceFromPhy(PhyDevice::Identifier device_id,
                                    PhyLayer::Identifier phy_id) {
  if (phy_layers_.find(phy_id) != phy_layers_.end()) {
    phy_layers_[phy_id]->Unregister(device_id);
  }
}

void TestModel::AddLinkLayerConnection(std::shared_ptr<Device> device,
                                       Phy::Type type) {
  LOG_INFO("Adding a new link layer connection of type: %s",
           type == Phy::Type::BR_EDR ? "BR_EDR" : "LOW_ENERGY");

  PhyDevice::Identifier device_id = AddDevice(device);

  for (auto& [_, phy_layer] : phy_layers_) {
    if (phy_layer->type == type) {
      phy_layer->Register(phy_devices_[device_id]);
    }
  }

  AsyncUserId user_id = get_user_id_();
  device->RegisterCloseCallback([this, device_id, user_id] {
    schedule_task_(user_id, std::chrono::milliseconds(0),
                   [this, device_id, user_id]() {
                     OnConnectionClosed(device_id, user_id);
                   });
  });
}

void TestModel::AddRemote(const std::string& server, int port, Phy::Type type) {
  auto device = connect_to_remote_(server, port, type);
  if (device == nullptr) {
    return;
  }
  AddLinkLayerConnection(device, type);
}

PhyDevice::Identifier TestModel::AddHciConnection(
    std::shared_ptr<HciDevice> device) {
  PhyDevice::Identifier device_id =
      AddDevice(std::static_pointer_cast<Device>(device));
  auto bluetooth_address = Address{{
      uint8_t(device_id),
      bluetooth_address_prefix_[4],
      bluetooth_address_prefix_[3],
      bluetooth_address_prefix_[2],
      bluetooth_address_prefix_[1],
      bluetooth_address_prefix_[0],
  }};
  device->SetAddress(bluetooth_address);

  LOG_INFO("Initialized device with address %s",
           bluetooth_address.ToString().c_str());

  for (auto& [_, phy_layer] : phy_layers_) {
    phy_layer->Register(phy_devices_[device_id]);
  }

  AsyncUserId user_id = get_user_id_();
  device->RegisterTaskScheduler([user_id, this](std::chrono::milliseconds delay,
                                                TaskCallback task_callback) {
    return schedule_task_(user_id, delay, std::move(task_callback));
  });
  device->RegisterTaskCancel(cancel_task_);
  device->RegisterCloseCallback([this, device_id, user_id] {
    schedule_task_(user_id, std::chrono::milliseconds(0),
                   [this, device_id, user_id]() {
                     OnConnectionClosed(device_id, user_id);
                   });
  });
  return device_id;
}

void TestModel::OnConnectionClosed(PhyDevice::Identifier device_id,
                                   AsyncUserId user_id) {
  if (phy_devices_.find(device_id) != phy_devices_.end()) {
    cancel_tasks_from_user_(user_id);
    RemoveDevice(device_id);
  }
}

void TestModel::SetDeviceAddress(PhyDevice::Identifier device_id,
                                 Address address) {
  if (phy_devices_.find(device_id) != phy_devices_.end()) {
    phy_devices_[device_id]->SetAddress(std::move(address));
  }
}

const std::string& TestModel::List() {
  list_string_.clear();
  list_string_ += " Devices: \r\n";

  for (auto const& [device_id, device] : phy_devices_) {
    list_string_ += "  " + std::to_string(device_id) + ":";
    list_string_ += device->ToString() + " \r\n";
  }

  list_string_ += " Phys: \r\n";

  for (auto const& [phy_id, phy] : phy_layers_) {
    list_string_ += "  " + std::to_string(phy_id) + ":";
    list_string_ += phy->ToString() + " \r\n";
  }

  return list_string_;
}

void TestModel::Tick() {
  for (auto& [_, device] : phy_devices_) {
    device->Tick();
  }
}

void TestModel::Reset() {
  StopTimer();
  schedule_task_(model_user_id_, std::chrono::milliseconds(0), [this]() {
    LOG_INFO("Running Reset task");
    for (auto& [_, phy_layer] : phy_layers_) {
      phy_layer->UnregisterAll();
    }
    phy_devices_.clear();
    next_device_id_ = 0;
  });
}

}  // namespace rootcanal
