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
#include <optional>

#include "include/phy.h"  // for Phy, Phy::Type
#include "log.h"
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
  INFO("StartTimer()");
  timer_tick_task_ =
      schedule_periodic_task_(model_user_id_, std::chrono::milliseconds(0),
                              timer_period_, [this]() { TestModel::Tick(); });
}

void TestModel::StopTimer() {
  INFO("StopTimer()");
  cancel_task_(timer_tick_task_);
  timer_tick_task_ = kInvalidTaskId;
}

std::unique_ptr<PhyLayer> TestModel::CreatePhyLayer(PhyLayer::Identifier id,
                                                    Phy::Type type) {
  return std::make_unique<PhyLayer>(id, type);
}

std::shared_ptr<PhyDevice> TestModel::CreatePhyDevice(
    std::string type, std::shared_ptr<Device> device) {
  return std::make_shared<PhyDevice>(std::move(type), std::move(device));
}

Address TestModel::GenerateBluetoothAddress(uint32_t device_id) const {
  Address address({
      static_cast<uint8_t>(device_id),
      bluetooth_address_prefix_[4],
      bluetooth_address_prefix_[3],
      bluetooth_address_prefix_[2],
      bluetooth_address_prefix_[1],
      bluetooth_address_prefix_[0],
  });

  if (reuse_device_addresses_) {
    // Find the first unused address.
    for (uint16_t b0 = 0; b0 <= 0xff; b0++) {
      address.address[0] = b0;
      bool used = std::any_of(phy_devices_.begin(), phy_devices_.end(),
                              [address](auto& device) {
                                return device.second->GetAddress() == address;
                              });
      if (!used) {
        break;
      }
    }
  }

  return address;
}

// Add a device to the test model.
PhyDevice::Identifier TestModel::AddDevice(std::shared_ptr<Device> device) {
  std::string device_type = device->GetTypeString();
  std::shared_ptr<PhyDevice> phy_device =
      CreatePhyDevice(device_type, std::move(device));
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
  INFO(device->id_, "Adding a new link layer connection of type: {}",
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
    std::shared_ptr<HciDevice> device, std::optional<Address> address) {
  // clients can specify BD_ADDR or have it set based on device_id.
  device->SetAddress(address.value_or(GenerateBluetoothAddress(device->id_)));
  AddDevice(std::static_pointer_cast<Device>(device));

  INFO(device->id_, "Initialized device with address {}", device->GetAddress());

  for (auto& [_, phy_layer] : phy_layers_) {
    phy_layer->Register(phy_devices_[device->id_]);
  }

  PhyDevice::Identifier device_id = device->id_;
  AsyncUserId user_id = get_user_id_();
  device->RegisterCloseCallback([this, device_id, user_id] {
    schedule_task_(user_id, std::chrono::milliseconds(0),
                   [this, device_id, user_id]() {
                     OnConnectionClosed(device_id, user_id);
                   });
  });
  return device->id_;
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

void TestModel::SetDeviceConfiguration(PhyDevice::Identifier device_id,
                                       rootcanal::configuration::Controller const& configuration) {
  if (phy_devices_.find(device_id) != phy_devices_.end()) {
    if (phy_devices_[device_id]->GetDevice()->GetTypeString() == "hci_device") {
      std::shared_ptr<DualModeController> device = std::static_pointer_cast<HciDevice>(
          phy_devices_[device_id]->GetDevice());
      device->SetProperties(ControllerProperties(configuration));
    } else {
      ERROR(device_id, "failed to update the configuration, device is not a controller device");
    }
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
    INFO("Running Reset task");
    for (auto& [_, phy_layer] : phy_layers_) {
      phy_layer->UnregisterAll();
    }
    phy_devices_.clear();
  });
}

}  // namespace rootcanal
