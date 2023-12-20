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

#include "test_command_handler.h"

#include <stdlib.h>

#include <fstream>
#include <memory>
#include <regex>

#include "device_boutique.h"
#include "log.h"
#include "phy.h"
#include "rootcanal/configuration.pb.h"

using std::vector;

namespace rootcanal {

static size_t ParseIntParam(std::string const& in) {
  return static_cast<size_t>(std::strtoul(in.c_str(), nullptr, 0));
}

TestCommandHandler::TestCommandHandler(TestModel& test_model)
    : model_(test_model) {
#define SET_HANDLER(command_name, method)                                     \
  active_commands_[command_name] = [this](const vector<std::string>& param) { \
    method(param);                                                            \
  };
  SET_HANDLER("add", AddDevice);
  SET_HANDLER("add_remote", AddRemote);
  SET_HANDLER("del", RemoveDevice);
  SET_HANDLER("add_phy", AddPhy);
  SET_HANDLER("del_phy", RemovePhy);
  SET_HANDLER("add_device_to_phy", AddDeviceToPhy);
  SET_HANDLER("del_device_from_phy", RemoveDeviceFromPhy);
  SET_HANDLER("list", List);
  SET_HANDLER("set_device_address", SetDeviceAddress);
  SET_HANDLER("set_device_configuration", SetDeviceConfiguration);
  SET_HANDLER("set_timer_period", SetTimerPeriod);
  SET_HANDLER("start_timer", StartTimer);
  SET_HANDLER("stop_timer", StopTimer);
  SET_HANDLER("reset", Reset);
#undef SET_HANDLER
  send_response_ = [](std::string const&) {};
}

void TestCommandHandler::AddDefaults() {
  // Add a phy for LE and one for BR/EDR
  AddPhy({"LOW_ENERGY"});
  AddPhy({"BR_EDR"});

  // Add the controller to the Phys
  AddDeviceToPhy({"1", "1"});
  AddDeviceToPhy({"1", "2"});

  // Add default test devices and add the devices to the phys
  //
  // Add({"beacon", "be:ac:10:00:00:01", "1000"});
  // AddDeviceToPhy({"2", "1"});
  //
  // Add({"sniffer", "ca:12:1c:17:00:01"});
  // AddDeviceToPhy({"3", "2"});
  //
  // Add({"sniffer", "3c:5a:b4:04:05:06"});
  // AddDeviceToPhy({"4", "2"});

  List({});

  SetTimerPeriod({"10"});
  StartTimer({});
}

void TestCommandHandler::HandleCommand(const std::string& name,
                                       const vector<std::string>& args) {
  if (active_commands_.count(name) == 0) {
    response_string_ = "Unhandled command: " + name;
    send_response_(response_string_);
    return;
  }
  active_commands_[name](args);
}

void TestCommandHandler::RegisterSendResponse(
    const std::function<void(const std::string&)> callback) {
  send_response_ = callback;
  send_response_("RegisterSendResponse called");
}

void TestCommandHandler::AddDevice(const vector<std::string>& args) {
  if (args.empty()) {
    response_string_ = "TestCommandHandler 'add' takes an argument";
    send_response_(response_string_);
    return;
  }
  std::shared_ptr<Device> new_dev = DeviceBoutique::Create(args);

  if (new_dev == NULL) {
    response_string_ = "TestCommandHandler 'add' " + args[0] + " failed!";
    send_response_(response_string_);
    WARNING("{}", response_string_);
    return;
  }

  INFO("Add {}", new_dev->ToString());
  size_t dev_index = model_.AddDevice(new_dev);
  response_string_ =
      std::to_string(dev_index) + std::string(":") + new_dev->ToString();
  send_response_(response_string_);
}

void TestCommandHandler::AddRemote(const vector<std::string>& args) {
  if (args.size() < 3) {
    response_string_ =
        "TestCommandHandler usage: add_remote host port phy_type";
    send_response_(response_string_);
    return;
  }

  size_t port = ParseIntParam(args[1]);
  Phy::Type phy_type = Phy::Type::BR_EDR;
  if ("LOW_ENERGY" == args[2]) {
    phy_type = Phy::Type::LOW_ENERGY;
  }
  if (port == 0 || port > 0xffff || args[0].size() < 2) {
    response_string_ = "TestCommandHandler bad arguments to 'add_remote': ";
    response_string_ += args[0];
    response_string_ += "@";
    response_string_ += args[1];
    send_response_(response_string_);
    return;
  }

  model_.AddRemote(args[0], port, phy_type);

  response_string_ = args[0] + std::string("@") + std::to_string(port);
  send_response_(response_string_);
}

void TestCommandHandler::RemoveDevice(const vector<std::string>& args) {
  size_t dev_index = ParseIntParam(args[0]);

  model_.RemoveDevice(dev_index);
  response_string_ = "TestCommandHandler 'del' called with device at index " +
                     std::to_string(dev_index);
  send_response_(response_string_);
}

void TestCommandHandler::AddPhy(const vector<std::string>& args) {
  if (args.size() != 1) {
    response_string_ = "TestCommandHandler 'add_phy' takes one argument";
  } else if (args[0] == "LOW_ENERGY") {
    model_.AddPhy(Phy::Type::LOW_ENERGY);
    response_string_ = "TestCommandHandler 'add_phy' called with LOW_ENERGY";
  } else if (args[0] == "BR_EDR") {
    model_.AddPhy(Phy::Type::BR_EDR);
    response_string_ = "TestCommandHandler 'add_phy' called with BR_EDR";
  } else {
    response_string_ =
        "TestCommandHandler 'add_phy' with unrecognized type " + args[0];
  }
  send_response_(response_string_);
}

void TestCommandHandler::RemovePhy(const vector<std::string>& args) {
  size_t phy_index = ParseIntParam(args[0]);

  model_.RemovePhy(phy_index);
  response_string_ = "TestCommandHandler 'del_phy' called with phy at index " +
                     std::to_string(phy_index);
  send_response_(response_string_);
}

void TestCommandHandler::AddDeviceToPhy(const vector<std::string>& args) {
  if (args.size() != 2) {
    response_string_ =
        "TestCommandHandler 'add_device_to_phy' takes two arguments";
    send_response_(response_string_);
    return;
  }
  size_t dev_index = ParseIntParam(args[0]);
  size_t phy_index = ParseIntParam(args[1]);
  model_.AddDeviceToPhy(dev_index, phy_index);
  response_string_ =
      "TestCommandHandler 'add_device_to_phy' called with device " +
      std::to_string(dev_index) + " and phy " + std::to_string(phy_index);
  send_response_(response_string_);
}

void TestCommandHandler::RemoveDeviceFromPhy(const vector<std::string>& args) {
  if (args.size() != 2) {
    response_string_ =
        "TestCommandHandler 'del_device_from_phy' takes two arguments";
    send_response_(response_string_);
    return;
  }
  size_t dev_index = ParseIntParam(args[0]);
  size_t phy_index = ParseIntParam(args[1]);
  model_.RemoveDeviceFromPhy(dev_index, phy_index);
  response_string_ =
      "TestCommandHandler 'del_device_from_phy' called with device " +
      std::to_string(dev_index) + " and phy " + std::to_string(phy_index);
  send_response_(response_string_);
}

void TestCommandHandler::List(const vector<std::string>& args) {
  if (!args.empty()) {
    INFO("Unused args: arg[0] = {}", args[0]);
    return;
  }
  send_response_(model_.List());
}

void TestCommandHandler::SetDeviceAddress(const vector<std::string>& args) {
  if (args.size() != 2) {
    response_string_ =
        "TestCommandHandler 'set_device_address' takes two arguments";
    send_response_(response_string_);
    return;
  }
  size_t device_id = ParseIntParam(args[0]);
  Address device_address{};
  Address::FromString(args[1], device_address);
  model_.SetDeviceAddress(device_id, device_address);
  response_string_ = "set_device_address " + args[0];
  response_string_ += " ";
  response_string_ += args[1];
  send_response_(response_string_);
}

void TestCommandHandler::SetDeviceConfiguration(const vector<std::string>& args) {
  if (args.size() != 2) {
    response_string_ =
        "TestCommandHandler 'set_device_configuration' takes two arguments";
    send_response_(response_string_);
    return;
  }
  size_t device_id = ParseIntParam(args[0]);
  rootcanal::configuration::ControllerPreset preset =
      rootcanal::configuration::ControllerPreset::DEFAULT;

  if (args[1] == "default") {
    preset = rootcanal::configuration::ControllerPreset::DEFAULT;
  } else if (args[1] == "laird_bl654") {
    preset = rootcanal::configuration::ControllerPreset::LAIRD_BL654;
  } else if (args[1] == "csr_rck_pts_dongle") {
    preset = rootcanal::configuration::ControllerPreset::CSR_RCK_PTS_DONGLE;
  } else {
    response_string_ =
        "TestCommandHandler 'set_device_configuration' invalid configuration preset";
    send_response_(response_string_);
    return;
  }

  rootcanal::configuration::Controller configuration;
  configuration.set_preset(preset);
  model_.SetDeviceConfiguration(device_id, configuration);
  response_string_ = "set_device_configuration " + args[0];
  response_string_ += " ";
  response_string_ += args[1];
  send_response_(response_string_);
}

void TestCommandHandler::SetTimerPeriod(const vector<std::string>& args) {
  if (args.size() != 1) {
    INFO("SetTimerPeriod takes 1 argument");
  }
  size_t period = ParseIntParam(args[0]);
  if (period != 0) {
    response_string_ = "set timer period to ";
    response_string_ += args[0];
    model_.SetTimerPeriod(std::chrono::milliseconds(period));
  } else {
    response_string_ = "invalid timer period ";
    response_string_ += args[0];
  }
  send_response_(response_string_);
}

void TestCommandHandler::StartTimer(const vector<std::string>& args) {
  if (!args.empty()) {
    INFO("Unused args: arg[0] = {}", args[0]);
  }
  model_.StartTimer();
  response_string_ = "timer started";
  send_response_(response_string_);
}

void TestCommandHandler::StopTimer(const vector<std::string>& args) {
  if (!args.empty()) {
    INFO("Unused args: arg[0] = {}", args[0]);
  }
  model_.StopTimer();
  response_string_ = "timer stopped";
  send_response_(response_string_);
}

void TestCommandHandler::Reset(const std::vector<std::string>& args) {
  if (!args.empty()) {
    INFO("Unused args: arg[0] = {}", args[0]);
  }
  model_.Reset();
  response_string_ = "model reset";
  send_response_(response_string_);
}

}  // namespace rootcanal
