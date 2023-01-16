/*
 * Copyright 2022 The Android Open Source Project
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

#include <android-base/logging.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "dual_mode_controller.h"

using namespace std::literals;
namespace py = pybind11;

namespace rootcanal {

namespace hci {
enum Type {
  CMD,
  EVT,
  ACL,
  SCO,
  ISO,
};
}  // namespace hci

// Overload the class DualModeController to implement
// SendLinkLayerPacket as forwarding packets to a registered handler.
class BaseController : public DualModeController {
 public:
  BaseController() {
    RegisterTaskScheduler(
        [this](std::chrono::milliseconds delay, TaskCallback const& task) {
          return this->async_manager_.ExecAsync(0, delay, task);
        });
    RegisterPeriodicTaskScheduler([this](std::chrono::milliseconds delay,
                                         std::chrono::milliseconds period,
                                         TaskCallback const& task) {
      return this->async_manager_.ExecAsyncPeriodically(0, delay, period, task);
    });
    RegisterTaskCancel([this](AsyncTaskId task_id) {
      this->async_manager_.CancelAsyncTask(task_id);
    });
  }
  ~BaseController() = default;

  void RegisterLLChannel(
      std::function<void(std::shared_ptr<std::vector<uint8_t>>)> const&
          send_ll) {
    send_ll_ = send_ll;
  }

  void Start() {
    if (timer_task_id_ == kInvalidTaskId) {
      timer_task_id_ = async_manager_.ExecAsyncPeriodically(
          0, 0ms, 5ms, [this]() { this->TimerTick(); });
    }
  }

  void Stop() {
    if (timer_task_id_ != kInvalidTaskId) {
      async_manager_.CancelAsyncTask(timer_task_id_);
      timer_task_id_ = kInvalidTaskId;
    }
  }

  virtual void SendLinkLayerPacket(
      std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
      Phy::Type /*phy_type*/, int8_t /*tx_power*/) override {
    auto bytes = std::make_shared<std::vector<uint8_t>>();
    bluetooth::packet::BitInserter inserter(*bytes);
    bytes->reserve(packet->size());
    packet->Serialize(inserter);
    send_ll_(bytes);
  }

 private:
  std::function<void(std::shared_ptr<std::vector<uint8_t>>)> send_ll_{};
  AsyncManager async_manager_{};
  AsyncTaskId timer_task_id_{kInvalidTaskId};

  BaseController(BaseController const&) = delete;
  DualModeController& operator=(BaseController const&) = delete;
};

PYBIND11_MODULE(lib_rootcanal_python3, m) {
  m.doc() = "RootCanal controller plugin";

  py::enum_<hci::Type>(m, "HciType")
      .value("Cmd", hci::Type::CMD)
      .value("Evt", hci::Type::EVT)
      .value("Acl", hci::Type::ACL)
      .value("Sco", hci::Type::SCO)
      .value("Iso", hci::Type::ISO);

  m.def(
      "generate_rpa",
      [](py::bytes arg) {
        std::string irk_str = arg;
        irk_str.resize(LinkLayerController::kIrkSize);

        std::array<uint8_t, LinkLayerController::kIrkSize> irk{};
        std::copy(irk_str.begin(), irk_str.end(), irk.begin());

        bluetooth::hci::Address rpa =
            rootcanal::LinkLayerController::generate_rpa(irk);
        // Python address representation keeps the same
        // byte order as the string representation, instead of using
        // little endian order.
        std::reverse(rpa.address.begin(), rpa.address.end());
        return rpa.address;
      },
      "Bluetooth RPA generation");

  py::class_<rootcanal::BaseController,
             std::shared_ptr<rootcanal::BaseController>>
      basic_controller(m, "BaseController");

  // Implement the constructor with two callback parameters to
  // handle emitted HCI packets and LL packets.
  basic_controller.def(py::init([](std::string address_str,
                                   py::object hci_handler,
                                   py::object ll_handler) {
    std::shared_ptr<BaseController> controller =
        std::make_shared<BaseController>();

    std::optional<bluetooth::hci::Address> address =
        bluetooth::hci::Address::FromString(address_str);
    if (address.has_value()) {
      controller->SetAddress(address.value());
    }
    controller->RegisterEventChannel(
        [=](std::shared_ptr<std::vector<uint8_t>> data) {
          pybind11::gil_scoped_acquire acquire;
          hci_handler(
              hci::Type::EVT,
              py::bytes(reinterpret_cast<char*>(data->data()), data->size()));
        });
    controller->RegisterAclChannel(
        [=](std::shared_ptr<std::vector<uint8_t>> data) {
          pybind11::gil_scoped_acquire acquire;
          hci_handler(
              hci::Type::ACL,
              py::bytes(reinterpret_cast<char*>(data->data()), data->size()));
        });
    controller->RegisterScoChannel(
        [=](std::shared_ptr<std::vector<uint8_t>> data) {
          pybind11::gil_scoped_acquire acquire;
          hci_handler(
              hci::Type::SCO,
              py::bytes(reinterpret_cast<char*>(data->data()), data->size()));
        });
    controller->RegisterIsoChannel(
        [=](std::shared_ptr<std::vector<uint8_t>> data) {
          pybind11::gil_scoped_acquire acquire;
          hci_handler(
              hci::Type::ISO,
              py::bytes(reinterpret_cast<char*>(data->data()), data->size()));
        });
    controller->RegisterLLChannel(
        [=](std::shared_ptr<std::vector<uint8_t>> data) {
          pybind11::gil_scoped_acquire acquire;
          ll_handler(
              py::bytes(reinterpret_cast<char*>(data->data()), data->size()));
        });
    return controller;
  }));

  // Timer interface.
  basic_controller.def("start", &BaseController::Start);
  basic_controller.def("stop", &BaseController::Stop);

  // Implement method BaseController.receive_hci which
  // injects HCI packets into the controller as if sent from the host.
  basic_controller.def(
      "send_hci", [](std::shared_ptr<rootcanal::BaseController> controller,
                     hci::Type typ, py::bytes data) {
        std::string data_str = data;
        std::shared_ptr<std::vector<uint8_t>> bytes =
            std::make_shared<std::vector<uint8_t>>(data_str.begin(),
                                                   data_str.end());

        switch (typ) {
          case hci::Type::CMD:
            controller->HandleCommand(bytes);
            break;
          case hci::Type::ACL:
            controller->HandleAcl(bytes);
            break;
          case hci::Type::SCO:
            controller->HandleSco(bytes);
            break;
          case hci::Type::ISO:
            controller->HandleIso(bytes);
            break;
          default:
            std::cerr << "Dropping HCI packet with unknown type " << typ
                      << std::endl;
            break;
        }
      });

  // Implement method BaseController.send_ll which
  // injects LL packets into the controller as if sent over the air.
  basic_controller.def(
      "send_ll", [](std::shared_ptr<rootcanal::BaseController> controller,
                    py::bytes data, int rssi) {
        std::string data_str = data;
        std::shared_ptr<std::vector<uint8_t>> bytes =
            std::make_shared<std::vector<uint8_t>>(data_str.begin(),
                                                   data_str.end());

        model::packets::LinkLayerPacketView packet =
            model::packets::LinkLayerPacketView::Create(
                bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian>(
                    bytes));
        if (!packet.IsValid()) {
          std::cerr << "Dropping malformed LL packet" << std::endl;
          return;
        }
        controller->IncomingPacket(std::move(packet), rssi);
      });
}

__attribute__((constructor)) static void ConfigureLogging() {
  android::base::InitLogging({}, android::base::StdioLogger);
}

}  // namespace rootcanal
