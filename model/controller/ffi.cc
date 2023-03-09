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

#include "ffi.h"

#include <android-base/logging.h>

#include <iostream>

#include "dual_mode_controller.h"

using namespace rootcanal;
using bluetooth::hci::Address;

namespace hci {

enum Idc {
  CMD = 1,
  ACL,
  SCO,
  EVT,
  ISO,
};

__attribute__((constructor)) static void ConfigureLogging() {
  android::base::InitLogging({}, android::base::StdioLogger);
}

}  // namespace hci

extern "C" {

__attribute__((visibility("default"))) void* ffi_controller_new(
    uint8_t const address[6],
    void (*send_hci)(int idc, uint8_t const* data, size_t data_len),
    void (*send_ll)(uint8_t const* data, size_t data_len, int phy,
                    int tx_power)) {
  DualModeController* controller = new DualModeController();
  controller->SetAddress(Address({address[0], address[1], address[2],
                                  address[3], address[4], address[5]}));
  controller->RegisterEventChannel(
      [=](std::shared_ptr<std::vector<uint8_t>> data) {
        send_hci(hci::Idc::EVT, data->data(), data->size());
      });
  controller->RegisterAclChannel(
      [=](std::shared_ptr<std::vector<uint8_t>> data) {
        send_hci(hci::Idc::ACL, data->data(), data->size());
      });
  controller->RegisterScoChannel(
      [=](std::shared_ptr<std::vector<uint8_t>> data) {
        send_hci(hci::Idc::SCO, data->data(), data->size());
      });
  controller->RegisterIsoChannel(
      [=](std::shared_ptr<std::vector<uint8_t>> data) {
        send_hci(hci::Idc::ISO, data->data(), data->size());
      });
  controller->RegisterLinkLayerChannel(
      [=](std::vector<uint8_t> const& data, Phy::Type phy, int8_t tx_power) {
        send_ll(data.data(), data.size(), static_cast<int>(phy), tx_power);
      });

  return controller;
}

__attribute__((visibility("default"))) void ffi_controller_delete(
    void* controller_) {
  DualModeController* controller =
      reinterpret_cast<DualModeController*>(controller_);
  delete controller;
}

__attribute__((visibility("default"))) void ffi_controller_receive_hci(
    void* controller_, int idc, uint8_t const* data, size_t data_len) {
  DualModeController* controller =
      reinterpret_cast<DualModeController*>(controller_);
  std::shared_ptr<std::vector<uint8_t>> bytes =
      std::make_shared<std::vector<uint8_t>>(data, data + data_len);

  switch (idc) {
    case hci::Idc::CMD:
      controller->HandleCommand(bytes);
      break;
    case hci::Idc::ACL:
      controller->HandleAcl(bytes);
      break;
    case hci::Idc::SCO:
      controller->HandleSco(bytes);
      break;
    case hci::Idc::ISO:
      controller->HandleIso(bytes);
      break;
    default:
      std::cerr << "Dropping HCI packet with unknown type " << (int)idc
                << std::endl;
      break;
  }
}

__attribute__((visibility("default"))) void ffi_controller_receive_ll(
    void* controller_, uint8_t const* data, size_t data_len, int phy,
    int rssi) {
  DualModeController* controller =
      reinterpret_cast<DualModeController*>(controller_);
  std::shared_ptr<std::vector<uint8_t>> bytes =
      std::make_shared<std::vector<uint8_t>>(data, data + data_len);
  model::packets::LinkLayerPacketView packet =
      model::packets::LinkLayerPacketView::Create(
          bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian>(
              bytes));
  if (!packet.IsValid()) {
    std::cerr << "Dropping malformed LL packet" << std::endl;
    return;
  }
  controller->ReceiveLinkLayerPacket(packet, Phy::Type(phy), rssi);
}

__attribute__((visibility("default"))) void ffi_controller_tick(
    void* controller_) {
  DualModeController* controller =
      reinterpret_cast<DualModeController*>(controller_);
  controller->Tick();
}

__attribute__((visibility("default"))) void ffi_generate_rpa(
    uint8_t const irk_[16], uint8_t rpa[6]) {
  std::array<uint8_t, LinkLayerController::kIrkSize> irk;
  memcpy(irk.data(), irk_, LinkLayerController::kIrkSize);
  Address address = LinkLayerController::generate_rpa(irk);
  memcpy(rpa, address.data(), Address::kLength);
}

};  // extern "C"
