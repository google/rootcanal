/*
 * Copyright 2021 The Android Open Source Project
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

#include "hci_sniffer.h"

#include <chrono>
#include <limits>

using namespace std::literals;

namespace rootcanal {

void HciSniffer::Open(const char* filename) {
  output_.open(filename, std::ios::binary);

  // https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.xml#file-header
  uint32_t magic_number = 0xa1b2c3d4;
  uint16_t major_version = 2;
  uint16_t minor_version = 4;
  uint32_t reserved1 = 0;
  uint32_t reserved2 = 0;
  uint32_t snaplen = std::numeric_limits<uint32_t>::max();
  uint32_t linktype = 201;  // http://www.tcpdump.org/linktypes.html
                            // LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR

  output_.write((char*)&magic_number, 4);
  output_.write((char*)&major_version, 2);
  output_.write((char*)&minor_version, 2);
  output_.write((char*)&reserved1, 4);
  output_.write((char*)&reserved2, 4);
  output_.write((char*)&snaplen, 4);
  output_.write((char*)&linktype, 4);
}

void HciSniffer::AppendRecord(PacketDirection packet_direction,
                              PacketType packet_type,
                              const std::vector<uint8_t>& packet) {
  auto time = std::chrono::steady_clock::now() - start_;

  // https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.xml#rfc.section.5
  uint32_t seconds = time / 1s;
  uint32_t microseconds = (time % 1s) / 1ms;
  uint32_t captured_packet_length = 4 + 1 + packet.size();
  uint32_t original_packet_length = captured_packet_length;

  // http://www.tcpdump.org/linktypes.html LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR
  uint32_t direction = static_cast<uint32_t>(packet_direction);
  uint8_t idc = static_cast<uint8_t>(packet_type);

  output_.write((char*)&seconds, 4);
  output_.write((char*)&microseconds, 4);
  output_.write((char*)&captured_packet_length, 4);
  output_.write((char*)&original_packet_length, 4);
  output_.write((char*)&direction, 4);
  output_.write((char*)&idc, 1);
  output_.write((char*)packet.data(), packet.size());
}

void HciSniffer::RegisterCallbacks(PacketCallback command_callback,
                                   PacketCallback acl_callback,
                                   PacketCallback sco_callback,
                                   PacketCallback iso_callback,
                                   CloseCallback close_callback) {
  transport_->RegisterCallbacks(
      [this,
       command_callback](const std::shared_ptr<std::vector<uint8_t>> command) {
        AppendRecord(PacketDirection::HOST_TO_CONTROLLER, PacketType::COMMAND,
                     *command);
        command_callback(command);
      },
      [this, acl_callback](const std::shared_ptr<std::vector<uint8_t>> acl) {
        AppendRecord(PacketDirection::HOST_TO_CONTROLLER, PacketType::ACL,
                     *acl);
        acl_callback(acl);
      },
      [this, sco_callback](const std::shared_ptr<std::vector<uint8_t>> sco) {
        AppendRecord(PacketDirection::HOST_TO_CONTROLLER, PacketType::SCO,
                     *sco);
        sco_callback(sco);
      },
      [this, iso_callback](const std::shared_ptr<std::vector<uint8_t>> iso) {
        AppendRecord(PacketDirection::HOST_TO_CONTROLLER, PacketType::ISO,
                     *iso);
        iso_callback(iso);
      },
      close_callback);
}

void HciSniffer::TimerTick() { transport_->TimerTick(); }

void HciSniffer::Close() {
  transport_->Close();
  output_.close();
}

void HciSniffer::SendEvent(const std::vector<uint8_t>& packet) {
  AppendRecord(PacketDirection::CONTROLLER_TO_HOST, PacketType::EVENT, packet);
  transport_->SendEvent(packet);
}

void HciSniffer::SendAcl(const std::vector<uint8_t>& packet) {
  AppendRecord(PacketDirection::CONTROLLER_TO_HOST, PacketType::ACL, packet);
  transport_->SendAcl(packet);
}

void HciSniffer::SendSco(const std::vector<uint8_t>& packet) {
  AppendRecord(PacketDirection::CONTROLLER_TO_HOST, PacketType::SCO, packet);
  transport_->SendSco(packet);
}

void HciSniffer::SendIso(const std::vector<uint8_t>& packet) {
  AppendRecord(PacketDirection::CONTROLLER_TO_HOST, PacketType::ISO, packet);
  transport_->SendIso(packet);
}
}  // namespace rootcanal
