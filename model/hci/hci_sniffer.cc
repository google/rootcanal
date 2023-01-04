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

#include "hci/pcap_filter.h"
#include "pcap.h"

namespace rootcanal {

HciSniffer::HciSniffer(std::shared_ptr<HciTransport> transport,
                       std::shared_ptr<std::ostream> outputStream,
                       std::shared_ptr<PcapFilter> filter)
    : transport_(transport), filter_(filter) {
  SetOutputStream(outputStream);
}

void HciSniffer::SetPcapFilter(std::shared_ptr<PcapFilter> filter) {
  filter_ = filter;
}

void HciSniffer::SetOutputStream(std::shared_ptr<std::ostream> outputStream) {
  output_ = outputStream;
  if (output_) {
    uint32_t linktype = 201;  // http://www.tcpdump.org/linktypes.html
                              // LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR

    pcap::WriteHeader(*output_, linktype);
  }
}

void HciSniffer::AppendRecord(PacketDirection packet_direction,
                              PacketType packet_type,
                              const std::vector<uint8_t>& packet) {
  if (output_ == nullptr) {
    return;
  }

  pcap::WriteRecordHeader(*output_, 4 + 1 + packet.size());

  // http://www.tcpdump.org/linktypes.html LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR
  char direction[4] = {0, 0, 0, static_cast<char>(packet_direction)};
  uint8_t idc = static_cast<uint8_t>(packet_type);
  output_->write(direction, sizeof(direction));
  output_->write((char*)&idc, 1);

  // Apply the PCAP filter when provided.
  if (filter_ != nullptr) {
    std::vector<uint8_t> filtered_packet =
        filter_->FilterHciPacket(packet, idc);
    output_->write((char*)filtered_packet.data(), filtered_packet.size());
  } else {
    output_->write((char*)packet.data(), packet.size());
  }

  // Flush packet.
  output_->flush();
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
  if (output_ != nullptr) {
    output_->flush();
  }
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
