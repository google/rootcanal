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
  // Note: the description given for the direction bit by tcpdump
  // is in opposition with the implementation in wireshark.
  // The values match wireshark's implementation here.
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

void HciSniffer::RegisterCallbacks(PacketCallback packet_callback,
                                   CloseCallback close_callback) {
  transport_->RegisterCallbacks(
      [this, packet_callback](
          PacketType packet_type,
          const std::shared_ptr<std::vector<uint8_t>> packet) {
        AppendRecord(PacketDirection::HOST_TO_CONTROLLER, packet_type, *packet);
        packet_callback(packet_type, packet);
      },
      close_callback);
}

void HciSniffer::Tick() { transport_->Tick(); }

void HciSniffer::Close() {
  transport_->Close();
  if (output_ != nullptr) {
    output_->flush();
  }
}

void HciSniffer::Send(PacketType packet_type,
                      const std::vector<uint8_t>& packet) {
  AppendRecord(PacketDirection::CONTROLLER_TO_HOST, packet_type, packet);
  transport_->Send(packet_type, packet);
}

}  // namespace rootcanal
