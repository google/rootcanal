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

#include "baseband_sniffer.h"

#include "log.h"
#include "packet/raw_builder.h"
#include "pcap.h"

using std::vector;

namespace rootcanal {

#include "bredr_bb.h"

BaseBandSniffer::BaseBandSniffer(const std::string& filename) {
  output_.open(filename, std::ios::binary);

  uint32_t linktype = 255;  // http://www.tcpdump.org/linktypes.html
                            // LINKTYPE_BLUETOOTH_BREDR_BB

  pcap::WriteHeader(output_, linktype);
  output_.flush();
}

void BaseBandSniffer::TimerTick() {}

void BaseBandSniffer::AppendRecord(
    std::unique_ptr<bredr_bb::BaseBandPacketBuilder> packet) {
  auto bytes = std::vector<uint8_t>();
  bytes.reserve(packet->size());
  bluetooth::packet::BitInserter i(bytes);
  packet->Serialize(i);

  pcap::WriteRecordHeader(output_, bytes.size());
  output_.write((char*)bytes.data(), bytes.size());
  output_.flush();
}

static uint8_t ReverseByte(uint8_t b) {
  static uint8_t lookup[16] = {
      [0b0000] = 0b0000, [0b0001] = 0b1000, [0b0010] = 0b0100,
      [0b0011] = 0b1100, [0b0100] = 0b0010, [0b0101] = 0b1010,
      [0b0110] = 0b0110, [0b0111] = 0b1110, [0b1000] = 0b0001,
      [0b1001] = 0b1001, [0b1010] = 0b0101, [0b1011] = 0b1101,
      [0b1100] = 0b0011, [0b1101] = 0b1011, [0b1110] = 0b0111,
      [0b1111] = 0b1111,
  };

  return (lookup[b & 0xF] << 4) | lookup[b >> 4];
}

static uint8_t HeaderErrorCheck(uint8_t uap, uint32_t data) {
  // See Bluetooth Core, Vol 2, Part B, 7.1.1

  uint8_t value = ReverseByte(uap);

  for (auto i = 0; i < 10; i++) {
    bool bit = (value ^ data) & 1;
    data >>= 1;
    value >>= 1;
    if (bit) value ^= 0xe5;
  }

  return value;
}

static uint32_t BuildBtPacketHeader(uint8_t uap, uint8_t lt_addr,
                                    uint8_t packet_type, bool flow, bool arqn,
                                    bool seqn) {
  // See Bluetooth Core, Vol2, Part B, 6.4

  uint32_t header = (lt_addr & 0x7) | ((packet_type & 0xF) << 3) | (flow << 7) |
                    (arqn << 8) | (seqn << 9);

  header |= (HeaderErrorCheck(uap, header) << 10);

  return header;
}

void BaseBandSniffer::IncomingPacket(
    model::packets::LinkLayerPacketView packet) {
  auto packet_type = packet.GetType();
  auto address = packet.GetSourceAddress();

  // Bluetooth Core, Vol2, Part B, 1.2, Figure 1.5
  uint32_t lap =
      address.data()[0] | (address.data()[1] << 8) | (address.data()[2] << 16);
  uint8_t uap = address.data()[3];
  uint16_t nap = address.data()[4] | (address.data()[5] << 8);

  // http://www.whiterocker.com/bt/LINKTYPE_BLUETOOTH_BREDR_BB.html
  uint16_t flags =
      /* BT Packet Header and BR or EDR Payload are de-whitened */ 0x0001 |
      /* BR or EDR Payload is decrypted */ 0x0008 |
      /* Reference LAP is valid and led to this packet being captured */
      0x0010 |
      /* BR or EDR Payload is present and follows this field */ 0x0020 |
      /* Reference UAP field is valid for HEC and CRC checking */ 0x0080 |
      /* CRC portion of the BR or EDR Payload was checked */ 0x0400 |
      /* CRC portion of the BR or EDR Payload passed its check */ 0x0800;

  uint8_t lt_addr = 0;

  uint8_t rf_channel = 0;
  uint8_t signal_power = 0;
  uint8_t noise_power = 0;
  uint8_t access_code_offenses = 0;
  uint8_t corrected_header_bits = 0;
  uint16_t corrected_payload_bits = 0;
  uint8_t lower_address_part = lap;
  uint8_t reference_lap = lap;
  uint8_t reference_uap = uap;

  if (packet_type == model::packets::PacketType::PAGE) {
    auto page_view = model::packets::PageView::Create(packet);
    ASSERT(page_view.IsValid());

    uint8_t bt_packet_type = 0b0010;  // FHS

    AppendRecord(bredr_bb::FHSAclPacketBuilder::Create(
        rf_channel, signal_power, noise_power, access_code_offenses,
        corrected_header_bits, corrected_payload_bits, lower_address_part,
        reference_lap, reference_uap,
        BuildBtPacketHeader(uap, lt_addr, bt_packet_type, true, true, true),
        flags,
        0,  // parity_bits
        lap,
        0,  // eir
        0,  // sr
        0,  // sp
        uap, nap, page_view.GetClassOfDevice().ToUint32Legacy(),
        1,  // lt_addr
        0,  // clk
        0,  // page_scan_mode
        0   // crc
        ));
  } else if (packet_type == model::packets::PacketType::LMP) {
    auto lmp_view = model::packets::LmpView::Create(packet);
    ASSERT(lmp_view.IsValid());
    auto lmp_bytes = std::vector<uint8_t>(lmp_view.GetPayload().begin(),
                                          lmp_view.GetPayload().end());

    uint8_t bt_packet_type = 0b0011;  // DM1

    AppendRecord(bredr_bb::DM1AclPacketBuilder::Create(
        rf_channel, signal_power, noise_power, access_code_offenses,
        corrected_header_bits, corrected_payload_bits, lower_address_part,
        reference_lap, reference_uap,
        BuildBtPacketHeader(uap, lt_addr, bt_packet_type, true, true, true),
        flags,
        0x3,  // llid
        1,    // flow
        std::make_unique<bluetooth::packet::RawBuilder>(lmp_bytes),
        0  // crc
        ));
  }
}

}  // namespace rootcanal
