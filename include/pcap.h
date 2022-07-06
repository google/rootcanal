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

#pragma once

#include <chrono>
#include <cstdint>
#include <limits>
#include <ostream>

namespace rootcanal::pcap {

using namespace std::literals;

static void WriteHeader(std::ostream& output, uint32_t linktype) {
  // https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.html#name-file-header
  uint32_t magic_number = 0xa1b2c3d4;
  uint16_t major_version = 2;
  uint16_t minor_version = 4;
  uint32_t reserved1 = 0;
  uint32_t reserved2 = 0;
  uint32_t snaplen = std::numeric_limits<uint32_t>::max();

  output.write((char*)&magic_number, 4);
  output.write((char*)&major_version, 2);
  output.write((char*)&minor_version, 2);
  output.write((char*)&reserved1, 4);
  output.write((char*)&reserved2, 4);
  output.write((char*)&snaplen, 4);
  output.write((char*)&linktype, 4);
}

static void WriteRecordHeader(std::ostream& output, uint32_t length) {
  auto time = std::chrono::system_clock::now().time_since_epoch();

  // https://tools.ietf.org/id/draft-gharris-opsawg-pcap-00.html#name-packet-record
  uint32_t seconds = time / 1s;
  uint32_t microseconds = (time % 1s) / 1ms;
  uint32_t captured_packet_length = length;
  uint32_t original_packet_length = length;

  output.write((char*)&seconds, 4);
  output.write((char*)&microseconds, 4);
  output.write((char*)&captured_packet_length, 4);
  output.write((char*)&original_packet_length, 4);
}

}  // namespace rootcanal::pcap
