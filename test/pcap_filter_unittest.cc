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

#include "hci/pcap_filter.h"

#include <gtest/gtest.h>

#include "packets/hci_packets.h"

namespace rootcanal {

using namespace bluetooth::hci;

class PcapFilterTest : public ::testing::Test {
 public:
  PcapFilterTest() = default;
  ~PcapFilterTest() override = default;

 protected:
  PcapFilter pcap_filter_;
};

TEST_F(PcapFilterTest, UnchangedIfNotDeviceName) {
  // Leaves gap data entries that do not contain a name unchanged.
  std::vector<uint8_t> input_gap_data{
      0x2, static_cast<uint8_t>(GapDataType::FLAGS), 0x0};
  std::vector<uint8_t> output_gap_data{input_gap_data.begin(),
                                       input_gap_data.end()};
  pcap_filter_.FilterGapData(output_gap_data);
  ASSERT_EQ(input_gap_data, output_gap_data);
}

TEST_F(PcapFilterTest, ReplacesShortenedDeviceName) {
  // Replaces the input gap data once, with a name of equal length.
  std::vector<uint8_t> input_gap_data{
      0x2,
      static_cast<uint8_t>(GapDataType::FLAGS),
      0x0,
      0x4,
      static_cast<uint8_t>(GapDataType::SHORTENED_LOCAL_NAME),
      0xa,
      0xb,
      0xc};
  std::vector<uint8_t> output_gap_data_1{input_gap_data.begin(),
                                         input_gap_data.end()};
  pcap_filter_.FilterGapData(output_gap_data_1);
  ASSERT_EQ(input_gap_data.size(), output_gap_data_1.size());
  ASSERT_NE(input_gap_data, output_gap_data_1);

  // Replaces the input gap data a second time with the same name.
  std::vector<uint8_t> output_gap_data_2{input_gap_data.begin(),
                                         input_gap_data.end()};
  pcap_filter_.FilterGapData(output_gap_data_2);
  ASSERT_EQ(output_gap_data_1, output_gap_data_2);
}

TEST_F(PcapFilterTest, ReplacesCompleteDeviceName) {
  // Replaces the input gap data once, with a name of equal length.
  std::vector<uint8_t> input_gap_data{
      0x2,
      static_cast<uint8_t>(GapDataType::FLAGS),
      0x0,
      0x4,
      static_cast<uint8_t>(GapDataType::COMPLETE_LOCAL_NAME),
      0xa,
      0xb,
      0xc};
  std::vector<uint8_t> output_gap_data_1{input_gap_data.begin(),
                                         input_gap_data.end()};
  pcap_filter_.FilterGapData(output_gap_data_1);
  ASSERT_EQ(input_gap_data.size(), output_gap_data_1.size());
  ASSERT_NE(input_gap_data, output_gap_data_1);

  // Replaces the input gap data a second time with the same name.
  std::vector<uint8_t> output_gap_data_2{input_gap_data.begin(),
                                         input_gap_data.end()};
  pcap_filter_.FilterGapData(output_gap_data_2);
  ASSERT_EQ(output_gap_data_1, output_gap_data_2);
}

}  // namespace rootcanal
