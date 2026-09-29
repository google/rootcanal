/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <gtest/gtest.h>

#include "model/controller/le_controller.h"
#include "test_helpers.h"

namespace rootcanal {

using namespace bluetooth::hci;

class LeAddDeviceToFilterAcceptListWithProximityThresholdTest : public ::testing::Test {
public:
  LeAddDeviceToFilterAcceptListWithProximityThresholdTest() {
    // Reduce the size of the filter accept list to simplify testing.
    properties_.le_filter_accept_list_size = 2;
  }

  ~LeAddDeviceToFilterAcceptListWithProximityThresholdTest() override = default;

protected:
  Address address_{0};
  ControllerProperties properties_{};
  LeController controller_{address_, properties_};
};

TEST_F(LeAddDeviceToFilterAcceptListWithProximityThresholdTest, Success) {
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptListWithProximityThreshold(
                    FilterAcceptListAddressType::PUBLIC, Address{1}, 100, 20),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptListWithProximityThreshold(
                    FilterAcceptListAddressType::RANDOM, Address{2}, 100, 20),
            ErrorCode::SUCCESS);
}

TEST_F(LeAddDeviceToFilterAcceptListWithProximityThresholdTest, ListFull) {
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptListWithProximityThreshold(
                    FilterAcceptListAddressType::PUBLIC, Address{1}, 100, 20),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptListWithProximityThreshold(
                    FilterAcceptListAddressType::PUBLIC, Address{2}, 100, 20),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptListWithProximityThreshold(
                    FilterAcceptListAddressType::PUBLIC, Address{3}, 100, 20),
            ErrorCode::MEMORY_CAPACITY_EXCEEDED);

  // Updating existing entry when full should succeed via in-place update!
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptListWithProximityThreshold(
                    FilterAcceptListAddressType::PUBLIC, Address{1}, 80, 10),
            ErrorCode::SUCCESS);
}

TEST_F(LeAddDeviceToFilterAcceptListWithProximityThresholdTest, ScanningActive) {
  controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x400, 0x200,
                                  OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                  LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY);
  controller_.LeSetScanEnable(true, false);

  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptListWithProximityThreshold(
                    FilterAcceptListAddressType::PUBLIC, Address{1}, 100, 20),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeAddDeviceToFilterAcceptListWithProximityThresholdTest, ThresholdEvaluation) {
  // Add device with Path Loss threshold = 80 dB, RSSI threshold = -60 dBm
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptListWithProximityThreshold(
                    FilterAcceptListAddressType::PUBLIC, Address{1}, 80, -60),
            ErrorCode::SUCCESS);

  AddressWithType peer{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS};

  // Case 1: TxPower present (0x0A type = 10 dBm), received RSSI = -75 dBm.
  // Calculated Path Loss = 10 - (-75) = 85 dB > 80 dB threshold -> false!
  std::vector<uint8_t> adv_data_unmet = {0x02, 0x0A, static_cast<uint8_t>(10)};
  ASSERT_FALSE(
          controller_.LeFilterAcceptListContainsDeviceWithThreshold(peer, -75, adv_data_unmet));

  // Case 2: TxPower present (10 dBm), received RSSI = -60 dBm.
  // Calculated Path Loss = 10 - (-60) = 70 dB <= 80 dB threshold -> true!
  std::vector<uint8_t> adv_data_met = {0x02, 0x0A, static_cast<uint8_t>(10)};
  ASSERT_TRUE(controller_.LeFilterAcceptListContainsDeviceWithThreshold(peer, -60, adv_data_met));

  // Case 3: TxPower absent -> Fallback to RSSI threshold (-60 dBm).
  // Received RSSI = -70 dBm < -60 dBm -> false!
  std::vector<uint8_t> adv_data_no_txpower = {0x02, 0x09, 'T'};
  ASSERT_FALSE(controller_.LeFilterAcceptListContainsDeviceWithThreshold(peer, -70,
                                                                         adv_data_no_txpower));

  // Case 4: TxPower absent -> Fallback to RSSI threshold (-60 dBm).
  // Received RSSI = -50 dBm >= -60 dBm -> true!
  ASSERT_TRUE(controller_.LeFilterAcceptListContainsDeviceWithThreshold(peer, -50,
                                                                        adv_data_no_txpower));

  // Case 5: Overflow test (TxPower = 127 dBm, RSSI = -128 dBm -> Path Loss = 255 dB).
  // Without int16_t cast, int8_t overflow causes 255 -> -1 <= 80 (incorrectly true).
  // With int16_t cast, 255 > 80 threshold -> correctly false!
  std::vector<uint8_t> adv_data_overflow = {0x02, 0x0A, static_cast<uint8_t>(127)};
  ASSERT_FALSE(controller_.LeFilterAcceptListContainsDeviceWithThreshold(
          peer, static_cast<int8_t>(-128), adv_data_overflow));

  // Case 6: Underflow test (TxPower = -128 dBm, RSSI = 127 dBm -> Path Loss = -255 dB).
  // Without int16_t cast, int8_t underflow causes -255 -> +1 > 80 (incorrectly false).
  // With int16_t cast, -255 <= 80 threshold -> correctly true!
  std::vector<uint8_t> adv_data_underflow = {0x02, 0x0A, static_cast<uint8_t>(-128)};
  ASSERT_TRUE(
          controller_.LeFilterAcceptListContainsDeviceWithThreshold(peer, 127, adv_data_underflow));

  // Case 7: PDU header attached TX power priority test.
  // Even if adv_data payload has no TX power, attached pdu_tx_power (10 dBm)
  // is prioritized and evaluated (Path Loss = 10 - (-60) = 70 dB <= 80 dB threshold -> true!).
  ASSERT_TRUE(controller_.LeFilterAcceptListContainsDeviceWithThreshold(
          peer, -60, adv_data_no_txpower, /*pdu_tx_power=*/10));
}

}  // namespace rootcanal
