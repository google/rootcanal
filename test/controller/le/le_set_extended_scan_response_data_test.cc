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

#include <gtest/gtest.h>

#include "model/controller/link_layer_controller.h"
#include "test_helpers.h"

namespace rootcanal {

using namespace bluetooth::hci;

class LeSetExtendedScanResponseDataTest : public ::testing::Test {
 public:
  LeSetExtendedScanResponseDataTest() {
    // Reduce the number of advertising sets to simplify testing.
    properties_.le_num_supported_advertising_sets = 2;
    properties_.le_max_advertising_data_length = 300;
  };
  ~LeSetExtendedScanResponseDataTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetExtendedScanResponseDataTest, Complete) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedScanResponseDataTest, Discard) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedScanResponseDataTest, Unchanged) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::UNCHANGED_DATA,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedScanResponseDataTest, Fragmented) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_scan_response_data_fragment = {1, 2, 3};
  std::vector<uint8_t> intermediate_scan_response_data_fragment = {4, 5, 6};
  std::vector<uint8_t> last_scan_response_data_fragment = {7, 8, 9};

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_scan_response_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::INTERMEDIATE_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                intermediate_scan_response_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::LAST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                last_scan_response_data_fragment),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedScanResponseDataTest, UnknownAdvertisingHandle) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          1, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER);
}

TEST_F(LeSetExtendedScanResponseDataTest, UnexpectedScanResponseData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedScanResponseDataTest, IncompleteLegacyScanResponseData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(LEGACY | SCANNABLE), 0x0800,
                0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_scan_response_data_fragment = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_scan_response_data_fragment),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedScanResponseDataTest, InvalidLegacyScanResponseData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(LEGACY | SCANNABLE), 0x0800,
                0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  scan_response_data.resize(32);
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedScanResponseDataTest, EmptyScanResponseDataFragment) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_scan_response_data_fragment = {1, 2, 3};
  std::vector<uint8_t> intermediate_scan_response_data_fragment = {4, 5, 6};
  std::vector<uint8_t> last_scan_response_data_fragment = {7, 8, 9};

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_scan_response_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::INTERMEDIATE_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::INTERMEDIATE_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                intermediate_scan_response_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::LAST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::LAST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                last_scan_response_data_fragment),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedScanResponseDataTest, AdvertisingEnabled) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::FIRST_FRAGMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetExtendedScanResponseDataTest, EmptyExtendedScanResponseData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetExtendedScanResponseDataTest,
       ScanResponseDataLargerThanMemoryCapacity) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data_fragment = {1, 2, 3};
  scan_response_data_fragment.resize(
      properties_.le_max_advertising_data_length);

  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                scan_response_data_fragment),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::LAST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                scan_response_data_fragment),
            ErrorCode::MEMORY_CAPACITY_EXCEEDED);
}

TEST_F(LeSetExtendedScanResponseDataTest,
       ScanResponseDataLargerThanPduCapacity) {
  // Overwrite le_max_advertising_data_length to make sure that the correct
  // check is triggered.
  properties_.le_max_advertising_data_length = 5000;

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  // No AUX chain possible for connectable advertising PDUs,
  // the advertising data is limited to one PDU's payload.
  scan_response_data.resize(1651);

  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::PACKET_TOO_LONG);
}

}  // namespace rootcanal
