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

class LeSetExtendedAdvertisingParametersTest : public ::testing::Test {
 public:
  LeSetExtendedAdvertisingParametersTest() {
    // Reduce the number of advertising sets to simplify testing.
    properties_.le_num_supported_advertising_sets = 2;
  };
  ~LeSetExtendedAdvertisingParametersTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetExtendedAdvertisingParametersTest, Success) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, LegacyUsed) {
  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x200,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, AdvertisingSetsFull) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                1, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                2, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::MEMORY_CAPACITY_EXCEEDED);
}

TEST_F(LeSetExtendedAdvertisingParametersTest,
       InvalidLegacyAdvertisingEventProperties) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | DIRECTED | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, UnexpectedAdvertisingData) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | DIRECTED | CONNECTABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, UnexpectedScanResponseData) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::SUCCESS);

  std::vector<uint8_t> scan_response_data = {1, 2, 3};
  ASSERT_EQ(
      controller_.LeSetExtendedScanResponseData(
          0, Operation::COMPLETE_ADVERTISEMENT,
          FragmentPreference::CONTROLLER_MAY_FRAGMENT, scan_response_data),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE), 0x0800,
                0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, InvalidLegacyAdvertisingData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  advertising_data.resize(32);
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE), 0x0800,
                0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, InvalidLegacyScanResponseData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
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
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(LEGACY | SCANNABLE), 0x0800,
                0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest,
       InvalidExtendedAdvertisingEventProperties) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE | SCANNABLE),
                0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0,
                MakeAdvertisingEventProperties(CONNECTABLE | DIRECTED |
                                               HIGH_DUTY_CYCLE),
                0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest,
       InvalidPrimaryAdvertisingInterval) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x10, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x10,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0400,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, InvalidChannelMap) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x0, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, InvalidPrimaryPhy) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE), 0x0800,
          0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_CODED,
          0, SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingParametersTest, AdvertisingActive) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(0), 0x0800, 0x0800, 0x7,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
