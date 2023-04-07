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

class LeSetPeriodicAdvertisingParametersTest : public ::testing::Test {
 public:
  LeSetPeriodicAdvertisingParametersTest() = default;
  ~LeSetPeriodicAdvertisingParametersTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetPeriodicAdvertisingParametersTest, Success) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(), 0x0800, 0x0800, 0x7,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(0, 0x6, 0xffff, false),
      ErrorCode::SUCCESS);
}

TEST_F(LeSetPeriodicAdvertisingParametersTest, UnknownAdvertisingHandle) {
  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(0, 0x6, 0xffff, false),
      ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER);
}

TEST_F(LeSetPeriodicAdvertisingParametersTest, InvalidAdvertisingInterval) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(), 0x0800, 0x0800, 0x7,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(0, 0x0, 0xffff, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(0, 0xffff, 0x6, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetPeriodicAdvertisingParametersTest,
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

TEST_F(LeSetPeriodicAdvertisingParametersTest,
       InvalidAdvertisingEventProperties) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(0, 0x6, 0xffff, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                1, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(1, 0x6, 0xffff, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                2, MakeAdvertisingEventProperties(ANONYMOUS), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(2, 0x6, 0xffff, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                3, MakeAdvertisingEventProperties(LEGACY), 0x0800, 0x0800, 0x7,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(3, 0x6, 0xffff, false),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetPeriodicAdvertisingParametersTest, PeriodicAdvertisingEnabled) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(), 0x0800, 0x0800, 0x7,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(0, 0x6, 0xffff, false),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(true, false, 0),
            ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetPeriodicAdvertisingParameters(0, 0x6, 0xffff, false),
      ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
