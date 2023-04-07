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

class LeSetPeriodicAdvertisingEnableTest : public ::testing::Test {
 public:
  LeSetPeriodicAdvertisingEnableTest() {}
  ~LeSetPeriodicAdvertisingEnableTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetPeriodicAdvertisingEnableTest, Enable) {
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

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT, advertising_data),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(true, false, 0),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetPeriodicAdvertisingEnableTest, Disable) {
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

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(false, false, 0),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetPeriodicAdvertisingEnableTest, UnknownAdvertisingHandle) {
  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(true, false, 0),
            ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER);

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(false, false, 0),
            ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER);
}

TEST_F(LeSetPeriodicAdvertisingEnableTest, PartialAdvertisingData) {
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

  std::vector<uint8_t> first_advertising_data_fragment = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingData(
                0, Operation::FIRST_FRAGMENT, first_advertising_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(true, false, 0),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetPeriodicAdvertisingEnableTest, PeriodicAdvertisingNotConfigured) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(), 0x0800, 0x0800, 0x7,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(true, false, 0),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetPeriodicAdvertisingEnableTest, InvalidAdvertisingEventProperties) {
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

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(true, false, 0),
            ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
