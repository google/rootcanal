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

namespace rootcanal {

using namespace bluetooth::hci;

class LeRemoveDeviceFromResolvingListTest : public ::testing::Test {
 public:
  LeRemoveDeviceFromResolvingListTest() {
    // Reduce the size of the resolving list to simplify testing.
    properties_.le_resolving_list_size = 2;
  }

  ~LeRemoveDeviceFromResolvingListTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeRemoveDeviceFromResolvingListTest, Success) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeRemoveDeviceFromResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1}),
            ErrorCode::SUCCESS);
}

TEST_F(LeRemoveDeviceFromResolvingListTest, NotFound) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeRemoveDeviceFromResolvingList(
                AddressType::RANDOM_DEVICE_ADDRESS, Address{1}),
            ErrorCode::UNKNOWN_CONNECTION);
}

TEST_F(LeRemoveDeviceFromResolvingListTest, ScanningActive) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
  controller_.SetLeScanEnable(OpCode::LE_SET_SCAN_ENABLE);

  ASSERT_EQ(controller_.LeRemoveDeviceFromResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeRemoveDeviceFromResolvingListTest, LegacyAdvertisingActive) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.SetLeAdvertisingEnable(1), ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeRemoveDeviceFromResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeRemoveDeviceFromResolvingListTest, ExtendedAdvertisingActive) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  EnabledSet enabled_set;
  enabled_set.advertising_handle_ = 1;
  enabled_set.duration_ = 0;
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.SetLeExtendedAdvertisingEnable(Enable::ENABLED,
                                                       {enabled_set}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeRemoveDeviceFromResolvingList(
                AddressType::PUBLIC_DEVICE_ADDRESS, Address{1}),
            ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
