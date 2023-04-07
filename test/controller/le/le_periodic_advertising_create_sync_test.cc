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

class LePeriodicAdvertisingCreateSyncTest : public ::testing::Test {
 public:
  LePeriodicAdvertisingCreateSyncTest() = default;
  ~LePeriodicAdvertisingCreateSyncTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LePeriodicAdvertisingCreateSyncTest, CreateUsingPublicAddress) {
  ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                PeriodicAdvertisingOptions(false, false, false), 0,
                AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address{1}, 0, 0x100, 0),
            ErrorCode::SUCCESS);
}

TEST_F(LePeriodicAdvertisingCreateSyncTest, CreateUsingPeriodicAdvertiserList) {
  ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                PeriodicAdvertisingOptions(true, false, false), 0,
                AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0, 0x100, 0),
            ErrorCode::SUCCESS);
}

TEST_F(LePeriodicAdvertisingCreateSyncTest, CreateSyncPending) {
  ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                PeriodicAdvertisingOptions(false, false, false), 0,
                AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address{1}, 0, 0x100, 0),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                PeriodicAdvertisingOptions(true, false, false), 0,
                AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0, 0x100, 0),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LePeriodicAdvertisingCreateSyncTest, InvalidSyncCteMask) {
  ASSERT_EQ(
      controller_.LePeriodicAdvertisingCreateSync(
          PeriodicAdvertisingOptions(false, false, false), 0,
          AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
          0, 0x100,
          static_cast<uint8_t>(
              PeriodicSyncCteType::AVOID_AOA_CONSTANT_TONE_EXTENSION) |
              static_cast<uint8_t>(
                  PeriodicSyncCteType::
                      AVOID_AOD_CONSTANT_TONE_EXTENSION_WITH_ONE_US_SLOTS) |
              static_cast<uint8_t>(
                  PeriodicSyncCteType::
                      AVOID_AOD_CONSTANT_TONE_EXTENSION_WITH_TWO_US_SLOTS) |
              static_cast<uint8_t>(
                  PeriodicSyncCteType::
                      AVOID_TYPE_THREE_CONSTANT_TONE_EXTENSION) |
              static_cast<uint8_t>(
                  PeriodicSyncCteType::AVOID_NO_CONSTANT_TONE_EXTENSION)),
      ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
