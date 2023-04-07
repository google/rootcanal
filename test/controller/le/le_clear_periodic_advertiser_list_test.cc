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

class LeClearPeriodicAdvertiserListTest : public ::testing::Test {
 public:
  LeClearPeriodicAdvertiserListTest() {
    // Reduce the size of the periodic advertiser list to simplify testing.
    properties_.le_periodic_advertiser_list_size = 1;
  }

  ~LeClearPeriodicAdvertiserListTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeClearPeriodicAdvertiserListTest, Success) {
  ASSERT_EQ(controller_.LeAddDeviceToPeriodicAdvertiserList(
                AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address{1}, 1),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeClearPeriodicAdvertiserList(), ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToPeriodicAdvertiserList(
                AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address{1}, 1),
            ErrorCode::SUCCESS);
}

TEST_F(LeClearPeriodicAdvertiserListTest, CreateSyncPending) {
  ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                PeriodicAdvertisingOptions(), 0,
                AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address{5}, false, 0x100, 0),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeClearPeriodicAdvertiserList(),
            ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
