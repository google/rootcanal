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

class LeClearFilterAcceptListTest : public ::testing::Test {
 public:
  LeClearFilterAcceptListTest() {
    // Reduce the size of the filter accept list to simplify testing.
    properties_.le_filter_accept_list_size = 2;
  }

  ~LeClearFilterAcceptListTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeClearFilterAcceptListTest, Success) {
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptList(
                FilterAcceptListAddressType::PUBLIC, Address{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeClearFilterAcceptList(), ErrorCode::SUCCESS);
}

TEST_F(LeClearFilterAcceptListTest, ScanningActive) {
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptList(
                FilterAcceptListAddressType::PUBLIC, Address{1}),
            ErrorCode::SUCCESS);

  controller_.LeSetScanParameters(
      LeScanType::PASSIVE, 0x400, 0x200, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
      LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY);
  controller_.LeSetScanEnable(true, false);

  ASSERT_EQ(controller_.LeClearFilterAcceptList(),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeClearFilterAcceptListTest, LegacyAdvertisingActive) {
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptList(
                FilterAcceptListAddressType::PUBLIC, Address{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::LISTED_SCAN),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAdvertisingEnable(true), ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeClearFilterAcceptList(),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeClearFilterAcceptListTest, ExtendedAdvertisingActive) {
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptList(
                FilterAcceptListAddressType::PUBLIC, Address{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::LISTED_SCAN, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeClearFilterAcceptList(),
            ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
