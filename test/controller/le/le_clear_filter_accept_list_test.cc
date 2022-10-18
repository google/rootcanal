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

  controller_.SetLeScanFilterPolicy(
      LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY);
  controller_.SetLeScanEnable(OpCode::LE_SET_SCAN_ENABLE);

  ASSERT_EQ(controller_.LeClearFilterAcceptList(),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeClearFilterAcceptListTest, LegacyAdvertisingActive) {
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptList(
                FilterAcceptListAddressType::PUBLIC, Address{1}),
            ErrorCode::SUCCESS);

  controller_.SetLeAdvertisingParameters(
      0x0800, 0x0800, AdvertisingType::ADV_IND, 0, 0, Address::kEmpty, 0x7,
      AdvertisingFilterPolicy::LISTED_SCAN);
  ASSERT_EQ(controller_.SetLeAdvertisingEnable(1), ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeClearFilterAcceptList(),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeClearFilterAcceptListTest, ExtendedAdvertisingActive) {
  ASSERT_EQ(controller_.LeAddDeviceToFilterAcceptList(
                FilterAcceptListAddressType::PUBLIC, Address{1}),
            ErrorCode::SUCCESS);

  EnabledSet enabled_set;
  enabled_set.advertising_handle_ = 1;
  enabled_set.duration_ = 0;
  ASSERT_EQ(controller_.SetLeExtendedAdvertisingParameters(
                1, 0, 0, LegacyAdvertisingEventProperties::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::LISTED_SCAN, 0x70),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.SetLeExtendedAdvertisingEnable(Enable::ENABLED,
                                                       {enabled_set}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeClearFilterAcceptList(),
            ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
