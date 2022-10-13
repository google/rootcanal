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

class LeSetScanEnableTest : public ::testing::Test {
 public:
  LeSetScanEnableTest() = default;
  ~LeSetScanEnableTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetScanEnableTest, EnableUsingPublicAddress) {
  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x200,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetScanEnable(true, false), ErrorCode::SUCCESS);
}

TEST_F(LeSetScanEnableTest, EnableUsingRandomAddress) {
  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x200,
                                      OwnAddressType::RANDOM_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetRandomAddress(Address{1}), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetScanEnable(true, false), ErrorCode::SUCCESS);
}

TEST_F(LeSetScanEnableTest, EnableUsingResolvableAddress) {
  ASSERT_EQ(controller_.LeSetScanParameters(
                LeScanType::PASSIVE, 0x2000, 0x200,
                OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS,
                LeScanningFilterPolicy::ACCEPT_ALL),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetRandomAddress(Address{1}), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetScanEnable(true, false), ErrorCode::SUCCESS);
}

TEST_F(LeSetScanEnableTest, Disable) {
  ASSERT_EQ(controller_.LeSetScanEnable(false, false), ErrorCode::SUCCESS);
}

TEST_F(LeSetScanEnableTest, NoRandomAddress) {
  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x200,
                                      OwnAddressType::RANDOM_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetScanEnable(true, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetScanParameters(
                LeScanType::PASSIVE, 0x2000, 0x200,
                OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS,
                LeScanningFilterPolicy::ACCEPT_ALL),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetScanEnable(true, false),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

}  // namespace rootcanal
