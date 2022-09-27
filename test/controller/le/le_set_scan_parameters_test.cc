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

class LeSetScanParametersTest : public ::testing::Test {
 public:
  LeSetScanParametersTest() = default;
  ~LeSetScanParametersTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetScanParametersTest, Success) {
  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x200,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::SUCCESS);
}

TEST_F(LeSetScanParametersTest, ScanningActive) {
  ASSERT_EQ(controller_.LeSetScanEnable(true, false), ErrorCode::SUCCESS);

  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x200,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetScanParametersTest, InvalidScanInterval) {
  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x0, 0x200,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x4001, 0x200,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);
}

TEST_F(LeSetScanParametersTest, InvalidScanWindow) {
  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x0,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x4001,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(
      controller_.LeSetScanParameters(LeScanType::PASSIVE, 0x2000, 0x2001,
                                      OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                      LeScanningFilterPolicy::ACCEPT_ALL),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

}  // namespace rootcanal
