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

class LeSetExtendedScanParametersTest : public ::testing::Test {
 public:
  LeSetExtendedScanParametersTest() = default;
  ~LeSetExtendedScanParametersTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

static ScanningPhyParameters MakeScanningPhyParameters(LeScanType scan_type,
                                                       uint16_t scan_interval,
                                                       uint16_t scan_window) {
  ScanningPhyParameters parameters;
  parameters.le_scan_type_ = scan_type;
  parameters.le_scan_interval_ = scan_interval;
  parameters.le_scan_window_ = scan_window;
  return parameters;
}

TEST_F(LeSetExtendedScanParametersTest, Success) {
  ASSERT_EQ(controller_.LeSetExtendedScanParameters(
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                LeScanningFilterPolicy::ACCEPT_ALL, 0x5,
                {MakeScanningPhyParameters(LeScanType::PASSIVE, 0x2000, 0x200),
                 MakeScanningPhyParameters(LeScanType::ACTIVE, 0x2000, 0x200)}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedScanParametersTest, ScanningActive) {
  ASSERT_EQ(controller_.LeSetExtendedScanParameters(
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                LeScanningFilterPolicy::ACCEPT_ALL, 0x5,
                {MakeScanningPhyParameters(LeScanType::PASSIVE, 0x2000, 0x200),
                 MakeScanningPhyParameters(LeScanType::ACTIVE, 0x2000, 0x200)}),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetExtendedScanEnable(
                true, FilterDuplicates::DISABLED, 0, 0),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedScanParameters(
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                LeScanningFilterPolicy::ACCEPT_ALL, 0x5,
                {MakeScanningPhyParameters(LeScanType::PASSIVE, 0x2000, 0x200),
                 MakeScanningPhyParameters(LeScanType::ACTIVE, 0x2000, 0x200)}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetExtendedScanParametersTest, ReservedPhy) {
  ASSERT_EQ(
      controller_.LeSetExtendedScanParameters(
          OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          LeScanningFilterPolicy::ACCEPT_ALL, 0x80,
          {MakeScanningPhyParameters(LeScanType::PASSIVE, 0x2000, 0x200)}),
      ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);
}

TEST_F(LeSetExtendedScanParametersTest, InvalidPhyParameters) {
  ASSERT_EQ(controller_.LeSetExtendedScanParameters(
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                LeScanningFilterPolicy::ACCEPT_ALL, 0x1, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(
      controller_.LeSetExtendedScanParameters(
          OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          LeScanningFilterPolicy::ACCEPT_ALL, 0x1,
          {MakeScanningPhyParameters(LeScanType::PASSIVE, 0x2000, 0x200),
           MakeScanningPhyParameters(LeScanType::PASSIVE, 0x2000, 0x200)}),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedScanParametersTest, InvalidScanInterval) {
  ASSERT_EQ(controller_.LeSetExtendedScanParameters(
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                LeScanningFilterPolicy::ACCEPT_ALL, 0x1,
                {MakeScanningPhyParameters(LeScanType::PASSIVE, 0x0, 0x200)}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedScanParametersTest, InvalidScanWindow) {
  ASSERT_EQ(controller_.LeSetExtendedScanParameters(
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                LeScanningFilterPolicy::ACCEPT_ALL, 0x1,
                {MakeScanningPhyParameters(LeScanType::PASSIVE, 0x2000, 0x0)}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(
      controller_.LeSetExtendedScanParameters(
          OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          LeScanningFilterPolicy::ACCEPT_ALL, 0x1,
          {MakeScanningPhyParameters(LeScanType::PASSIVE, 0x2000, 0x2001)}),
      ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

}  // namespace rootcanal
