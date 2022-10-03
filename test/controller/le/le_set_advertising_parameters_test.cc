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

class LeSetAdvertisingParametersTest : public ::testing::Test {
 public:
  LeSetAdvertisingParametersTest() = default;
  ~LeSetAdvertisingParametersTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetAdvertisingParametersTest, Success) {
  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetAdvertisingParametersTest, AdvertisingActive) {
  ASSERT_EQ(controller_.LeSetAdvertisingEnable(true), ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetAdvertisingParametersTest, InvalidChannelMap) {
  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x0, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetAdvertisingParametersTest, InvalidAdvertisingInterval) {
  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x4001, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x4001, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0900, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

}  // namespace rootcanal
