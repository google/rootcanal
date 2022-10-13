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

class LeSetAdvertisingEnableTest : public ::testing::Test {
 public:
  LeSetAdvertisingEnableTest() = default;
  ~LeSetAdvertisingEnableTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetAdvertisingEnableTest, EnableUsingPublicAddress) {
  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAdvertisingEnable(true), ErrorCode::SUCCESS);
}

TEST_F(LeSetAdvertisingEnableTest, EnableUsingRandomAddress) {
  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::RANDOM_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetRandomAddress(Address{1}), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAdvertisingEnable(true), ErrorCode::SUCCESS);
}

TEST_F(LeSetAdvertisingEnableTest, EnableUsingResolvableAddress) {
  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
  // Note: the command will fail if the peer address is not in the resolvable
  // address list and the random address is not set.
  // Success here signifies that the RPA was successfully generated.
  ASSERT_EQ(controller_.LeSetAdvertisingEnable(true), ErrorCode::SUCCESS);
}

TEST_F(LeSetAdvertisingEnableTest, Disable) {
  ASSERT_EQ(controller_.LeSetAdvertisingEnable(false), ErrorCode::SUCCESS);
}

TEST_F(LeSetAdvertisingEnableTest, NoRandomAddress) {
  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::RANDOM_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetAdvertisingEnable(true),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetAdvertisingEnableTest, NoResolvableOrRandomAddress) {
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAdvertisingParameters(
                0x0800, 0x0800, AdvertisingType::ADV_IND,
                OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, 0x7, AdvertisingFilterPolicy::ALL_DEVICES),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetAdvertisingEnable(true),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

}  // namespace rootcanal
