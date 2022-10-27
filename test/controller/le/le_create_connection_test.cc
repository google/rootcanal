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

class LeCreateConnectionTest : public ::testing::Test {
 public:
  LeCreateConnectionTest() = default;
  ~LeCreateConnectionTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeCreateConnectionTest, ConnectUsingPublicAddress) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::SUCCESS);
}

TEST_F(LeCreateConnectionTest, ConnectUsingRandomAddress) {
  ASSERT_EQ(controller_.LeSetRandomAddress(Address{1}), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::RANDOM_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::SUCCESS);
}

TEST_F(LeCreateConnectionTest, ConnectUsingResolvableAddress) {
  ASSERT_EQ(controller_.LeSetRandomAddress(Address{1}), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS, 0x100, 0x200,
                0x010, 0x0c80, 0x0, 0x0),
            ErrorCode::SUCCESS);
}

TEST_F(LeCreateConnectionTest, InitiatingActive) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{2}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeCreateConnectionTest, InvalidScanInterval) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x3, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x4001, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);
}

TEST_F(LeCreateConnectionTest, InvalidScanWindow) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x3, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x4001, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x100, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeCreateConnectionTest, InvalidConnectionInterval) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x5, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x0c81, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x200, 0x5, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x200, 0x0c81, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x4001, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x200, 0x100, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);
}

TEST_F(LeCreateConnectionTest, InvalidMaxLatency) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x01f4,
                0x0c80, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);
}

TEST_F(LeCreateConnectionTest, InvalidSupervisionTimeout) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010, 0x9,
                0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c81, 0x0, 0x0),
            ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x1f3,
                0x0c80, 0x0, 0x0),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeCreateConnectionTest, NoRandomAddress) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::RANDOM_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS, 0x100, 0x200,
                0x010, 0x0c80, 0x0, 0x0),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

}  // namespace rootcanal
