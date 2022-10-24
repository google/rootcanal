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

class LeCreateConnectionCancelTest : public ::testing::Test {
 public:
  LeCreateConnectionCancelTest() = default;
  ~LeCreateConnectionCancelTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeCreateConnectionCancelTest, CancelLegacyConnection) {
  ASSERT_EQ(controller_.LeCreateConnection(
                0x200, 0x200, InitiatorFilterPolicy::USE_PEER_ADDRESS,
                AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS},
                OwnAddressType::PUBLIC_DEVICE_ADDRESS, 0x100, 0x200, 0x010,
                0x0c80, 0x0, 0x0),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeCreateConnectionCancel(), ErrorCode::SUCCESS);
}

TEST_F(LeCreateConnectionCancelTest, CancelExtendedConnection) {
  ASSERT_EQ(
      controller_.LeExtendedCreateConnection(
          InitiatorFilterPolicy::USE_PEER_ADDRESS,
          OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          AddressWithType{Address{1}, AddressType::PUBLIC_DEVICE_ADDRESS}, 0x1,
          {MakeInitiatingPhyParameters(0x200, 0x200, 0x100, 0x200, 0x010,
                                       0x0c80, 0x0, 0x0)}),
      ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeCreateConnectionCancel(), ErrorCode::SUCCESS);
}

TEST_F(LeCreateConnectionCancelTest, NoPendingConnection) {
  ASSERT_EQ(controller_.LeCreateConnectionCancel(),
            ErrorCode::COMMAND_DISALLOWED);
}

}  // namespace rootcanal
