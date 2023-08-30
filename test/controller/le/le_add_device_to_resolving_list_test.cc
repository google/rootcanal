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

class LeAddDeviceToResolvingListTest : public ::testing::Test {
 public:
  LeAddDeviceToResolvingListTest() {
    // Reduce the size of the resolving list to simplify testing.
    properties_.le_resolving_list_size = 2;
  }

  ~LeAddDeviceToResolvingListTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeAddDeviceToResolvingListTest, Success) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{2}, std::array<uint8_t, 16>{2}),
            ErrorCode::SUCCESS);
}

TEST_F(LeAddDeviceToResolvingListTest, ListFull) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{2},
                std::array<uint8_t, 16>{2}, std::array<uint8_t, 16>{2}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{3},
                std::array<uint8_t, 16>{3}, std::array<uint8_t, 16>{3}),
            ErrorCode::MEMORY_CAPACITY_EXCEEDED);
}

TEST_F(LeAddDeviceToResolvingListTest, ScanningActive) {
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
  controller_.LeSetScanEnable(true, false);

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeAddDeviceToResolvingListTest, LegacyAdvertisingActive) {
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAdvertisingEnable(true), ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeAddDeviceToResolvingListTest, ExtendedAdvertisingActive) {
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
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

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeAddDeviceToResolvingListTest, PeerAddressDuplicate) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{2}, std::array<uint8_t, 16>{2}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeAddDeviceToResolvingListTest, PeerIrkDuplicate) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeAddDeviceToResolvingListTest, EmptyPeerIrkDuplicate) {
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{0}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{0}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);
}

}  // namespace rootcanal
