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

class LeSetExtendedAdvertisingDataTest : public ::testing::Test {
 public:
  LeSetExtendedAdvertisingDataTest() {
    // Reduce the number of advertising sets to simplify testing.
    properties_.le_num_supported_advertising_sets = 2;
    properties_.le_max_advertising_data_length = 300;
  };
  ~LeSetExtendedAdvertisingDataTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetExtendedAdvertisingDataTest, Complete) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, Unchanged) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::UNCHANGED_DATA,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, Fragmented) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_advertising_data_fragment = {1, 2, 3};
  std::vector<uint8_t> intermediate_advertising_data_fragment = {4, 5, 6};
  std::vector<uint8_t> last_advertising_data_fragment = {7, 8, 9};

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_advertising_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::INTERMEDIATE_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                intermediate_advertising_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::LAST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                last_advertising_data_fragment),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, UnknownAdvertisingHandle) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                1, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER);
}

TEST_F(LeSetExtendedAdvertisingDataTest, UnexpectedAdvertisingData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, IncompleteLegacyAdvertisingData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(LEGACY | SCANNABLE), 0x0800,
                0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_advertising_data_fragment = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_advertising_data_fragment),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, InvalidLegacyAdvertisingData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(LEGACY | SCANNABLE), 0x0800,
                0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  advertising_data.resize(32);
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, UnchangedWhenDisabled) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::UNCHANGED_DATA,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, UnchangedWhenAdvertisingDataEmpty) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::UNCHANGED_DATA,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, UnchangedWhenUsingLegacyAdvertising) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(LEGACY | SCANNABLE), 0x0800,
                0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::UNCHANGED_DATA,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, EmptyAdvertisingDataFragment) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_advertising_data_fragment = {1, 2, 3};
  std::vector<uint8_t> intermediate_advertising_data_fragment = {4, 5, 6};
  std::vector<uint8_t> last_advertising_data_fragment = {7, 8, 9};

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_advertising_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::INTERMEDIATE_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::INTERMEDIATE_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                intermediate_advertising_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::LAST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::LAST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                last_advertising_data_fragment),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingDataTest, AdvertisingEnabled) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_advertising_data_fragment = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_advertising_data_fragment),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetExtendedAdvertisingDataTest,
       AdvertisingDataLargerThanMemoryCapacity) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data_fragment = {1, 2, 3};
  advertising_data_fragment.resize(properties_.le_max_advertising_data_length);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                advertising_data_fragment),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::LAST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                advertising_data_fragment),
            ErrorCode::MEMORY_CAPACITY_EXCEEDED);
}

TEST_F(LeSetExtendedAdvertisingDataTest, AdvertisingDataLargerThanPduCapacity) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);

  // No AUX chain possible for connectable advertising PDUs,
  // the advertising data is limited to one PDU's payload.
  std::vector<uint8_t> advertising_data = {1, 2, 3};
  advertising_data.resize(254);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::PACKET_TOO_LONG);
}

}  // namespace rootcanal
