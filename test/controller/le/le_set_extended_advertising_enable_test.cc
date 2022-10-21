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

class LeSetExtendedAdvertisingEnableTest : public ::testing::Test {
 public:
  LeSetExtendedAdvertisingEnableTest() {
    // Reduce the number of advertising sets to simplify testing.
    properties_.le_num_supported_advertising_sets = 2;
    properties_.le_max_advertising_data_length = 2000;
  };
  ~LeSetExtendedAdvertisingEnableTest() override = default;

 protected:
  Address address_{0};
  ControllerProperties properties_{};
  LinkLayerController controller_{address_, properties_};
};

TEST_F(LeSetExtendedAdvertisingEnableTest, DisableAll) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(false, {}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, DisableSelected) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                false, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, EnableUsingPublicAddress) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, EnableUsingTimeout) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0x40, 0)}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, EnableUsingRandomAddress) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::RANDOM_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetAdvertisingSetRandomAddress(0, Address{1}),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0x40, 0)}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, EnableUsingResolvableAddress) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeAddDeviceToResolvingList(
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address{1},
                std::array<uint8_t, 16>{1}, std::array<uint8_t, 16>{1}),
            ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);
  // Note: the command will fail if the peer address is not in the resolvable
  // address list and the random address is not set.
  // Success here signifies that the RPA was successfully generated.
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0x40, 0)}),
            ErrorCode::SUCCESS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, DuplicateAdvertisingHandle) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0), MakeEnabledSet(0, 0, 0)}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, UnknownAdvertisingHandle) {
  ASSERT_EQ(
      controller_.LeSetExtendedAdvertisingParameters(
          0, MakeAdvertisingEventProperties(LEGACY | CONNECTABLE | SCANNABLE),
          0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
          PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
          AdvertisingFilterPolicy::ALL_DEVICES, 0x70, PrimaryPhyType::LE_1M, 0,
          SecondaryPhyType::LE_2M, 0x0, false),
      ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0), MakeEnabledSet(1, 0, 0)}),
            ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, MissingAdvertisingHandle) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(true, {}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, InvalidDuration) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0,
                MakeAdvertisingEventProperties(LEGACY | DIRECTED | CONNECTABLE |
                                               HIGH_DUTY_CYCLE),
                0x0800, 0x0800, 0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0x801, 0)}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, PartialAdvertisingData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_advertising_data_fragment = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_advertising_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, PartialScanResponseData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> first_scan_response_data_fragment = {1, 2, 3};
  ASSERT_EQ(controller_.LeSetExtendedScanResponseData(
                0, Operation::FIRST_FRAGMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT,
                first_scan_response_data_fragment),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, EmptyScanResponseData) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(SCANNABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::COMMAND_DISALLOWED);
}

TEST_F(LeSetExtendedAdvertisingEnableTest,
       AdvertisingDataLargerThanPduCapacity) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  advertising_data.resize(254);
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest,
       AdvertisingDataLargerThanMaxPduCapacity) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(0), 0x0800, 0x0800, 0x7,
                OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  std::vector<uint8_t> advertising_data = {1, 2, 3};
  advertising_data.resize(1651);
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingData(
                0, Operation::COMPLETE_ADVERTISEMENT,
                FragmentPreference::CONTROLLER_MAY_FRAGMENT, advertising_data),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::PACKET_TOO_LONG);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, NoRandomAddress) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::RANDOM_DEVICE_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

TEST_F(LeSetExtendedAdvertisingEnableTest, NoResolvableOrRandomAddress) {
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                0, MakeAdvertisingEventProperties(CONNECTABLE), 0x0800, 0x0800,
                0x7, OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS,
                PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                Address::kEmpty, AdvertisingFilterPolicy::ALL_DEVICES, 0x70,
                PrimaryPhyType::LE_1M, 0, SecondaryPhyType::LE_2M, 0x0, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(
                true, {MakeEnabledSet(0, 0, 0)}),
            ErrorCode::INVALID_HCI_COMMAND_PARAMETERS);
}

}  // namespace rootcanal
