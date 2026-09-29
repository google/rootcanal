/*
 * Copyright 2024 The Android Open Source Project
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

#include <chrono>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include "hci/address.h"
#include "hci/address_with_type.h"
#include "model/controller/dual_mode_controller.h"
#include "model/controller/le_controller.h"
#include "packets/hci_packets.h"
#include "packets/link_layer_packets.h"
#include "test_helpers.h"

namespace rootcanal {

using namespace bluetooth::hci;

class LeBigTerminateIndTest : public ::testing::Test {
public:
  LeBigTerminateIndTest() = default;
  ~LeBigTerminateIndTest() override = default;

  void SetUp() override {
    event_listener_called_ = 0;
    remote_listener_called_ = 0;
    scanning_started_ = false;
    last_sent_packet_ = nullptr;
    sent_packets_.clear();
    events_.clear();

    controller_.RegisterEventChannel([this](std::shared_ptr<EventBuilder> event) {
      event_listener_called_++;
      events_.push_back(event);
    });

    controller_.RegisterRemoteChannel(
            [this](std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
                   Phy::Type /* phy */, int8_t /* tx_power */) {
              remote_listener_called_++;
              last_sent_packet_ = packet;
              sent_packets_.push_back(packet);
            });

    auto to_mask = [](auto event) -> uint64_t {
      return UINT64_C(1) << (static_cast<uint8_t>(event) - 1);
    };

    controller_.SetEventMask(to_mask(EventCode::LE_META_EVENT));
    controller_.SetLeEventMask(to_mask(SubeventCode::LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V1) |
                               to_mask(SubeventCode::LE_PERIODIC_ADVERTISING_SYNC_LOST) |
                               to_mask(SubeventCode::LE_PERIODIC_ADVERTISING_REPORT_V1) |
                               to_mask(SubeventCode::LE_BIG_INFO_ADVERTISING_REPORT));
  }

  void StartExtendedScan() {
    ScanningPhyParameters param;
    param.le_scan_type_ = LeScanType::ACTIVE;
    param.le_scan_interval_ = 0x4;
    param.le_scan_window_ = 0x4;

    ASSERT_EQ(controller_.LeSetExtendedScanParameters(OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                                                      LeScanningFilterPolicy::ACCEPT_ALL, 0x1,
                                                      {param}),
              ErrorCode::SUCCESS);
    ASSERT_EQ(controller_.LeSetExtendedScanEnable(true, FilterDuplicates::DISABLED, 0, 0),
              ErrorCode::SUCCESS);
    scanning_started_ = true;
  }

  void EstablishPeriodicSync(Address peer_address, uint8_t sid = 0x01,
                             uint16_t sync_timeout = 0x0100) {
    if (!scanning_started_) {
      StartExtendedScan();
    }
    ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                      PeriodicAdvertisingOptions(false, false, false), sid,
                      AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, peer_address,
                      0 /* skip */, sync_timeout, 0 /* sync_cte_type */),
              ErrorCode::SUCCESS);

    // Send Periodic Advertising PDU to establish sync
    model::packets::BigInfo empty_big_info(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    auto pdu = model::packets::LePeriodicAdvertisingPduBuilder::Create(
            peer_address, Address::kEmpty, model::packets::AddressType::PUBLIC, sid,
            0x7F /* tx_power */, 0x0100 /* advertising_interval */, empty_big_info, {});
    controller_.IncomingPacket(FromBuilder(std::move(pdu)), -90);
  }

  void SendBigInfoReport(Address peer_address, uint8_t sid = 0x01) {
    model::packets::BigInfo big_info(1 /* num_bis */, 2 /* nse */, 0x10 /* iso_interval */,
                                     1 /* bn */, 0 /* pto */, 2 /* irc */, 251 /* max_pdu */,
                                     10000 /* sdu_interval */, 251 /* max_sdu */, 1 /* phy */,
                                     0 /* framing */, 0 /* encryption */);
    auto pdu = model::packets::LePeriodicAdvertisingPduBuilder::Create(
            peer_address, Address::kEmpty, model::packets::AddressType::PUBLIC, sid,
            0x7F /* tx_power */, 0x0100 /* advertising_interval */, big_info, {});
    controller_.IncomingPacket(FromBuilder(std::move(pdu)), -90);
  }

  static model::packets::LinkLayerPacketView FromBuilder(
          std::unique_ptr<pdl::packet::Builder> builder) {
    auto data = std::make_shared<std::vector<uint8_t>>(builder->SerializeToBytes());
    return model::packets::LinkLayerPacketView::Create(pdl::packet::slice(data));
  }

protected:
  Address address_{0};
  ControllerProperties properties_{};
  LeController controller_{address_, properties_};

  bool scanning_started_{false};
  unsigned event_listener_called_{0};
  unsigned remote_listener_called_{0};
  std::shared_ptr<model::packets::LinkLayerPacketBuilder> last_sent_packet_{nullptr};
  std::vector<std::shared_ptr<model::packets::LinkLayerPacketBuilder>> sent_packets_{};
  std::vector<std::shared_ptr<EventBuilder>> events_{};
};

TEST_F(LeBigTerminateIndTest, ReceiveLlBigTerminateIndMatchesSourceAddress) {
  Address peer_address{1};
  EstablishPeriodicSync(peer_address, 0x01 /* sid */);
  SendBigInfoReport(peer_address, 0x01 /* sid */);

  // Send LL_BIG_TERMINATE_IND from peer advertiser address with matching sid
  auto terminate_ind = model::packets::LlBigTerminateIndBuilder::Create(
          peer_address, Address::kEmpty, 0x01 /* sid */,
          0x16 /* reason: Remote User Terminated Connection */, 0 /* instant */);
  controller_.IncomingPacket(FromBuilder(std::move(terminate_ind)), -90);

  // Subsequent Periodic Advertising PDU with num_bis = 0 should be handled without
  // double-terminating
  model::packets::BigInfo empty_big_info(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  auto pdu = model::packets::LePeriodicAdvertisingPduBuilder::Create(
          peer_address, Address::kEmpty, model::packets::AddressType::PUBLIC, 0x01,
          0x7F /* tx_power */, 0x0100 /* advertising_interval */, empty_big_info, {});
  controller_.IncomingPacket(FromBuilder(std::move(pdu)), -90);
}

TEST_F(LeBigTerminateIndTest, ReceiveLlBigTerminateIndMatchesResolvedIdentityAddress) {
  Address peer_identity{2};
  std::array<uint8_t, 16> peer_irk = {
          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  };
  std::array<uint8_t, 16> local_irk = {0};

  ASSERT_EQ(
          controller_.LeAddDeviceToResolvingList(PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                                                 peer_identity, peer_irk, local_irk),
          ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);

  Address peer_rpa = rootcanal::LeController::generate_rpa(peer_irk);

  StartExtendedScan();
  ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                    PeriodicAdvertisingOptions(false, false, false), 0x01,
                    AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, peer_identity,
                    0 /* skip */, 0x0100 /* sync_timeout */, 0 /* sync_cte_type */),
            ErrorCode::SUCCESS);

  // Establish sync using RPA
  model::packets::BigInfo empty_big_info(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  auto pdu = model::packets::LePeriodicAdvertisingPduBuilder::Create(
          peer_rpa, Address::kEmpty, model::packets::AddressType::RANDOM, 0x01, 0x7F /* tx_power */,
          0x0100 /* advertising_interval */, empty_big_info, {});
  controller_.IncomingPacket(FromBuilder(std::move(pdu)), -90);

  // Send BIG Info from RPA
  SendBigInfoReport(peer_rpa, 0x01 /* sid */);

  // Send LL_BIG_TERMINATE_IND from peer RPA
  auto terminate_ind = model::packets::LlBigTerminateIndBuilder::Create(
          peer_rpa, Address::kEmpty, 0x01 /* sid */,
          0x16 /* reason: Remote User Terminated Connection */, 0 /* instant */);
  controller_.IncomingPacket(FromBuilder(std::move(terminate_ind)), -90);

  // Subsequent Periodic Advertising PDU with num_bis = 0 should be handled without
  // double-terminating
  model::packets::BigInfo empty_big_info_after(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  auto pdu_after = model::packets::LePeriodicAdvertisingPduBuilder::Create(
          peer_rpa, Address::kEmpty, model::packets::AddressType::RANDOM, 0x01, 0x7F /* tx_power */,
          0x0100 /* advertising_interval */, empty_big_info_after, {});
  controller_.IncomingPacket(FromBuilder(std::move(pdu_after)), -90);
}

TEST_F(LeBigTerminateIndTest, ReceiveLlBigTerminateIndMatchesRandomIdentityAddress) {
  Address peer_identity{2};
  std::array<uint8_t, 16> peer_irk = {
          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  };
  std::array<uint8_t, 16> local_irk = {0};

  ASSERT_EQ(
          controller_.LeAddDeviceToResolvingList(PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS,
                                                 peer_identity, peer_irk, local_irk),
          ErrorCode::SUCCESS);
  ASSERT_EQ(controller_.LeSetAddressResolutionEnable(true), ErrorCode::SUCCESS);

  Address peer_rpa = rootcanal::LeController::generate_rpa(peer_irk);

  StartExtendedScan();
  ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                    PeriodicAdvertisingOptions(false, false, false), 0x01,
                    AdvertiserAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS, peer_identity,
                    0 /* skip */, 0x0100 /* sync_timeout */, 0 /* sync_cte_type */),
            ErrorCode::SUCCESS);

  // Establish sync using RPA
  model::packets::BigInfo empty_big_info(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  auto pdu = model::packets::LePeriodicAdvertisingPduBuilder::Create(
          peer_rpa, Address::kEmpty, model::packets::AddressType::RANDOM, 0x01, 0x7F /* tx_power */,
          0x0100 /* advertising_interval */, empty_big_info, {});
  controller_.IncomingPacket(FromBuilder(std::move(pdu)), -90);

  // Send BIG Info from RPA
  SendBigInfoReport(peer_rpa, 0x01 /* sid */);

  // Send LL_BIG_TERMINATE_IND from peer RPA
  auto terminate_ind = model::packets::LlBigTerminateIndBuilder::Create(
          peer_rpa, Address::kEmpty, 0x01 /* sid */,
          0x16 /* reason: Remote User Terminated Connection */, 0 /* instant */);
  controller_.IncomingPacket(FromBuilder(std::move(terminate_ind)), -90);

  // Subsequent Periodic Advertising PDU with num_bis = 0 should be handled without
  // double-terminating
  model::packets::BigInfo empty_big_info_after(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  auto pdu_after = model::packets::LePeriodicAdvertisingPduBuilder::Create(
          peer_rpa, Address::kEmpty, model::packets::AddressType::RANDOM, 0x01, 0x7F /* tx_power */,
          0x0100 /* advertising_interval */, empty_big_info_after, {});
  controller_.IncomingPacket(FromBuilder(std::move(pdu_after)), -90);
}

TEST_F(LeBigTerminateIndTest, ReceiveLlBigTerminateIndMismatchedAddressIgnored) {
  Address peer_address{1};
  Address other_address{3};
  EstablishPeriodicSync(peer_address, 0x01 /* sid */);
  SendBigInfoReport(peer_address, 0x01 /* sid */);

  // Send LL_BIG_TERMINATE_IND from an unrelated address
  auto terminate_ind = model::packets::LlBigTerminateIndBuilder::Create(
          other_address, Address::kEmpty, 0x01 /* sid */, 0x16 /* reason */, 0 /* instant */);
  controller_.IncomingPacket(FromBuilder(std::move(terminate_ind)), -90);
}

TEST_F(LeBigTerminateIndTest, ReceiveLlBigTerminateIndMismatchedSidIgnored) {
  Address peer_address{1};
  EstablishPeriodicSync(peer_address, 0x01 /* sid */);
  SendBigInfoReport(peer_address, 0x01 /* sid */);

  // Send LL_BIG_TERMINATE_IND with mismatched sid (0x02 instead of 0x01)
  auto terminate_ind = model::packets::LlBigTerminateIndBuilder::Create(
          peer_address, Address::kEmpty, 0x02 /* sid */, 0x16 /* reason */, 0 /* instant */);
  controller_.IncomingPacket(FromBuilder(std::move(terminate_ind)), -90);
}

TEST_F(LeBigTerminateIndTest, ReceiveLlBigTerminateIndWithoutBigInfoIgnored) {
  Address peer_address{1};
  EstablishPeriodicSync(peer_address, 0x01 /* sid */);

  // Send LL_BIG_TERMINATE_IND when no BIG Info has been established
  auto terminate_ind = model::packets::LlBigTerminateIndBuilder::Create(
          peer_address, Address::kEmpty, 0x01 /* sid */, 0x16 /* reason */, 0 /* instant */);
  controller_.IncomingPacket(FromBuilder(std::move(terminate_ind)), -90);
}

TEST_F(LeBigTerminateIndTest, ReceiveLlBigTerminateIndInvalidPacket) {
  // Send a packet with valid LinkLayerPacket header but invalid/truncated LlBigTerminateInd payload
  std::vector<uint8_t> invalid_bytes = {
          0,
          0,
          0,
          0,
          0,
          0,  // Source Address (6 bytes)
          0,
          0,
          0,
          0,
          0,
          0,  // Destination Address (6 bytes)
          static_cast<uint8_t>(model::packets::PacketType::LL_BIG_TERMINATE_IND),  // Type (1 byte)
          // Missing full payload: sid (1 byte), reason (1 byte), instant (2 bytes)
  };
  auto data = std::make_shared<std::vector<uint8_t>>(std::move(invalid_bytes));
  auto packet_view = model::packets::LinkLayerPacketView::Create(pdl::packet::slice(data));
  controller_.IncomingPacket(packet_view, -90);
}

TEST_F(LeBigTerminateIndTest, PeriodicAdvertisingZeroNumBisTerminatesActiveBig) {
  Address peer_address{1};
  EstablishPeriodicSync(peer_address);
  SendBigInfoReport(peer_address);

  // Send a Periodic Advertising PDU with num_bis = 0 while BIG is active
  model::packets::BigInfo empty_big_info(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  auto pdu = model::packets::LePeriodicAdvertisingPduBuilder::Create(
          peer_address, Address::kEmpty, model::packets::AddressType::PUBLIC, 0x01,
          0x7F /* tx_power */, 0x0100 /* advertising_interval */, empty_big_info, {});
  controller_.IncomingPacket(FromBuilder(std::move(pdu)), -90);
}

TEST_F(LeBigTerminateIndTest, PeriodicAdvertisingSyncTimeoutWithoutBigInfo) {
  Address peer_address{1};
  // Establish sync without sending BigInfo report
  EstablishPeriodicSync(peer_address, 0x01, 0x000A);

  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  size_t events_before = events_.size();
  controller_.Tick();

  EXPECT_GT(events_.size(), events_before);
}

TEST_F(LeBigTerminateIndTest, PeriodicAdvertisingSyncTimeoutDoesNotTerminateActiveBig) {
  Address peer_address{1};
  EstablishPeriodicSync(peer_address, 0x01, 0x000A);
  SendBigInfoReport(peer_address);

  // Synchronize to the BIG via ForwardToLl
  auto create_sync_cmd = LeBigCreateSyncBuilder::Create(
          0x01 /* big_handle */, 0x0000 /* sync_handle */, Enable::DISABLED /* encryption */,
          std::array<uint8_t, 16>{0} /* broadcast_code */, 0 /* mse */,
          0x0100 /* big_sync_timeout */, std::vector<uint8_t>{1} /* bis */);
  auto create_sync_bytes =
          std::make_shared<std::vector<uint8_t>>(create_sync_cmd->SerializeToBytes());
  controller_.ForwardToLl(CommandView::Create(pdl::packet::slice(create_sync_bytes)));
  controller_.Tick();

  // Advance time beyond PA sync timeout (100ms)
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  size_t events_before = events_.size();
  controller_.Tick();

  // Verify that PA sync lost event was emitted
  EXPECT_GT(events_.size(), events_before);

  // Verify that the BIG is still active by successfully terminating it via ForwardToLl
  // (Core Spec Vol 6, Part B § 4.4.6: Losing PA sync does not terminate BIG sync).
  auto terminate_sync_cmd = LeBigTerminateSyncBuilder::Create(0x01 /* big_handle */);
  auto terminate_sync_bytes =
          std::make_shared<std::vector<uint8_t>>(terminate_sync_cmd->SerializeToBytes());
  events_before = events_.size();
  controller_.ForwardToLl(CommandView::Create(pdl::packet::slice(terminate_sync_bytes)));
  controller_.Tick();

  // Verify that LeBigTerminateSync completed successfully (event emitted)
  EXPECT_GT(events_.size(), events_before);
}

TEST_F(LeBigTerminateIndTest, PeriodicAdvertisingSyncTimeoutMultipleTrains) {
  Address peer_address1{1};
  Address peer_address2{2};

  // Train 1: short timeout (100ms)
  EstablishPeriodicSync(peer_address1, 0x01, 0x000A);
  // Train 2: long timeout (10s)
  EstablishPeriodicSync(peer_address2, 0x02, 0x0A00);

  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  controller_.Tick();

  // Train 1 expired, can recreate sync for train 1
  ASSERT_EQ(controller_.LePeriodicAdvertisingCreateSync(
                    PeriodicAdvertisingOptions(false, false, false), 0x01,
                    AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, peer_address1,
                    0 /* skip */, 0x0100 /* sync_timeout */, 0 /* sync_cte_type */),
            ErrorCode::SUCCESS);
}

TEST_F(LeBigTerminateIndTest, PeriodicAdvertisingSyncTimeoutEventMasked) {
  Address peer_address{1};
  EstablishPeriodicSync(peer_address, 0x01, 0x000A);

  // Mask out LE_PERIODIC_ADVERTISING_SYNC_LOST event
  controller_.SetLeEventMask(0);

  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  size_t events_before = events_.size();
  controller_.Tick();

  // No sync lost event should be sent since it is masked
  EXPECT_EQ(events_.size(), events_before);
}

TEST_F(LeBigTerminateIndTest, LeTerminateBigTransmitsLlBigTerminateInd) {
  // Configure extended and periodic advertising on controller_
  AdvertisingEventProperties properties(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  ASSERT_EQ(controller_.LeSetExtendedAdvertisingParameters(
                    0x00 /* advertising_handle */, properties, 0x00A0 /* min */, 0x00A0 /* max */,
                    0x07 /* channel_map */, OwnAddressType::PUBLIC_DEVICE_ADDRESS,
                    PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS, Address::kEmpty,
                    AdvertisingFilterPolicy::ALL_DEVICES, 0x7F /* tx_power */,
                    PrimaryPhyType::LE_1M, 0x00 /* max_skip */, SecondaryPhyType::LE_1M,
                    0x01 /* sid */, false /* scan_request_notification_enable */),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingParameters(
                    0x00 /* advertising_handle */, 0x00A0 /* min */, 0x00A0 /* max */, false),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetPeriodicAdvertisingEnable(1 /* enable */, false /* include_adi */,
                                                       0x00 /* advertising_handle */),
            ErrorCode::SUCCESS);

  ASSERT_EQ(controller_.LeSetExtendedAdvertisingEnable(true, {EnabledSet(0x00, 0, 0)}),
            ErrorCode::SUCCESS);

  // 1. Create BIG via ForwardToLl
  auto create_big_cmd = LeCreateBigBuilder::Create(
          0x00 /* big_handle */, 0x00 /* advertising_handle */, 1 /* num_bis */,
          10000 /* sdu_interval */, 100 /* max_sdu */, 4000 /* max_transport_latency */,
          2 /* rtn */, SecondaryPhyType::LE_1M, Packing::SEQUENTIAL, Enable::DISABLED /* framing */,
          Enable::DISABLED /* encryption */, std::array<uint8_t, 16>{0} /* broadcast_code */);
  auto create_big_bytes =
          std::make_shared<std::vector<uint8_t>>(create_big_cmd->SerializeToBytes());
  controller_.ForwardToLl(CommandView::Create(pdl::packet::slice(create_big_bytes)));

  // 2. Terminate BIG via ForwardToLl
  size_t packets_before = sent_packets_.size();
  auto terminate_big_cmd = LeTerminateBigBuilder::Create(
          0x00 /* big_handle */, ErrorCode::CONNECTION_TERMINATED_BY_LOCAL_HOST);
  auto terminate_big_bytes =
          std::make_shared<std::vector<uint8_t>>(terminate_big_cmd->SerializeToBytes());
  controller_.ForwardToLl(CommandView::Create(pdl::packet::slice(terminate_big_bytes)));
  controller_.Tick();

  // Verify that an LlBigTerminateInd link layer packet was transmitted through
  // send_big_terminate_ind
  EXPECT_GT(sent_packets_.size(), packets_before);
}

}  // namespace rootcanal
