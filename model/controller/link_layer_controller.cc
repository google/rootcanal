/*
 * Copyright 2017 The Android Open Source Project
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

#include "model/controller/link_layer_controller.h"

#include <packet_runtime.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "crypto/crypto.h"
#include "hci/address.h"
#include "hci/address_with_type.h"
#include "log.h"
#include "model/controller/acl_connection.h"
#include "model/controller/acl_connection_handler.h"
#include "model/controller/controller_properties.h"
#include "model/controller/le_advertiser.h"
#include "model/controller/sco_connection.h"
#include "packets/hci_packets.h"
#include "packets/link_layer_packets.h"
#include "phy.h"
#include "rust/include/rootcanal_rs.h"

using namespace std::chrono;
using bluetooth::hci::Address;
using bluetooth::hci::AddressType;
using bluetooth::hci::AddressWithType;
using bluetooth::hci::LLFeaturesBits;
using bluetooth::hci::SubeventCode;

using namespace model::packets;
using namespace std::literals;

using TaskId = rootcanal::LinkLayerController::TaskId;

namespace rootcanal {

constexpr milliseconds kScanRequestTimeout(200);
constexpr milliseconds kNoDelayMs(0);
constexpr milliseconds kPageInterval(1000);

const Address& LinkLayerController::GetAddress() const { return address_; }

AddressWithType PeerDeviceAddress(Address address,
                                  PeerAddressType peer_address_type) {
  switch (peer_address_type) {
    case PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS:
      return AddressWithType(address, AddressType::PUBLIC_DEVICE_ADDRESS);
    case PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS:
      return AddressWithType(address, AddressType::RANDOM_DEVICE_ADDRESS);
  }
}

AddressWithType PeerIdentityAddress(Address address,
                                    PeerAddressType peer_address_type) {
  switch (peer_address_type) {
    case PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS:
      return AddressWithType(address, AddressType::PUBLIC_IDENTITY_ADDRESS);
    case PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS:
      return AddressWithType(address, AddressType::RANDOM_IDENTITY_ADDRESS);
  }
}

bool LinkLayerController::IsEventUnmasked(EventCode event) const {
  uint64_t bit = UINT64_C(1) << (static_cast<uint8_t>(event) - 1);
  return (event_mask_ & bit) != 0;
}

bool LinkLayerController::IsLeEventUnmasked(SubeventCode subevent) const {
  uint64_t bit = UINT64_C(1) << (static_cast<uint8_t>(subevent) - 1);
  return IsEventUnmasked(EventCode::LE_META_EVENT) &&
         (le_event_mask_ & bit) != 0;
}

bool LinkLayerController::FilterAcceptListBusy() {
  // Filter Accept List cannot be modified when
  //  • any advertising filter policy uses the Filter Accept List and
  //    advertising is enabled,
  if (legacy_advertiser_.IsEnabled() &&
      legacy_advertiser_.advertising_filter_policy !=
          bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES) {
    return true;
  }

  for (auto const& [_, advertiser] : extended_advertisers_) {
    if (advertiser.IsEnabled() &&
        advertiser.advertising_filter_policy !=
            bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES) {
      return true;
    }
  }

  //  • the scanning filter policy uses the Filter Accept List and scanning
  //    is enabled,
  if (scanner_.IsEnabled() &&
      (scanner_.scan_filter_policy ==
           bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY ||
       scanner_.scan_filter_policy ==
           bluetooth::hci::LeScanningFilterPolicy::
               FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY)) {
    return true;
  }

  //  • the initiator filter policy uses the Filter Accept List and an
  //    HCI_LE_Create_Connection or HCI_LE_Extended_Create_Connection
  //    command is pending.
  if (initiator_.IsEnabled() &&
      initiator_.initiator_filter_policy ==
          bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST) {
    return true;
  }

  return false;
}

bool LinkLayerController::LeFilterAcceptListContainsDevice(
    FilterAcceptListAddressType address_type, Address address) {
  for (auto const& entry : le_filter_accept_list_) {
    if (entry.address_type == address_type &&
        (address_type == FilterAcceptListAddressType::ANONYMOUS_ADVERTISERS ||
         entry.address == address)) {
      return true;
    }
  }

  return false;
}

bool LinkLayerController::LePeriodicAdvertiserListContainsDevice(
    bluetooth::hci::AdvertiserAddressType advertiser_address_type,
    Address advertiser_address, uint8_t advertising_sid) {
  for (auto const& entry : le_periodic_advertiser_list_) {
    if (entry.advertiser_address_type == advertiser_address_type &&
        entry.advertiser_address == advertiser_address &&
        entry.advertising_sid == advertising_sid) {
      return true;
    }
  }

  return false;
}

bool LinkLayerController::LeFilterAcceptListContainsDevice(
    AddressWithType address) {
  FilterAcceptListAddressType address_type;
  switch (address.GetAddressType()) {
    case AddressType::PUBLIC_DEVICE_ADDRESS:
    case AddressType::PUBLIC_IDENTITY_ADDRESS:
      address_type = FilterAcceptListAddressType::PUBLIC;
      break;
    case AddressType::RANDOM_DEVICE_ADDRESS:
    case AddressType::RANDOM_IDENTITY_ADDRESS:
      address_type = FilterAcceptListAddressType::RANDOM;
      break;
  }

  return LeFilterAcceptListContainsDevice(address_type, address.GetAddress());
}

bool LinkLayerController::ResolvingListBusy() {
  // The resolving list cannot be modified when
  //  • Advertising (other than periodic advertising) is enabled,
  if (legacy_advertiser_.IsEnabled()) {
    return true;
  }

  for (auto const& [_, advertiser] : extended_advertisers_) {
    if (advertiser.IsEnabled()) {
      return true;
    }
  }

  //  • Scanning is enabled,
  if (scanner_.IsEnabled()) {
    return true;
  }

  //  • an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
  //    HCI_LE_Periodic_Advertising_Create_Sync command is pending.
  if (initiator_.IsEnabled()) {
    return true;
  }

  return false;
}

std::optional<AddressWithType> LinkLayerController::ResolvePrivateAddress(
    AddressWithType address) {
  if (!address.IsRpa()) {
    return address;
  }

  if (!le_resolving_list_enabled_) {
    return {};
  }

  for (auto& entry : le_resolving_list_) {
    if (address.IsRpaThatMatchesIrk(entry.peer_irk)) {
      // Update the peer resolvable address used for the peer
      // with the returned identity address.
      entry.peer_resolvable_address = address.GetAddress();

      return PeerDeviceAddress(entry.peer_identity_address,
                               entry.peer_identity_address_type);
    }
  }

  return {};
}

bool LinkLayerController::ResolveTargetA(AddressWithType target_a,
                                         AddressWithType adv_a) {
  if (!le_resolving_list_enabled_) {
    return false;
  }

  for (auto const& entry : le_resolving_list_) {
    if (adv_a == PeerDeviceAddress(entry.peer_identity_address,
                                   entry.peer_identity_address_type) &&
        target_a.IsRpaThatMatchesIrk(entry.local_irk)) {
      return true;
    }
  }

  return false;
}

bool LinkLayerController::ValidateTargetA(AddressWithType target_a,
                                          AddressWithType adv_a) {
  if (IsLocalPublicOrRandomAddress(target_a)) {
    return true;
  }
  if (target_a.IsRpa()) {
    return ResolveTargetA(target_a, adv_a);
  }
  return false;
}

std::optional<AddressWithType>
LinkLayerController::GenerateResolvablePrivateAddress(AddressWithType address,
                                                      IrkSelection irk) {
  for (auto& entry : le_resolving_list_) {
    if (address.GetAddress() == entry.peer_identity_address &&
        address.ToPeerAddressType() == entry.peer_identity_address_type) {
      std::array<uint8_t, LinkLayerController::kIrkSize> const& used_irk =
          irk == IrkSelection::Local ? entry.local_irk : entry.peer_irk;
      Address local_resolvable_address = generate_rpa(used_irk);

      // Update the local resolvable address used for the peer
      // with the returned identity address.
      if (irk == IrkSelection::Local) {
        entry.local_resolvable_address = local_resolvable_address;
      }

      return AddressWithType{local_resolvable_address,
                             AddressType::RANDOM_DEVICE_ADDRESS};
    }
  }

  return {};
}

// =============================================================================
//  BR/EDR Commands
// =============================================================================

// HCI Read Rssi command (Vol 4, Part E § 7.5.4).
ErrorCode LinkLayerController::ReadRssi(uint16_t connection_handle,
                                        int8_t* rssi) {
  // Not documented: If the connection handle is not found, the Controller
  // shall return the error code Unknown Connection Identifier (0x02).
  if (!connections_.HasHandle(connection_handle)) {
    INFO(id_, "unknown connection identifier");
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  *rssi = connections_.GetRssi(connection_handle);
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  General LE Commands
// =============================================================================

// HCI LE Set Random Address command (Vol 4, Part E § 7.8.4).
ErrorCode LinkLayerController::LeSetRandomAddress(Address random_address) {
  // If the Host issues this command when any of advertising (created using
  // legacy advertising commands), scanning, or initiating are enabled,
  // the Controller shall return the error code Command Disallowed (0x0C).
  if (legacy_advertiser_.IsEnabled() || scanner_.IsEnabled() ||
      initiator_.IsEnabled()) {
    INFO(id_, "advertising, scanning or initiating are currently active");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (random_address == Address::kEmpty) {
    INFO(id_, "the random address may not be set to 00:00:00:00:00:00");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  random_address_ = random_address;
  return ErrorCode::SUCCESS;
}

// HCI LE Set Host Feature command (Vol 4, Part E § 7.8.45).
ErrorCode LinkLayerController::LeSetResolvablePrivateAddressTimeout(
    uint16_t rpa_timeout) {
  // Note: no documented status code for this case.
  if (rpa_timeout < 0x1 || rpa_timeout > 0x0e10) {
    INFO(id_,
         "rpa_timeout (0x{:04x}) is outside the range of supported values "
         " 0x1 - 0x0e10",
         rpa_timeout);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  resolvable_private_address_timeout_ = seconds(rpa_timeout);
  return ErrorCode::SUCCESS;
}

// HCI LE Read Phy command (Vol 4, Part E § 7.8.47).
ErrorCode LinkLayerController::LeReadPhy(uint16_t connection_handle,
                                         bluetooth::hci::PhyType* tx_phy,
                                         bluetooth::hci::PhyType* rx_phy) {
  // Note: no documented status code for this case.
  if (!connections_.HasHandle(connection_handle) ||
      connections_.GetPhyType(connection_handle) != Phy::Type::LOW_ENERGY) {
    INFO(id_, "unknown or invalid connection handle");
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  AclConnection const& connection =
      connections_.GetAclConnection(connection_handle);
  *tx_phy = connection.GetTxPhy();
  *rx_phy = connection.GetRxPhy();
  return ErrorCode::SUCCESS;
}

// HCI LE Set Default Phy command (Vol 4, Part E § 7.8.48).
ErrorCode LinkLayerController::LeSetDefaultPhy(
    bool all_phys_no_transmit_preference, bool all_phys_no_receive_preference,
    uint8_t tx_phys, uint8_t rx_phys) {
  uint8_t supported_phys = properties_.LeSupportedPhys();

  // If the All_PHYs parameter specifies that the Host has no preference,
  // the TX_PHYs parameter shall be ignored; otherwise at least one bit shall
  // be set to 1.
  if (all_phys_no_transmit_preference) {
    tx_phys = supported_phys;
  }
  if (tx_phys == 0) {
    INFO(id_, "TX_Phys does not configure any bit");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the All_PHYs parameter specifies that the Host has no preference,
  // the RX_PHYs parameter shall be ignored; otherwise at least one bit shall
  // be set to 1.
  if (all_phys_no_receive_preference) {
    rx_phys = supported_phys;
  }
  if (rx_phys == 0) {
    INFO(id_, "RX_Phys does not configure any bit");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the Host sets, in the TX_PHYs or RX_PHYs parameter, a bit for a PHY that
  // the Controller does not support, including a bit that is reserved for
  // future use, the Controller shall return the error code Unsupported Feature
  // or Parameter Value (0x11).
  if ((tx_phys & ~supported_phys) != 0) {
    INFO(id_, "TX_PhyS {:x} configures unsupported or reserved bits", tx_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }
  if ((rx_phys & ~supported_phys) != 0) {
    INFO(id_, "RX_PhyS {:x} configures unsupported or reserved bits", rx_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  default_tx_phys_ = tx_phys;
  default_rx_phys_ = rx_phys;
  return ErrorCode::SUCCESS;
}

// HCI LE Set Phy command (Vol 4, Part E § 7.8.49).
ErrorCode LinkLayerController::LeSetPhy(
    uint16_t connection_handle, bool all_phys_no_transmit_preference,
    bool all_phys_no_receive_preference, uint8_t tx_phys, uint8_t rx_phys,
    bluetooth::hci::PhyOptions /*phy_options*/) {
  uint8_t supported_phys = properties_.LeSupportedPhys();

  // Note: no documented status code for this case.
  if (!connections_.HasHandle(connection_handle) ||
      connections_.GetPhyType(connection_handle) != Phy::Type::LOW_ENERGY) {
    INFO(id_, "unknown or invalid connection handle");
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // If the All_PHYs parameter specifies that the Host has no preference,
  // the TX_PHYs parameter shall be ignored; otherwise at least one bit shall
  // be set to 1.
  if (all_phys_no_transmit_preference) {
    tx_phys = supported_phys;
  }
  if (tx_phys == 0) {
    INFO(id_, "TX_Phys does not configure any bit");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the All_PHYs parameter specifies that the Host has no preference,
  // the RX_PHYs parameter shall be ignored; otherwise at least one bit shall
  // be set to 1.
  if (all_phys_no_receive_preference) {
    rx_phys = supported_phys;
  }
  if (rx_phys == 0) {
    INFO(id_, "RX_Phys does not configure any bit");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the Host sets, in the TX_PHYs or RX_PHYs parameter, a bit for a PHY that
  // the Controller does not support, including a bit that is reserved for
  // future use, the Controller shall return the error code Unsupported Feature
  // or Parameter Value (0x11).
  if ((tx_phys & ~supported_phys) != 0) {
    INFO(id_, "TX_PhyS ({:x}) configures unsupported or reserved bits",
         tx_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }
  if ((rx_phys & ~supported_phys) != 0) {
    INFO(id_, "RX_PhyS ({:x}) configures unsupported or reserved bits",
         rx_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The HCI_LE_PHY_Update_Complete event shall be generated either when one
  // or both PHY changes or when the Controller determines that neither PHY
  // will change immediately.
  SendLeLinkLayerPacket(model::packets::LlPhyReqBuilder::Create(
      connections_.GetOwnAddress(connection_handle).GetAddress(),
      connections_.GetAddress(connection_handle).GetAddress(), tx_phys,
      rx_phys));

  connections_.GetAclConnection(connection_handle).InitiatePhyUpdate();
  requested_tx_phys_ = tx_phys;
  requested_rx_phys_ = rx_phys;
  return ErrorCode::SUCCESS;
}

// Helper to pick one phy in enabled phys.
static bluetooth::hci::PhyType select_phy(uint8_t phys,
                                          bluetooth::hci::PhyType current) {
  return (phys & 0x4)   ? bluetooth::hci::PhyType::LE_CODED
         : (phys & 0x2) ? bluetooth::hci::PhyType::LE_2M
         : (phys & 0x1) ? bluetooth::hci::PhyType::LE_1M
                        : current;
}

// Helper to generate the LL_PHY_UPDATE_IND mask for the selected phy.
// The mask is non zero only if the phy has changed.
static uint8_t indicate_phy(bluetooth::hci::PhyType selected,
                            bluetooth::hci::PhyType current) {
  return selected == current                             ? 0x0
         : selected == bluetooth::hci::PhyType::LE_CODED ? 0x4
         : selected == bluetooth::hci::PhyType::LE_2M    ? 0x2
                                                         : 0x1;
}

void LinkLayerController::IncomingLlPhyReq(
    model::packets::LinkLayerPacketView incoming) {
  auto phy_req = model::packets::LlPhyReqView::Create(incoming);
  ASSERT(phy_req.IsValid());
  uint16_t connection_handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());

  if (connection_handle == kReservedHandle) {
    INFO(id_, "@{}: Unknown connection @{}", incoming.GetDestinationAddress(),
         incoming.GetSourceAddress());
    return;
  }

  AclConnection& connection = connections_.GetAclConnection(connection_handle);

  if (connection.GetRole() == bluetooth::hci::Role::PERIPHERAL) {
    // Peripheral receives the request: respond with local phy preferences
    // in LL_PHY_RSP pdu.
    SendLeLinkLayerPacket(model::packets::LlPhyRspBuilder::Create(
        incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
        default_tx_phys_, default_rx_phys_));
  } else {
    // Central receives the request: respond with LL_PHY_UPDATE_IND and
    // the selected phys.

    // Intersect phy preferences with local preferences.
    uint8_t tx_phys = phy_req.GetRxPhys() & default_tx_phys_;
    uint8_t rx_phys = phy_req.GetTxPhys() & default_rx_phys_;

    // Select valid TX and RX phys from preferences.
    bluetooth::hci::PhyType phy_c_to_p =
        select_phy(tx_phys, connection.GetTxPhy());
    bluetooth::hci::PhyType phy_p_to_c =
        select_phy(rx_phys, connection.GetRxPhy());

    // Send LL_PHY_UPDATE_IND to notify selected phys.
    //
    // PHY_C_TO_P shall be set to indicate the PHY that shall be used for
    // packets sent from the Central to the Peripheral. These fields each
    // consist of 8 bits. If a PHY is changing, the bit corresponding to the new
    // PHY shall be set to 1 and the remaining bits to 0; if a PHY is remaining
    // unchanged, then the corresponding field shall be set to the value 0.
    SendLeLinkLayerPacket(model::packets::LlPhyUpdateIndBuilder::Create(
        incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
        indicate_phy(phy_c_to_p, connection.GetTxPhy()),
        indicate_phy(phy_p_to_c, connection.GetRxPhy()), 0));

    // Notify the host when the phy selection has changed
    // (responder in this case).
    if ((phy_c_to_p != connection.GetTxPhy() ||
         phy_p_to_c != connection.GetRxPhy()) &&
        IsLeEventUnmasked(SubeventCode::PHY_UPDATE_COMPLETE)) {
      send_event_(bluetooth::hci::LePhyUpdateCompleteBuilder::Create(
          ErrorCode::SUCCESS, connection_handle, phy_c_to_p, phy_p_to_c));
    }

    // Update local state.
    connection.SetTxPhy(phy_c_to_p);
    connection.SetRxPhy(phy_p_to_c);
  }
}

void LinkLayerController::IncomingLlPhyRsp(
    model::packets::LinkLayerPacketView incoming) {
  auto phy_rsp = model::packets::LlPhyRspView::Create(incoming);
  ASSERT(phy_rsp.IsValid());
  uint16_t connection_handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());

  if (connection_handle == kReservedHandle) {
    INFO(id_, "@{}: Unknown connection @{}", incoming.GetDestinationAddress(),
         incoming.GetSourceAddress());
    return;
  }

  AclConnection& connection = connections_.GetAclConnection(connection_handle);
  ASSERT(connection.GetRole() == bluetooth::hci::Role::CENTRAL);

  // Intersect phy preferences with local preferences.
  uint8_t tx_phys = phy_rsp.GetRxPhys() & requested_tx_phys_;
  uint8_t rx_phys = phy_rsp.GetTxPhys() & requested_rx_phys_;

  // Select valid TX and RX phys from preferences.
  bluetooth::hci::PhyType phy_c_to_p =
      select_phy(tx_phys, connection.GetTxPhy());
  bluetooth::hci::PhyType phy_p_to_c =
      select_phy(rx_phys, connection.GetRxPhy());

  // Send LL_PHY_UPDATE_IND to notify selected phys.
  //
  // PHY_C_TO_P shall be set to indicate the PHY that shall be used for
  // packets sent from the Central to the Peripheral. These fields each
  // consist of 8 bits. If a PHY is changing, the bit corresponding to the new
  // PHY shall be set to 1 and the remaining bits to 0; if a PHY is remaining
  // unchanged, then the corresponding field shall be set to the value 0.
  SendLeLinkLayerPacket(model::packets::LlPhyUpdateIndBuilder::Create(
      incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
      indicate_phy(phy_c_to_p, connection.GetTxPhy()),
      indicate_phy(phy_p_to_c, connection.GetRxPhy()), 0));

  // Always notify the host, even if the phy selection has not changed
  // (initiator in this case).
  if (IsLeEventUnmasked(SubeventCode::PHY_UPDATE_COMPLETE)) {
    send_event_(bluetooth::hci::LePhyUpdateCompleteBuilder::Create(
        ErrorCode::SUCCESS, connection_handle, phy_c_to_p, phy_p_to_c));
  }

  // Update local state.
  connection.PhyUpdateComplete();
  connection.SetTxPhy(phy_c_to_p);
  connection.SetRxPhy(phy_p_to_c);
}

void LinkLayerController::IncomingLlPhyUpdateInd(
    model::packets::LinkLayerPacketView incoming) {
  auto phy_update_ind = model::packets::LlPhyUpdateIndView::Create(incoming);
  ASSERT(phy_update_ind.IsValid());
  uint16_t connection_handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());

  if (connection_handle == kReservedHandle) {
    INFO(id_, "@{}: Unknown connection @{}", incoming.GetDestinationAddress(),
         incoming.GetSourceAddress());
    return;
  }

  AclConnection& connection = connections_.GetAclConnection(connection_handle);
  ASSERT(connection.GetRole() == bluetooth::hci::Role::PERIPHERAL);

  bluetooth::hci::PhyType tx_phy =
      select_phy(phy_update_ind.GetPhyPToC(), connection.GetTxPhy());
  bluetooth::hci::PhyType rx_phy =
      select_phy(phy_update_ind.GetPhyCToP(), connection.GetRxPhy());

  // Update local state, and notify the host.
  // The notification is sent only when the local host is initiator
  // of the Phy update procedure or the phy selection has changed.
  if (IsLeEventUnmasked(SubeventCode::PHY_UPDATE_COMPLETE) &&
      (tx_phy != connection.GetTxPhy() || rx_phy != connection.GetRxPhy() ||
       connection.InitiatedPhyUpdate())) {
    send_event_(bluetooth::hci::LePhyUpdateCompleteBuilder::Create(
        ErrorCode::SUCCESS, connection_handle, tx_phy, rx_phy));
  }

  connection.PhyUpdateComplete();
  connection.SetTxPhy(tx_phy);
  connection.SetRxPhy(rx_phy);
}

// HCI LE Set Host Feature command (Vol 4, Part E § 7.8.115).
ErrorCode LinkLayerController::LeSetHostFeature(uint8_t bit_number,
                                                uint8_t bit_value) {
  if (bit_number >= 64 || bit_value > 1) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If Bit_Value is set to 0x01 and Bit_Number specifies a feature bit that
  // requires support of a feature that the Controller does not support,
  // the Controller shall return the error code Unsupported Feature or
  // Parameter Value (0x11).
  // TODO

  // If the Host issues this command while the Controller has a connection to
  // another device, the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (HasAclConnection()) {
    return ErrorCode::COMMAND_DISALLOWED;
  }

  uint64_t bit_mask = UINT64_C(1) << bit_number;
  if (bit_mask ==
      static_cast<uint64_t>(
          LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_HOST_SUPPORT)) {
    connected_isochronous_stream_host_support_ = bit_value != 0;
  } else if (bit_mask ==
             static_cast<uint64_t>(
                 LLFeaturesBits::CONNECTION_SUBRATING_HOST_SUPPORT)) {
    connection_subrating_host_support_ = bit_value != 0;
  }
  // If Bit_Number specifies a feature bit that is not controlled by the Host,
  // the Controller shall return the error code Unsupported Feature or
  // Parameter Value (0x11).
  else {
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (bit_value != 0) {
    le_host_supported_features_ |= bit_mask;
  } else {
    le_host_supported_features_ &= ~bit_mask;
  }

  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Resolving List
// =============================================================================

// HCI command LE_Add_Device_To_Resolving_List (Vol 4, Part E § 7.8.38).
ErrorCode LinkLayerController::LeAddDeviceToResolvingList(
    PeerAddressType peer_identity_address_type, Address peer_identity_address,
    std::array<uint8_t, kIrkSize> peer_irk,
    std::array<uint8_t, kIrkSize> local_irk) {
  // This command shall not be used when address resolution is enabled in the
  // Controller and:
  //  • Advertising (other than periodic advertising) is enabled,
  //  • Scanning is enabled, or
  //  • an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
  //    HCI_LE_Periodic_Advertising_Create_Sync command is pending.
  if (le_resolving_list_enabled_ && ResolvingListBusy()) {
    INFO(id_,
         "device is currently advertising, scanning, or establishing an"
         " LE connection");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // When a Controller cannot add a device to the list because there is no space
  // available, it shall return the error code Memory Capacity Exceeded (0x07).
  if (le_resolving_list_.size() >= properties_.le_resolving_list_size) {
    INFO(id_, "resolving list is full");
    return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
  }

  // If there is an existing entry in the resolving list with the same
  // Peer_Identity_Address and Peer_Identity_Address_Type, or with the same
  // Peer_IRK, the Controller should return the error code Invalid HCI Command
  // Parameters (0x12).
  for (auto const& entry : le_resolving_list_) {
    if ((entry.peer_identity_address_type == peer_identity_address_type &&
         entry.peer_identity_address == peer_identity_address) ||
        (entry.peer_irk == peer_irk && !irk_is_zero(peer_irk))) {
      INFO(id_, "device is already present in the resolving list");
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }
  }

  le_resolving_list_.emplace_back(ResolvingListEntry{peer_identity_address_type,
                                                     peer_identity_address,
                                                     peer_irk,
                                                     local_irk,
                                                     PrivacyMode::NETWORK,
                                                     {},
                                                     {}});
  return ErrorCode::SUCCESS;
}

// HCI command LE_Remove_Device_From_Resolving_List (Vol 4, Part E § 7.8.39).
ErrorCode LinkLayerController::LeRemoveDeviceFromResolvingList(
    PeerAddressType peer_identity_address_type, Address peer_identity_address) {
  // This command shall not be used when address resolution is enabled in the
  // Controller and:
  //  • Advertising (other than periodic advertising) is enabled,
  //  • Scanning is enabled, or
  //  • an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
  //    HCI_LE_Periodic_Advertising_Create_Sync command is pending.
  if (le_resolving_list_enabled_ && ResolvingListBusy()) {
    INFO(id_,
         "device is currently advertising, scanning, or establishing an"
         " LE connection");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  for (auto it = le_resolving_list_.begin(); it != le_resolving_list_.end();
       it++) {
    if (it->peer_identity_address_type == peer_identity_address_type &&
        it->peer_identity_address == peer_identity_address) {
      le_resolving_list_.erase(it);
      return ErrorCode::SUCCESS;
    }
  }

  // When a Controller cannot remove a device from the resolving list because
  // it is not found, it shall return the error code
  // Unknown Connection Identifier (0x02).
  INFO(id_, "peer address not found in the resolving list");
  return ErrorCode::UNKNOWN_CONNECTION;
}

// HCI command LE_Clear_Resolving_List (Vol 4, Part E § 7.8.40).
ErrorCode LinkLayerController::LeClearResolvingList() {
  // This command shall not be used when address resolution is enabled in the
  // Controller and:
  //  • Advertising (other than periodic advertising) is enabled,
  //  • Scanning is enabled, or
  //  • an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
  //    HCI_LE_Periodic_Advertising_Create_Sync command is pending.
  if (le_resolving_list_enabled_ && ResolvingListBusy()) {
    INFO(id_,
         "device is currently advertising, scanning,"
         " or establishing an LE connection");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  le_resolving_list_.clear();
  return ErrorCode::SUCCESS;
}

// HCI command LE_Read_Peer_Resolvable_Address (Vol 4, Part E § 7.8.42).
ErrorCode LinkLayerController::LeReadPeerResolvableAddress(
    PeerAddressType peer_identity_address_type, Address peer_identity_address,
    Address* peer_resolvable_address) {
  for (auto const& entry : le_resolving_list_) {
    if (entry.peer_identity_address_type == peer_identity_address_type &&
        entry.peer_identity_address == peer_identity_address &&
        entry.peer_resolvable_address.has_value()) {
      *peer_resolvable_address = entry.peer_resolvable_address.value();
      return ErrorCode::SUCCESS;
    }
  }

  // When a Controller cannot find a Resolvable Private Address associated with
  // the Peer Identity Address, or if the Peer Identity Address cannot be found
  // in the resolving list, it shall return the error code
  // Unknown Connection Identifier (0x02).
  INFO(id_,
       "peer identity address {}[{}] not found in the resolving list,"
       " or peer resolvable address unavailable",
       peer_identity_address, PeerAddressTypeText(peer_identity_address_type));
  return ErrorCode::UNKNOWN_CONNECTION;
}

// HCI command LE_Read_Local_Resolvable_Address (Vol 4, Part E § 7.8.43).
ErrorCode LinkLayerController::LeReadLocalResolvableAddress(
    PeerAddressType peer_identity_address_type, Address peer_identity_address,
    Address* local_resolvable_address) {
  for (auto const& entry : le_resolving_list_) {
    if (entry.peer_identity_address_type == peer_identity_address_type &&
        entry.peer_identity_address == peer_identity_address &&
        entry.local_resolvable_address.has_value()) {
      *local_resolvable_address = entry.local_resolvable_address.value();
      return ErrorCode::SUCCESS;
    }
  }

  // When a Controller cannot find a Resolvable Private Address associated with
  // the Peer Identity Address, or if the Peer Identity Address cannot be found
  // in the resolving list, it shall return the error code
  // Unknown Connection Identifier (0x02).
  INFO(id_,
       "peer identity address {}[{}] not found in the resolving list,"
       " or peer resolvable address unavailable",
       peer_identity_address, PeerAddressTypeText(peer_identity_address_type));
  return ErrorCode::UNKNOWN_CONNECTION;
}

// HCI command LE_Set_Address_Resolution_Enable (Vol 4, Part E § 7.8.44).
ErrorCode LinkLayerController::LeSetAddressResolutionEnable(bool enable) {
  // This command shall not be used when:
  //  • Advertising (other than periodic advertising) is enabled,
  //  • Scanning is enabled, or
  //  • an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
  //    HCI_LE_Periodic_Advertising_Create_Sync command is pending.
  if (ResolvingListBusy()) {
    INFO(id_,
         "device is currently advertising, scanning,"
         " or establishing an LE connection");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  le_resolving_list_enabled_ = enable;
  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Privacy_Mode (Vol 4, Part E § 7.8.77).
ErrorCode LinkLayerController::LeSetPrivacyMode(
    PeerAddressType peer_identity_address_type, Address peer_identity_address,
    bluetooth::hci::PrivacyMode privacy_mode) {
  // This command shall not be used when address resolution is enabled in the
  // Controller and:
  //  • Advertising (other than periodic advertising) is enabled,
  //  • Scanning is enabled, or
  //  • an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
  //    HCI_LE_Periodic_Advertising_Create_Sync command is pending.
  if (le_resolving_list_enabled_ && ResolvingListBusy()) {
    INFO(id_,
         "device is currently advertising, scanning,"
         " or establishing an LE connection");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  for (auto& entry : le_resolving_list_) {
    if (entry.peer_identity_address_type == peer_identity_address_type &&
        entry.peer_identity_address == peer_identity_address) {
      entry.privacy_mode = privacy_mode;
      return ErrorCode::SUCCESS;
    }
  }

  // If the device is not on the resolving list, the Controller shall return
  // the error code Unknown Connection Identifier (0x02).
  INFO(id_, "peer address not found in the resolving list");
  return ErrorCode::UNKNOWN_CONNECTION;
}

// =============================================================================
//  LE Filter Accept List
// =============================================================================

// HCI command LE_Clear_Filter_Accept_List (Vol 4, Part E § 7.8.15).
ErrorCode LinkLayerController::LeClearFilterAcceptList() {
  // This command shall not be used when:
  //  • any advertising filter policy uses the Filter Accept List and
  //    advertising is enabled,
  //  • the scanning filter policy uses the Filter Accept List and scanning
  //    is enabled, or
  //  • the initiator filter policy uses the Filter Accept List and an
  //    HCI_LE_Create_Connection or HCI_LE_Extended_Create_Connection
  //    command is pending.
  if (FilterAcceptListBusy()) {
    INFO(id_,
         "device is currently advertising, scanning,"
         " or establishing an LE connection using the filter accept list");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  le_filter_accept_list_.clear();
  return ErrorCode::SUCCESS;
}

// HCI command LE_Add_Device_To_Filter_Accept_List (Vol 4, Part E § 7.8.16).
ErrorCode LinkLayerController::LeAddDeviceToFilterAcceptList(
    FilterAcceptListAddressType address_type, Address address) {
  // This command shall not be used when:
  //  • any advertising filter policy uses the Filter Accept List and
  //    advertising is enabled,
  //  • the scanning filter policy uses the Filter Accept List and scanning
  //    is enabled, or
  //  • the initiator filter policy uses the Filter Accept List and an
  //    HCI_LE_Create_Connection or HCI_LE_Extended_Create_Connection
  //    command is pending.
  if (FilterAcceptListBusy()) {
    INFO(id_,
         "device is currently advertising, scanning,"
         " or establishing an LE connection using the filter accept list");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // When a Controller cannot add a device to the Filter Accept List
  // because there is no space available, it shall return the error code
  // Memory Capacity Exceeded (0x07).
  if (le_filter_accept_list_.size() >= properties_.le_filter_accept_list_size) {
    INFO(id_, "filter accept list is full");
    return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
  }

  le_filter_accept_list_.emplace_back(
      FilterAcceptListEntry{address_type, address});
  return ErrorCode::SUCCESS;
}

// HCI command LE_Remove_Device_From_Filter_Accept_List (Vol 4, Part E
// § 7.8.17).
ErrorCode LinkLayerController::LeRemoveDeviceFromFilterAcceptList(
    FilterAcceptListAddressType address_type, Address address) {
  // This command shall not be used when:
  //  • any advertising filter policy uses the Filter Accept List and
  //    advertising is enabled,
  //  • the scanning filter policy uses the Filter Accept List and scanning
  //    is enabled, or
  //  • the initiator filter policy uses the Filter Accept List and an
  //    HCI_LE_Create_Connection or HCI_LE_Extended_Create_Connection
  //    command is pending.
  if (FilterAcceptListBusy()) {
    INFO(id_,
         "device is currently advertising, scanning,"
         " or establishing an LE connection using the filter accept list");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  for (auto it = le_filter_accept_list_.begin();
       it != le_filter_accept_list_.end(); it++) {
    // Address shall be ignored when Address_Type is set to 0xFF.
    if (it->address_type == address_type &&
        (address_type == FilterAcceptListAddressType::ANONYMOUS_ADVERTISERS ||
         it->address == address)) {
      le_filter_accept_list_.erase(it);
      return ErrorCode::SUCCESS;
    }
  }

  // Note: this case is not documented.
  INFO(id_, "address not found in the filter accept list");
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Periodic Advertiser List
// =============================================================================

// HCI LE Add Device To Periodic Advertiser List command (Vol 4, Part E
// § 7.8.70).
ErrorCode LinkLayerController::LeAddDeviceToPeriodicAdvertiserList(
    bluetooth::hci::AdvertiserAddressType advertiser_address_type,
    Address advertiser_address, uint8_t advertising_sid) {
  // If the Host issues this command when an HCI_LE_Periodic_Advertising_-
  // Create_Sync command is pending, the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (synchronizing_.has_value()) {
    INFO(id_,
         "LE Periodic Advertising Create Sync command is currently pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // When a Controller cannot add an entry to the Periodic Advertiser list
  // because the list is full, the Controller shall return the error code Memory
  // Capacity Exceeded (0x07).
  if (le_periodic_advertiser_list_.size() >=
      properties_.le_periodic_advertiser_list_size) {
    INFO(id_, "periodic advertiser list is full");
    return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
  }

  // If the entry is already on the list, the Controller shall
  // return the error code Invalid HCI Command Parameters (0x12).
  for (auto& entry : le_periodic_advertiser_list_) {
    if (entry.advertiser_address_type == advertiser_address_type &&
        entry.advertiser_address == advertiser_address &&
        entry.advertising_sid == advertising_sid) {
      INFO(id_, "entry is already found in the periodic advertiser list");
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }
  }

  le_periodic_advertiser_list_.emplace_back(PeriodicAdvertiserListEntry{
      advertiser_address_type, advertiser_address, advertising_sid});
  return ErrorCode::SUCCESS;
}

// HCI LE Remove Device From Periodic Advertiser List command
// (Vol 4, Part E § 7.8.71).
ErrorCode LinkLayerController::LeRemoveDeviceFromPeriodicAdvertiserList(
    bluetooth::hci::AdvertiserAddressType advertiser_address_type,
    Address advertiser_address, uint8_t advertising_sid) {
  // If this command is used when an HCI_LE_Periodic_Advertising_Create_Sync
  // command is pending, the Controller shall return the error code Command
  // Disallowed (0x0C).
  if (synchronizing_.has_value()) {
    INFO(id_,
         "LE Periodic Advertising Create Sync command is currently pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  for (auto it = le_periodic_advertiser_list_.begin();
       it != le_periodic_advertiser_list_.end(); it++) {
    if (it->advertiser_address_type == advertiser_address_type &&
        it->advertiser_address == advertiser_address &&
        it->advertising_sid == advertising_sid) {
      le_periodic_advertiser_list_.erase(it);
      return ErrorCode::SUCCESS;
    }
  }

  // When a Controller cannot remove an entry from the Periodic Advertiser list
  // because it is not found, the Controller shall return the error code Unknown
  // Advertising Identifier (0x42).
  INFO(id_, "entry not found in the periodic advertiser list");
  return ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER;
}

// HCI LE Clear Periodic Advertiser List command (Vol 4, Part E § 7.8.72).
ErrorCode LinkLayerController::LeClearPeriodicAdvertiserList() {
  // If this command is used when an HCI_LE_Periodic_Advertising_Create_Sync
  // command is pending, the Controller shall return the error code Command
  // Disallowed (0x0C).
  if (synchronizing_.has_value()) {
    INFO(id_,
         "LE Periodic Advertising Create Sync command is currently pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  le_periodic_advertiser_list_.clear();
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Periodic Sync
// =============================================================================

// HCI LE Periodic Advertising Create Sync command (Vol 4, Part E § 7.8.67).
ErrorCode LinkLayerController::LePeriodicAdvertisingCreateSync(
    bluetooth::hci::PeriodicAdvertisingOptions options, uint8_t advertising_sid,
    bluetooth::hci::AdvertiserAddressType advertiser_address_type,
    Address advertiser_address, uint16_t /*skip*/, uint16_t sync_timeout,
    uint8_t sync_cte_type) {
  // If the Host issues this command when another HCI_LE_Periodic_Advertising_-
  // Create_Sync command is pending, the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (synchronizing_.has_value()) {
    INFO(id_,
         "LE Periodic Advertising Create Sync command is currently pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host sets all the non-reserved bits of the Sync_CTE_Type parameter
  // to 1, the Controller shall return the error code Command Disallowed (0x0C).
  uint8_t sync_cte_type_mask = 0x1f;
  if ((sync_cte_type & sync_cte_type_mask) == sync_cte_type_mask) {
    INFO(id_,
         "Sync_CTE_Type is configured to ignore all types of advertisement");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command with bit 0 of Options not set and with
  // Advertising_SID, Advertiser_Address_Type, and Advertiser_Address the same
  // as those of a periodic advertising train that the Controller is already
  // synchronized to, the Controller shall return the error code
  // Connection Already Exists (0x0B).
  bool has_synchronized_train = false;
  for (auto& [_, sync] : synchronized_) {
    has_synchronized_train |=
        sync.advertiser_address_type == advertiser_address_type &&
        sync.advertiser_address == advertiser_address &&
        sync.advertising_sid == advertising_sid;
  }
  if (!options.use_periodic_advertiser_list_ && has_synchronized_train) {
    INFO(id_,
         "the controller is already synchronized on the periodic advertising"
         " train from {}[{}] - SID=0x{:x}",
         advertiser_address,
         bluetooth::hci::AdvertiserAddressTypeText(advertiser_address_type),
         advertising_sid);
    return ErrorCode::CONNECTION_ALREADY_EXISTS;
  }

  // If the Host issues this command and the Controller has insufficient
  // resources to handle any more periodic advertising trains, the Controller
  // shall return the error code Memory Capacity Exceeded (0x07)
  // TODO emulate LE state limits.

  // If bit 1 of Options is set to 0, bit 2 is set to 1, and the Controller does
  // not support the Periodic Advertising ADI Support feature, then the
  // Controller shall return an error which should use the error code
  // Unsupported Feature or Parameter Value (0x11).
  if (!options.disable_reporting_ && options.enable_duplicate_filtering_ &&
      !properties_.SupportsLLFeature(
          LLFeaturesBits::PERIODIC_ADVERTISING_ADI_SUPPORT)) {
    INFO(id_,
         "reporting and duplicate filtering are enabled in the options,"
         " but the controller does not support the Periodic Advertising ADI"
         " Support feature");
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // If bit 1 of the Options parameter is set to 1 and the Controller does not
  // support the HCI_LE_Set_Periodic_Advertising_Receive_Enable command, the
  // Controller shall return the error code Connection Failed to be Established
  // / Synchronization Timeout (0x3E).
  if (options.disable_reporting_ &&
      !properties_.SupportsCommand(
          bluetooth::hci::OpCodeIndex::
              LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE)) {
    INFO(id_,
         "reporting is disabled in the options, but the controller does not"
         " support the HCI_LE_Set_Periodic_Advertising_Receive_Enable command");
    return ErrorCode::CONNECTION_FAILED_ESTABLISHMENT;
  }

  synchronizing_ = Synchronizing{
      .options = options,
      .advertiser_address_type = advertiser_address_type,
      .advertiser_address = advertiser_address,
      .advertising_sid = advertising_sid,
      .sync_timeout = 10ms * sync_timeout,
  };
  return ErrorCode::SUCCESS;
}

// HCI LE Periodic Advertising Create Sync Cancel command (Vol 4, Part E
// § 7.8.68).
ErrorCode LinkLayerController::LePeriodicAdvertisingCreateSyncCancel() {
  // If the Host issues this command while no HCI_LE_Periodic_Advertising_-
  // Create_Sync command is pending, the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (!synchronizing_.has_value()) {
    INFO(id_, "no LE Periodic Advertising Create Sync command is pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // After the HCI_Command_Complete is sent and if the cancellation was
  // successful, the Controller sends an HCI_LE_Periodic_Advertising_Sync_-
  // Established event to the Host with the error code Operation Cancelled
  // by Host (0x44).
  if (IsLeEventUnmasked(SubeventCode::PERIODIC_ADVERTISING_SYNC_ESTABLISHED)) {
    ScheduleTask(0ms, [this] {
      send_event_(
          bluetooth::hci::LePeriodicAdvertisingSyncEstablishedBuilder::Create(
              ErrorCode::OPERATION_CANCELLED_BY_HOST, 0, 0,
              AddressType::PUBLIC_DEVICE_ADDRESS, Address::kEmpty,
              bluetooth::hci::SecondaryPhyType::NO_PACKETS, 0,
              bluetooth::hci::ClockAccuracy::PPM_500));
    });
  }

  synchronizing_ = {};
  return ErrorCode::SUCCESS;
}

// HCI LE Periodic Advertising Terminate Sync command (Vol 4, Part E
// § 7.8.69).
ErrorCode LinkLayerController::LePeriodicAdvertisingTerminateSync(
    uint16_t sync_handle) {
  // If the periodic advertising train corresponding to the Sync_Handle
  // parameter does not exist, then the Controller shall return the error
  // code Unknown Advertising Identifier (0x42).
  if (synchronized_.count(sync_handle) == 0) {
    INFO(id_, "the Sync_Handle 0x{:x} does not exist", sync_handle);
    return ErrorCode::UNKNOWN_ADVERTISING_IDENTIFIER;
  }

  synchronized_.erase(sync_handle);
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Legacy Scanning
// =============================================================================

// HCI command LE_Set_Scan_Parameters (Vol 4, Part E § 7.8.10).
ErrorCode LinkLayerController::LeSetScanParameters(
    bluetooth::hci::LeScanType scan_type, uint16_t scan_interval,
    uint16_t scan_window, bluetooth::hci::OwnAddressType own_address_type,
    bluetooth::hci::LeScanningFilterPolicy scanning_filter_policy) {
  // Legacy advertising commands are disallowed when extended advertising
  // commands were used since the last reset.
  if (!SelectLegacyAdvertising()) {
    INFO(id_,
         "legacy advertising command rejected because extended advertising"
         " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // The Host shall not issue this command when scanning is enabled in the
  // Controller; if it is the Command Disallowed error code shall be used.
  if (scanner_.IsEnabled()) {
    INFO(id_, "scanning is currently enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // Note: no explicit error code stated for invalid interval and window
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (scan_interval < 0x4 || scan_interval > 0x4000 || scan_window < 0x4 ||
      scan_window > 0x4000) {
    INFO(id_,
         "le_scan_interval (0x{:04x}) and/or"
         " le_scan_window (0x{:04x}) are outside the range"
         " of supported values (0x0004 - 0x4000)",
         scan_interval, scan_window);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The LE_Scan_Window parameter shall always be set to a value smaller
  // or equal to the value set for the LE_Scan_Interval parameter.
  if (scan_window > scan_interval) {
    INFO(id_,
         "le_scan_window (0x{:04x}) is larger than le_scan_interval (0x{:04x})",
         scan_window, scan_interval);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  scanner_.le_1m_phy.enabled = true;
  scanner_.le_coded_phy.enabled = false;
  scanner_.le_1m_phy.scan_type = scan_type;
  scanner_.le_1m_phy.scan_interval = scan_interval;
  scanner_.le_1m_phy.scan_window = scan_window;
  scanner_.own_address_type = own_address_type;
  scanner_.scan_filter_policy = scanning_filter_policy;
  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Scan_Enable (Vol 4, Part E § 7.8.11).
ErrorCode LinkLayerController::LeSetScanEnable(bool enable,
                                               bool filter_duplicates) {
  // Legacy advertising commands are disallowed when extended advertising
  // commands were used since the last reset.
  if (!SelectLegacyAdvertising()) {
    INFO(id_,
         "legacy advertising command rejected because extended advertising"
         " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (!enable) {
    scanner_.scan_enable = false;
    scanner_.pending_scan_request = {};
    scanner_.pending_scan_request_timeout = {};
    scanner_.history.clear();
    return ErrorCode::SUCCESS;
  }

  // TODO: additional checks would apply in the case of a LE only Controller
  // with no configured public device address.

  // If LE_Scan_Enable is set to 0x01, the scanning parameters' Own_Address_Type
  // parameter is set to 0x01 or 0x03, and the random address for the device
  // has not been initialized using the HCI_LE_Set_Random_Address command,
  // the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if ((scanner_.own_address_type ==
           bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS ||
       scanner_.own_address_type ==
           bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS) &&
      random_address_ == Address::kEmpty) {
    INFO(id_,
         "own_address_type is Random_Device_Address or"
         " Resolvable_or_Random_Address but the Random_Address"
         " has not been initialized");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  scanner_.scan_enable = true;
  scanner_.history.clear();
  scanner_.timeout = {};
  scanner_.periodical_timeout = {};
  scanner_.pending_scan_request = {};
  scanner_.pending_scan_request_timeout = {};
  scanner_.filter_duplicates = filter_duplicates
                                   ? bluetooth::hci::FilterDuplicates::ENABLED
                                   : bluetooth::hci::FilterDuplicates::DISABLED;
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Extended Scanning
// =============================================================================

// HCI command LE_Set_Extended_Scan_Parameters (Vol 4, Part E § 7.8.64).
ErrorCode LinkLayerController::LeSetExtendedScanParameters(
    bluetooth::hci::OwnAddressType own_address_type,
    bluetooth::hci::LeScanningFilterPolicy scanning_filter_policy,
    uint8_t scanning_phys,
    std::vector<bluetooth::hci::ScanningPhyParameters>
        scanning_phy_parameters) {
  uint8_t supported_phys = properties_.LeSupportedPhys();

  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    INFO(id_,
         "extended advertising command rejected because legacy advertising"
         " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command when scanning is enabled in the Controller,
  // the Controller shall return the error code Command Disallowed (0x0C).
  if (scanner_.IsEnabled()) {
    INFO(id_, "scanning is currently enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host specifies a PHY that is not supported by the Controller,
  // including a bit that is reserved for future use, it should return the
  // error code Unsupported Feature or Parameter Value (0x11).
  if ((scanning_phys & ~supported_phys) != 0) {
    INFO(id_,
         "scanning_phys ({:02x}) enables PHYs that are not supported by"
         " the controller",
         scanning_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // TODO(c++20) std::popcount
  if (__builtin_popcount(scanning_phys) !=
      int(scanning_phy_parameters.size())) {
    INFO(id_,
         "scanning_phy_parameters ({})"
         " does not match scanning_phys ({:02x})",
         scanning_phy_parameters.size(), scanning_phys);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Note: no explicit error code stated for empty scanning_phys
  // but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on HCI Extended LE Create Connecton command.
  if (scanning_phys == 0) {
    INFO(id_, "scanning_phys is empty");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  for (auto const& parameter : scanning_phy_parameters) {
    //  If the requested scan cannot be supported by the implementation,
    // the Controller shall return the error code
    // Invalid HCI Command Parameters (0x12).
    if (parameter.le_scan_interval_ < 0x4 || parameter.le_scan_window_ < 0x4) {
      INFO(id_,
           "le_scan_interval (0x{:04x}) and/or"
           " le_scan_window (0x{:04x}) are outside the range"
           " of supported values (0x0004 - 0xffff)",
           parameter.le_scan_interval_, parameter.le_scan_window_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    if (parameter.le_scan_window_ > parameter.le_scan_interval_) {
      INFO(id_,
           "le_scan_window (0x{:04x}) is larger than le_scan_interval "
           "(0x{:04x})",
           parameter.le_scan_window_, parameter.le_scan_interval_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }
  }

  scanner_.own_address_type = own_address_type;
  scanner_.scan_filter_policy = scanning_filter_policy;
  scanner_.le_1m_phy.enabled = false;
  scanner_.le_coded_phy.enabled = false;
  int offset = 0;

  if (scanning_phys & 0x1) {
    scanner_.le_1m_phy = Scanner::PhyParameters{
        .enabled = true,
        .scan_type = scanning_phy_parameters[offset].le_scan_type_,
        .scan_interval = scanning_phy_parameters[offset].le_scan_interval_,
        .scan_window = scanning_phy_parameters[offset].le_scan_window_,
    };
    offset++;
  }

  if (scanning_phys & 0x4) {
    scanner_.le_coded_phy = Scanner::PhyParameters{
        .enabled = true,
        .scan_type = scanning_phy_parameters[offset].le_scan_type_,
        .scan_interval = scanning_phy_parameters[offset].le_scan_interval_,
        .scan_window = scanning_phy_parameters[offset].le_scan_window_,
    };
    offset++;
  }

  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Extended_Scan_Enable (Vol 4, Part E § 7.8.65).
ErrorCode LinkLayerController::LeSetExtendedScanEnable(
    bool enable, bluetooth::hci::FilterDuplicates filter_duplicates,
    uint16_t duration, uint16_t period) {
  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    INFO(id_,
         "extended advertising command rejected because legacy advertising"
         " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (!enable) {
    scanner_.scan_enable = false;
    scanner_.pending_scan_request = {};
    scanner_.pending_scan_request_timeout = {};
    scanner_.history.clear();
    return ErrorCode::SUCCESS;
  }

  // The Period parameter shall be ignored when the Duration parameter is zero.
  if (duration == 0) {
    period = 0;
  }

  // If Filter_Duplicates is set to 0x02 and either Period or Duration to zero,
  // the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (filter_duplicates ==
          bluetooth::hci::FilterDuplicates::RESET_EACH_PERIOD &&
      (period == 0 || duration == 0)) {
    INFO(id_,
         "filter_duplicates is Reset_Each_Period but either"
         " the period or duration is 0");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  auto duration_ms = std::chrono::milliseconds(10 * duration);
  auto period_ms = std::chrono::milliseconds(1280 * period);

  // If both the Duration and Period parameters are non-zero and the Duration is
  // greater than or equal to the Period, the Controller shall return the
  // error code Invalid HCI Command Parameters (0x12).
  if (period != 0 && duration != 0 && duration_ms >= period_ms) {
    INFO(id_, "the period is greater than or equal to the duration");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: additional checks would apply in the case of a LE only Controller
  // with no configured public device address.

  // If LE_Scan_Enable is set to 0x01, the scanning parameters' Own_Address_Type
  // parameter is set to 0x01 or 0x03, and the random address for the device
  // has not been initialized using the HCI_LE_Set_Random_Address command,
  // the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if ((scanner_.own_address_type ==
           bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS ||
       scanner_.own_address_type ==
           bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS) &&
      random_address_ == Address::kEmpty) {
    INFO(id_,
         "own_address_type is Random_Device_Address or"
         " Resolvable_or_Random_Address but the Random_Address"
         " has not been initialized");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  scanner_.scan_enable = true;
  scanner_.history.clear();
  scanner_.timeout = {};
  scanner_.periodical_timeout = {};
  scanner_.pending_scan_request = {};
  scanner_.pending_scan_request_timeout = {};
  scanner_.filter_duplicates = filter_duplicates;
  scanner_.duration = duration_ms;
  scanner_.period = period_ms;

  auto now = std::chrono::steady_clock::now();

  // At the end of a single scan (Duration non-zero but Period zero), an
  // HCI_LE_Scan_Timeout event shall be generated.
  if (duration != 0) {
    scanner_.timeout = now + scanner_.duration;
  }
  if (period != 0) {
    scanner_.periodical_timeout = now + scanner_.period;
  }

  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Legacy Connection
// =============================================================================

// HCI LE Create Connection command (Vol 4, Part E § 7.8.12).
ErrorCode LinkLayerController::LeCreateConnection(
    uint16_t scan_interval, uint16_t scan_window,
    bluetooth::hci::InitiatorFilterPolicy initiator_filter_policy,
    AddressWithType peer_address,
    bluetooth::hci::OwnAddressType own_address_type,
    uint16_t connection_interval_min, uint16_t connection_interval_max,
    uint16_t max_latency, uint16_t supervision_timeout, uint16_t min_ce_length,
    uint16_t max_ce_length) {
  // Legacy advertising commands are disallowed when extended advertising
  // commands were used since the last reset.
  if (!SelectLegacyAdvertising()) {
    INFO(id_,
         "legacy advertising command rejected because extended advertising"
         " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command when another HCI_LE_Create_Connection
  // command is pending in the Controller, the Controller shall return the
  // error code Command Disallowed (0x0C).
  if (initiator_.IsEnabled()) {
    INFO(id_, "initiator is currently enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // Note: no explicit error code stated for invalid interval and window
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (scan_interval < 0x4 || scan_interval > 0x4000 || scan_window < 0x4 ||
      scan_window > 0x4000) {
    INFO(id_,
         "scan_interval (0x{:04x}) and/or "
         "scan_window (0x{:04x}) are outside the range"
         " of supported values (0x4 - 0x4000)",
         scan_interval, scan_window);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The LE_Scan_Window parameter shall be set to a value smaller or equal to
  // the value set for the LE_Scan_Interval parameter.
  if (scan_interval < scan_window) {
    INFO(id_, "scan_window (0x{:04x}) is larger than scan_interval (0x{:04x})",
         scan_window, scan_interval);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Note: no explicit error code stated for invalid connection interval
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (connection_interval_min < 0x6 || connection_interval_min > 0x0c80 ||
      connection_interval_max < 0x6 || connection_interval_max > 0x0c80) {
    INFO(id_,
         "connection_interval_min (0x{:04x}) and/or "
         "connection_interval_max (0x{:04x}) are outside the range"
         " of supported values (0x6 - 0x0c80)",
         connection_interval_min, connection_interval_max);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The Connection_Interval_Min parameter shall not be greater than the
  // Connection_Interval_Max parameter.
  if (connection_interval_max < connection_interval_min) {
    INFO(id_,
         "connection_interval_min (0x{:04x}) is larger than"
         " connection_interval_max (0x{:04x})",
         connection_interval_min, connection_interval_max);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Note: no explicit error code stated for invalid max_latency
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (max_latency > 0x01f3) {
    INFO(id_,
         "max_latency (0x{:04x}) is outside the range"
         " of supported values (0x0 - 0x01f3)",
         max_latency);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // Note: no explicit error code stated for invalid supervision timeout
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (supervision_timeout < 0xa || supervision_timeout > 0x0c80) {
    INFO(id_,
         "supervision_timeout (0x{:04x}) is outside the range"
         " of supported values (0xa - 0x0c80)",
         supervision_timeout);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The Supervision_Timeout in milliseconds shall be larger than
  // (1 + Max_Latency) * Connection_Interval_Max * 2, where
  // Connection_Interval_Max is given in milliseconds.
  milliseconds min_supervision_timeout = duration_cast<milliseconds>(
      (1 + max_latency) * slots(2 * connection_interval_max) * 2);
  if (supervision_timeout * 10ms < min_supervision_timeout) {
    INFO(id_,
         "supervision_timeout ({} ms) is smaller that the minimal supervision "
         "timeout allowed by connection_interval_max and max_latency ({} ms)",
         supervision_timeout * 10,
         static_cast<unsigned>(min_supervision_timeout / 1ms));
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: additional checks would apply in the case of a LE only Controller
  // with no configured public device address.

  // If the Own_Address_Type parameter is set to 0x01 and the random
  // address for the device has not been initialized using the
  // HCI_LE_Set_Random_Address command, the Controller shall return the
  // error code Invalid HCI Command Parameters (0x12).
  if (own_address_type == OwnAddressType::RANDOM_DEVICE_ADDRESS &&
      random_address_ == Address::kEmpty) {
    INFO(id_,
         "own_address_type is Random_Device_Address but the Random_Address"
         " has not been initialized");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the Own_Address_Type parameter is set to 0x03, the
  // Initiator_Filter_Policy parameter is set to 0x00, the controller's
  // resolving list did not contain matching entry, and the random address for
  // the device has not been initialized using the HCI_LE_Set_Random_Address
  // command, the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (own_address_type == OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS &&
      initiator_filter_policy == InitiatorFilterPolicy::USE_PEER_ADDRESS &&
      !GenerateResolvablePrivateAddress(peer_address, IrkSelection::Local) &&
      random_address_ == Address::kEmpty) {
    INFO(id_,
         "own_address_type is Resolvable_Or_Random_Address but the"
         " Resolving_List does not contain a matching entry and the"
         " Random_Address is not initialized");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  initiator_.connect_enable = true;
  initiator_.initiator_filter_policy = initiator_filter_policy;
  initiator_.peer_address = peer_address;
  initiator_.own_address_type = own_address_type;
  initiator_.le_1m_phy.enabled = true;
  initiator_.le_1m_phy.scan_interval = scan_interval;
  initiator_.le_1m_phy.scan_window = scan_window;
  initiator_.le_1m_phy.connection_interval_min = connection_interval_min;
  initiator_.le_1m_phy.connection_interval_max = connection_interval_max;
  initiator_.le_1m_phy.max_latency = max_latency;
  initiator_.le_1m_phy.supervision_timeout = supervision_timeout;
  initiator_.le_1m_phy.min_ce_length = min_ce_length;
  initiator_.le_1m_phy.max_ce_length = max_ce_length;
  initiator_.le_2m_phy.enabled = false;
  initiator_.le_coded_phy.enabled = false;
  initiator_.pending_connect_request = {};
  return ErrorCode::SUCCESS;
}

// HCI LE Create Connection Cancel command (Vol 4, Part E § 7.8.12).
ErrorCode LinkLayerController::LeCreateConnectionCancel() {
  // If no HCI_LE_Create_Connection or HCI_LE_Extended_Create_Connection
  // command is pending, then the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (!initiator_.IsEnabled()) {
    INFO(id_, "initiator is currently disabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the cancellation was successful then, after the HCI_Command_Complete
  // event for the HCI_LE_Create_Connection_Cancel command, either an LE
  // Connection Complete or an HCI_LE_Enhanced_Connection_Complete event
  // shall be generated. In either case, the event shall be sent with the error
  // code Unknown Connection Identifier (0x02).
  if (IsLeEventUnmasked(SubeventCode::ENHANCED_CONNECTION_COMPLETE)) {
    ScheduleTask(0ms, [this] {
      send_event_(bluetooth::hci::LeEnhancedConnectionCompleteBuilder::Create(
          ErrorCode::UNKNOWN_CONNECTION, 0, Role::CENTRAL,
          AddressType::PUBLIC_DEVICE_ADDRESS, Address(), Address(), Address(),
          0, 0, 0, bluetooth::hci::ClockAccuracy::PPM_500));
    });
  } else if (IsLeEventUnmasked(SubeventCode::CONNECTION_COMPLETE)) {
    ScheduleTask(0ms, [this] {
      send_event_(bluetooth::hci::LeConnectionCompleteBuilder::Create(
          ErrorCode::UNKNOWN_CONNECTION, 0, Role::CENTRAL,
          AddressType::PUBLIC_DEVICE_ADDRESS, Address(), 0, 0, 0,
          bluetooth::hci::ClockAccuracy::PPM_500));
    });
  }

  initiator_.Disable();
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Extended Connection
// =============================================================================

// HCI LE Extended Create Connection command (Vol 4, Part E § 7.8.66).
ErrorCode LinkLayerController::LeExtendedCreateConnection(
    bluetooth::hci::InitiatorFilterPolicy initiator_filter_policy,
    bluetooth::hci::OwnAddressType own_address_type,
    AddressWithType peer_address, uint8_t initiating_phys,
    std::vector<bluetooth::hci::InitiatingPhyParameters>
        initiating_phy_parameters) {
  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    INFO(id_,
         "extended advertising command rejected because legacy advertising"
         " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command when another
  // HCI_LE_Extended_Create_Connection command is pending in the Controller,
  // the Controller shall return the error code Command Disallowed (0x0C).
  if (initiator_.IsEnabled()) {
    INFO(id_, "initiator is currently enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host specifies a PHY that is not supported by the Controller,
  // including a bit that is reserved for future use, the latter should return
  // the error code Unsupported Feature or Parameter Value (0x11).
  if ((initiating_phys & 0xf8) != 0) {
    INFO(id_,
         "initiating_phys ({:02x}) enables PHYs that are not supported by"
         " the controller",
         initiating_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // TODO(c++20) std::popcount
  if (__builtin_popcount(initiating_phys) !=
      int(initiating_phy_parameters.size())) {
    INFO(id_,
         "initiating_phy_parameters ({})"
         " does not match initiating_phys ({:02x})",
         initiating_phy_parameters.size(), initiating_phys);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the Initiating_PHYs parameter does not have at least one bit set for a
  // PHY allowed for scanning on the primary advertising physical channel, the
  // Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (initiating_phys == 0) {
    INFO(id_, "initiating_phys is empty");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  for (auto const& parameter : initiating_phy_parameters) {
    // Note: no explicit error code stated for invalid interval and window
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.scan_interval_ < 0x4 || parameter.scan_interval_ > 0x4000 ||
        parameter.scan_window_ < 0x4 || parameter.scan_window_ > 0x4000) {
      INFO(id_,
           "scan_interval (0x{:04x}) and/or "
           "scan_window (0x{:04x}) are outside the range"
           " of supported values (0x4 - 0x4000)",
           parameter.scan_interval_, parameter.scan_window_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // The LE_Scan_Window parameter shall be set to a value smaller or equal to
    // the value set for the LE_Scan_Interval parameter.
    if (parameter.scan_interval_ < parameter.scan_window_) {
      INFO(id_,
           "scan_window (0x{:04x}) is larger than scan_interval (0x{:04x})",
           parameter.scan_window_, parameter.scan_interval_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    // Note: no explicit error code stated for invalid connection interval
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.connection_interval_min_ < 0x6 ||
        parameter.connection_interval_min_ > 0x0c80 ||
        parameter.connection_interval_max_ < 0x6 ||
        parameter.connection_interval_max_ > 0x0c80) {
      INFO(id_,
           "connection_interval_min (0x{:04x}) and/or "
           "connection_interval_max (0x{:04x}) are outside the range"
           " of supported values (0x6 - 0x0c80)",
           parameter.connection_interval_min_,
           parameter.connection_interval_max_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // The Connection_Interval_Min parameter shall not be greater than the
    // Connection_Interval_Max parameter.
    if (parameter.connection_interval_max_ <
        parameter.connection_interval_min_) {
      INFO(id_,
           "connection_interval_min (0x{:04x}) is larger than"
           " connection_interval_max (0x{:04x})",
           parameter.connection_interval_min_,
           parameter.connection_interval_max_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    // Note: no explicit error code stated for invalid max_latency
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.max_latency_ > 0x01f3) {
      INFO(id_,
           "max_latency (0x{:04x}) is outside the range"
           " of supported values (0x0 - 0x01f3)",
           parameter.max_latency_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // Note: no explicit error code stated for invalid supervision timeout
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.supervision_timeout_ < 0xa ||
        parameter.supervision_timeout_ > 0x0c80) {
      INFO(id_,
           "supervision_timeout (0x{:04x}) is outside the range"
           " of supported values (0xa - 0x0c80)",
           parameter.supervision_timeout_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // The Supervision_Timeout in milliseconds shall be larger than
    // (1 + Max_Latency) * Connection_Interval_Max * 2, where
    // Connection_Interval_Max is given in milliseconds.
    milliseconds min_supervision_timeout = duration_cast<milliseconds>(
        (1 + parameter.max_latency_) *
        slots(2 * parameter.connection_interval_max_) * 2);
    if (parameter.supervision_timeout_ * 10ms < min_supervision_timeout) {
      INFO(
          id_,
          "supervision_timeout ({} ms) is smaller that the minimal supervision "
          "timeout allowed by connection_interval_max and max_latency ({} ms)",
          parameter.supervision_timeout_ * 10,
          static_cast<unsigned>(min_supervision_timeout / 1ms));
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }
  }

  // TODO: additional checks would apply in the case of a LE only Controller
  // with no configured public device address.

  // If the Own_Address_Type parameter is set to 0x01 and the random
  // address for the device has not been initialized using the
  // HCI_LE_Set_Random_Address command, the Controller shall return the
  // error code Invalid HCI Command Parameters (0x12).
  if (own_address_type == OwnAddressType::RANDOM_DEVICE_ADDRESS &&
      random_address_ == Address::kEmpty) {
    INFO(id_,
         "own_address_type is Random_Device_Address but the Random_Address"
         " has not been initialized");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the Own_Address_Type parameter is set to 0x03, the
  // Initiator_Filter_Policy parameter is set to 0x00, the controller's
  // resolving list did not contain matching entry, and the random address for
  // the device has not been initialized using the HCI_LE_Set_Random_Address
  // command, the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (own_address_type == OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS &&
      initiator_filter_policy == InitiatorFilterPolicy::USE_PEER_ADDRESS &&
      !GenerateResolvablePrivateAddress(peer_address, IrkSelection::Local) &&
      random_address_ == Address::kEmpty) {
    INFO(id_,
         "own_address_type is Resolvable_Or_Random_Address but the"
         " Resolving_List does not contain a matching entry and the"
         " Random_Address is not initialized");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  initiator_.connect_enable = true;
  initiator_.initiator_filter_policy = initiator_filter_policy;
  initiator_.peer_address = peer_address;
  initiator_.own_address_type = own_address_type;
  initiator_.pending_connect_request = {};

  initiator_.le_1m_phy.enabled = false;
  initiator_.le_2m_phy.enabled = false;
  initiator_.le_coded_phy.enabled = false;
  int offset = 0;

  if (initiating_phys & 0x1) {
    initiator_.le_1m_phy = Initiator::PhyParameters{
        .enabled = true,
        .scan_interval = initiating_phy_parameters[offset].scan_interval_,
        .scan_window = initiating_phy_parameters[offset].scan_window_,
        .connection_interval_min =
            initiating_phy_parameters[offset].connection_interval_min_,
        .connection_interval_max =
            initiating_phy_parameters[offset].connection_interval_max_,
        .max_latency = initiating_phy_parameters[offset].max_latency_,
        .supervision_timeout =
            initiating_phy_parameters[offset].supervision_timeout_,
        .min_ce_length = initiating_phy_parameters[offset].min_ce_length_,
        .max_ce_length = initiating_phy_parameters[offset].max_ce_length_,
    };
    offset++;
  }

  if (initiating_phys & 0x2) {
    initiator_.le_2m_phy = Initiator::PhyParameters{
        .enabled = true,
        .scan_interval = initiating_phy_parameters[offset].scan_interval_,
        .scan_window = initiating_phy_parameters[offset].scan_window_,
        .connection_interval_min =
            initiating_phy_parameters[offset].connection_interval_min_,
        .connection_interval_max =
            initiating_phy_parameters[offset].connection_interval_max_,
        .max_latency = initiating_phy_parameters[offset].max_latency_,
        .supervision_timeout =
            initiating_phy_parameters[offset].supervision_timeout_,
        .min_ce_length = initiating_phy_parameters[offset].min_ce_length_,
        .max_ce_length = initiating_phy_parameters[offset].max_ce_length_,
    };
    offset++;
  }

  if (initiating_phys & 0x4) {
    initiator_.le_coded_phy = Initiator::PhyParameters{
        .enabled = true,
        .scan_interval = initiating_phy_parameters[offset].scan_interval_,
        .scan_window = initiating_phy_parameters[offset].scan_window_,
        .connection_interval_min =
            initiating_phy_parameters[offset].connection_interval_min_,
        .connection_interval_max =
            initiating_phy_parameters[offset].connection_interval_max_,
        .max_latency = initiating_phy_parameters[offset].max_latency_,
        .supervision_timeout =
            initiating_phy_parameters[offset].supervision_timeout_,
        .min_ce_length = initiating_phy_parameters[offset].min_ce_length_,
        .max_ce_length = initiating_phy_parameters[offset].max_ce_length_,
    };
    offset++;
  }

  return ErrorCode::SUCCESS;
}

void LinkLayerController::SetSecureSimplePairingSupport(bool enable) {
  uint64_t bit = 0x1;
  secure_simple_pairing_host_support_ = enable;
  if (enable) {
    host_supported_features_ |= bit;
  } else {
    host_supported_features_ &= ~bit;
  }
}

void LinkLayerController::SetLeHostSupport(bool enable) {
  // TODO: Vol 2, Part C § 3.5 Feature requirements.
  // (65) LE Supported (Host)             implies
  //    (38) LE Supported (Controller)
  uint64_t bit = 0x2;
  le_host_support_ = enable;
  if (enable) {
    host_supported_features_ |= bit;
  } else {
    host_supported_features_ &= ~bit;
  }
}

void LinkLayerController::SetSecureConnectionsSupport(bool enable) {
  // TODO: Vol 2, Part C § 3.5 Feature requirements.
  // (67) Secure Connections (Host Support)           implies
  //    (64) Secure Simple Pairing (Host Support)     and
  //    (136) Secure Connections (Controller Support)
  uint64_t bit = 0x8;
  secure_connections_host_support_ = enable;
  if (enable) {
    host_supported_features_ |= bit;
  } else {
    host_supported_features_ &= ~bit;
  }
}

void LinkLayerController::SetLocalName(
    std::array<uint8_t, kLocalNameSize> const& local_name) {
  std::copy(local_name.begin(), local_name.end(), local_name_.begin());
}

void LinkLayerController::SetLocalName(std::vector<uint8_t> const& local_name) {
  ASSERT(local_name.size() <= local_name_.size());
  local_name_.fill(0);
  std::copy(local_name.begin(), local_name.end(), local_name_.begin());
}

void LinkLayerController::SetExtendedInquiryResponse(
    std::array<uint8_t, 240> const& extended_inquiry_response) {
  extended_inquiry_response_ = extended_inquiry_response;
}

void LinkLayerController::SetExtendedInquiryResponse(
    std::vector<uint8_t> const& extended_inquiry_response) {
  ASSERT(extended_inquiry_response.size() <= extended_inquiry_response_.size());
  extended_inquiry_response_.fill(0);
  std::copy(extended_inquiry_response.begin(), extended_inquiry_response.end(),
            extended_inquiry_response_.begin());
}

LinkLayerController::LinkLayerController(const Address& address,
                                         const ControllerProperties& properties,
                                         uint32_t id)
    : id_(id),
      address_(address),
      properties_(properties),
      lm_(nullptr, link_manager_destroy),
      ll_(nullptr, link_layer_destroy) {
  if (properties_.quirks.has_default_random_address) {
    WARNING(id_, "Configuring a default random address for this controller");
    random_address_ = Address { 0xba, 0xdb, 0xad, 0xba, 0xdb, 0xad };
  }

  controller_ops_ = {
      .user_pointer = this,
      .get_handle =
          [](void* user, const uint8_t(*address)[6]) {
            auto controller = static_cast<LinkLayerController*>(user);

            return controller->connections_.GetHandleOnlyAddress(
                Address(*address));
          },

      .get_address =
          [](void* user, uint16_t handle, uint8_t(*result)[6]) {
            auto controller = static_cast<LinkLayerController*>(user);

            auto address_opt = controller->connections_.GetAddressSafe(handle);
            Address address = address_opt.has_value()
                                  ? address_opt.value().GetAddress()
                                  : Address::kEmpty;
            std::copy(address.data(), address.data() + 6,
                      reinterpret_cast<uint8_t*>(result));
          },

      .get_extended_features =
          [](void* user, uint8_t features_page) {
            auto controller = static_cast<LinkLayerController*>(user);
            return controller->GetLmpFeatures(features_page);
          },

      .get_le_features =
          [](void* user) {
            auto controller = static_cast<LinkLayerController*>(user);
            return controller->GetLeSupportedFeatures();
          },

      .get_le_event_mask =
          [](void* user) {
            auto controller = static_cast<LinkLayerController*>(user);
            return controller->le_event_mask_;
          },

      .send_hci_event =
          [](void* user, const uint8_t* data, uintptr_t len) {
            auto controller = static_cast<LinkLayerController*>(user);

            auto event_code = static_cast<EventCode>(data[0]);
            controller->send_event_(bluetooth::hci::EventBuilder::Create(
                event_code, std::vector(data + 2, data + len)));
          },

      .send_lmp_packet =
          [](void* user, const uint8_t(*to)[6], const uint8_t* data,
             uintptr_t len) {
            auto controller = static_cast<LinkLayerController*>(user);

            Address source = controller->GetAddress();
            Address dest(*to);

            controller->SendLinkLayerPacket(model::packets::LmpBuilder::Create(
                source, dest, std::vector(data, data + len)));
          },

      .send_llcp_packet =
          [](void* user, uint16_t acl_connection_handle, const uint8_t* data,
             uintptr_t len) {
            auto controller = static_cast<LinkLayerController*>(user);

            if (!controller->connections_.HasHandle(acl_connection_handle)) {
              ERROR(
                  "Dropping LLCP packet sent for unknown connection handle "
                  "0x{:x}",
                  acl_connection_handle);
              return;
            }

            AclConnection const& connection =
                controller->connections_.GetAclConnection(
                    acl_connection_handle);
            Address source = connection.GetOwnAddress().GetAddress();
            Address destination = connection.GetAddress().GetAddress();

            controller->SendLinkLayerPacket(model::packets::LlcpBuilder::Create(
                source, destination, std::vector(data, data + len)));
          }};

  lm_.reset(link_manager_create(controller_ops_));
  ll_.reset(link_layer_create(controller_ops_));
}

LinkLayerController::~LinkLayerController() {}

void LinkLayerController::SendLeLinkLayerPacket(
    std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet,
    int8_t tx_power) {
  std::shared_ptr<model::packets::LinkLayerPacketBuilder> shared_packet =
      std::move(packet);
  ScheduleTask(kNoDelayMs, [this, shared_packet, tx_power]() {
    send_to_remote_(shared_packet, Phy::Type::LOW_ENERGY, tx_power);
  });
}

void LinkLayerController::SendLinkLayerPacket(
    std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet,
    int8_t tx_power) {
  std::shared_ptr<model::packets::LinkLayerPacketBuilder> shared_packet =
      std::move(packet);
  ScheduleTask(kNoDelayMs, [this, shared_packet, tx_power]() {
    send_to_remote_(shared_packet, Phy::Type::BR_EDR, tx_power);
  });
}

ErrorCode LinkLayerController::SendLeCommandToRemoteByAddress(
    OpCode opcode, const Address& own_address, const Address& peer_address) {
  switch (opcode) {
    case (OpCode::LE_READ_REMOTE_FEATURES):
      SendLeLinkLayerPacket(model::packets::LeReadRemoteFeaturesBuilder::Create(
          own_address, peer_address));
      break;
    default:
      INFO(id_, "Dropping unhandled command 0x{:04x}",
           static_cast<uint16_t>(opcode));
      return ErrorCode::UNKNOWN_HCI_COMMAND;
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SendCommandToRemoteByAddress(
    OpCode opcode, pdl::packet::slice args, const Address& own_address,
    const Address& peer_address) {
  switch (opcode) {
    case (OpCode::REMOTE_NAME_REQUEST):
      // LMP features get requested with remote name requests.
      SendLinkLayerPacket(model::packets::ReadRemoteLmpFeaturesBuilder::Create(
          own_address, peer_address));
      SendLinkLayerPacket(model::packets::RemoteNameRequestBuilder::Create(
          own_address, peer_address));
      break;
    case (OpCode::READ_REMOTE_SUPPORTED_FEATURES):
      SendLinkLayerPacket(
          model::packets::ReadRemoteSupportedFeaturesBuilder::Create(
              own_address, peer_address));
      break;
    case (OpCode::READ_REMOTE_EXTENDED_FEATURES): {
      pdl::packet::slice page_number_slice = args.subrange(5, 1);
      uint8_t page_number = page_number_slice.read_le<uint8_t>();
      SendLinkLayerPacket(
          model::packets::ReadRemoteExtendedFeaturesBuilder::Create(
              own_address, peer_address, page_number));
    } break;
    case (OpCode::READ_REMOTE_VERSION_INFORMATION):
      SendLinkLayerPacket(
          model::packets::ReadRemoteVersionInformationBuilder::Create(
              own_address, peer_address));
      break;
    case (OpCode::READ_CLOCK_OFFSET):
      SendLinkLayerPacket(model::packets::ReadClockOffsetBuilder::Create(
          own_address, peer_address));
      break;
    default:
      INFO(id_, "Dropping unhandled command 0x{:04x}",
           static_cast<uint16_t>(opcode));
      return ErrorCode::UNKNOWN_HCI_COMMAND;
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SendCommandToRemoteByHandle(
    OpCode opcode, pdl::packet::slice args, uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  switch (opcode) {
    case (OpCode::LE_READ_REMOTE_FEATURES):
      return SendLeCommandToRemoteByAddress(
          opcode, connections_.GetOwnAddress(handle).GetAddress(),
          connections_.GetAddress(handle).GetAddress());
    default:
      return SendCommandToRemoteByAddress(
          opcode, args, connections_.GetOwnAddress(handle).GetAddress(),
          connections_.GetAddress(handle).GetAddress());
  }
}

ErrorCode LinkLayerController::SendAclToRemote(
    bluetooth::hci::AclView acl_packet) {
  uint16_t handle = acl_packet.GetHandle();
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  AddressWithType my_address = connections_.GetOwnAddress(handle);
  AddressWithType destination = connections_.GetAddress(handle);
  Phy::Type phy = connections_.GetPhyType(handle);

  auto acl_packet_payload = acl_packet.GetPayload();
  auto acl = model::packets::AclBuilder::Create(
      my_address.GetAddress(), destination.GetAddress(),
      static_cast<uint8_t>(acl_packet.GetPacketBoundaryFlag()),
      static_cast<uint8_t>(acl_packet.GetBroadcastFlag()),
      std::vector(acl_packet_payload.begin(), acl_packet_payload.end()));

  switch (phy) {
    case Phy::Type::BR_EDR:
      SendLinkLayerPacket(std::move(acl));
      break;
    case Phy::Type::LOW_ENERGY:
      SendLeLinkLayerPacket(std::move(acl));
      break;
  }

  ScheduleTask(kNoDelayMs, [this, handle]() {
    send_event_(bluetooth::hci::NumberOfCompletedPacketsBuilder::Create(
        {bluetooth::hci::CompletedPackets(handle, 1)}));
  });
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SendScoToRemote(
    bluetooth::hci::ScoView sco_packet) {
  uint16_t handle = sco_packet.GetHandle();
  if (!connections_.HasScoHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: SCO flow control
  Address source = GetAddress();
  Address destination = connections_.GetScoAddress(handle);

  auto sco_data = sco_packet.GetData();
  std::vector<uint8_t> sco_data_bytes(sco_data.begin(), sco_data.end());

  SendLinkLayerPacket(model::packets::ScoBuilder::Create(
      source, destination, std::move(sco_data_bytes)));
  return ErrorCode::SUCCESS;
}

void LinkLayerController::IncomingPacket(
    model::packets::LinkLayerPacketView incoming, int8_t rssi) {
  ASSERT(incoming.IsValid());
  auto destination_address = incoming.GetDestinationAddress();

  // Match broadcasts
  bool address_matches = (destination_address == Address::kEmpty);

  // Address match is performed in specific handlers for these PDU types.
  switch (incoming.GetType()) {
    case model::packets::PacketType::LE_SCAN:
    case model::packets::PacketType::LE_SCAN_RESPONSE:
    case model::packets::PacketType::LE_LEGACY_ADVERTISING_PDU:
    case model::packets::PacketType::LE_EXTENDED_ADVERTISING_PDU:
    case model::packets::PacketType::LE_CONNECT:
      address_matches = true;
      break;
    default:
      break;
  }

  // Check public address
  if (destination_address == address_ ||
      destination_address == random_address_) {
    address_matches = true;
  }

  // Check current connection address
  if (destination_address == initiator_.initiating_address) {
    address_matches = true;
  }

  // Check connection addresses
  auto source_address = incoming.GetSourceAddress();
  auto handle = connections_.GetHandleOnlyAddress(source_address);
  if (handle != kReservedHandle) {
    if (connections_.GetOwnAddress(handle).GetAddress() ==
        destination_address) {
      address_matches = true;

      // Update link timeout for valid ACL connections
      connections_.ResetLinkTimer(handle);
    }
  }

  // Drop packets not addressed to me
  if (!address_matches) {
    INFO(id_, "{} | Dropping packet not addressed to me {}->{} (type 0x{:x})",
         address_, source_address, destination_address,
         static_cast<int>(incoming.GetType()));
    return;
  }

  switch (incoming.GetType()) {
    case model::packets::PacketType::ACL:
      IncomingAclPacket(incoming, rssi);
      break;
    case model::packets::PacketType::SCO:
      IncomingScoPacket(incoming);
      break;
    case model::packets::PacketType::LE_CONNECTED_ISOCHRONOUS_PDU:
      IncomingLeConnectedIsochronousPdu(incoming);
      break;
    case model::packets::PacketType::DISCONNECT:
      IncomingDisconnectPacket(incoming);
      break;
    case model::packets::PacketType::LMP:
      IncomingLmpPacket(incoming);
      break;
    case model::packets::PacketType::LLCP:
      IncomingLlcpPacket(incoming);
      break;
    case model::packets::PacketType::INQUIRY:
      if (inquiry_scan_enable_) {
        IncomingInquiryPacket(incoming, rssi);
      }
      break;
    case model::packets::PacketType::INQUIRY_RESPONSE:
      IncomingInquiryResponsePacket(incoming);
      break;
    case model::packets::PacketType::LE_LEGACY_ADVERTISING_PDU:
      IncomingLeLegacyAdvertisingPdu(incoming, rssi);
      return;
    case model::packets::PacketType::LE_EXTENDED_ADVERTISING_PDU:
      IncomingLeExtendedAdvertisingPdu(incoming, rssi);
      return;
    case model::packets::PacketType::LE_PERIODIC_ADVERTISING_PDU:
      IncomingLePeriodicAdvertisingPdu(incoming, rssi);
      return;
    case model::packets::PacketType::LE_CONNECT:
      IncomingLeConnectPacket(incoming);
      break;
    case model::packets::PacketType::LE_CONNECT_COMPLETE:
      IncomingLeConnectCompletePacket(incoming);
      break;
    case model::packets::PacketType::LE_CONNECTION_PARAMETER_REQUEST:
      IncomingLeConnectionParameterRequest(incoming);
      break;
    case model::packets::PacketType::LE_CONNECTION_PARAMETER_UPDATE:
      IncomingLeConnectionParameterUpdate(incoming);
      break;
    case model::packets::PacketType::LE_ENCRYPT_CONNECTION:
      IncomingLeEncryptConnection(incoming);
      break;
    case model::packets::PacketType::LE_ENCRYPT_CONNECTION_RESPONSE:
      IncomingLeEncryptConnectionResponse(incoming);
      break;
    case (model::packets::PacketType::LE_READ_REMOTE_FEATURES):
      IncomingLeReadRemoteFeatures(incoming);
      break;
    case (model::packets::PacketType::LE_READ_REMOTE_FEATURES_RESPONSE):
      IncomingLeReadRemoteFeaturesResponse(incoming);
      break;
    case model::packets::PacketType::LE_SCAN:
      IncomingLeScanPacket(incoming);
      break;
    case model::packets::PacketType::LE_SCAN_RESPONSE:
      IncomingLeScanResponsePacket(incoming, rssi);
      break;
    case model::packets::PacketType::PAGE:
      if (page_scan_enable_) {
        IncomingPagePacket(incoming);
      }
      break;
    case model::packets::PacketType::PAGE_RESPONSE:
      IncomingPageResponsePacket(incoming);
      break;
    case model::packets::PacketType::PAGE_REJECT:
      IncomingPageRejectPacket(incoming);
      break;
    case (model::packets::PacketType::REMOTE_NAME_REQUEST):
      IncomingRemoteNameRequest(incoming);
      break;
    case (model::packets::PacketType::REMOTE_NAME_REQUEST_RESPONSE):
      IncomingRemoteNameRequestResponse(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_SUPPORTED_FEATURES):
      IncomingReadRemoteSupportedFeatures(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_SUPPORTED_FEATURES_RESPONSE):
      IncomingReadRemoteSupportedFeaturesResponse(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_LMP_FEATURES):
      IncomingReadRemoteLmpFeatures(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_LMP_FEATURES_RESPONSE):
      IncomingReadRemoteLmpFeaturesResponse(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_EXTENDED_FEATURES):
      IncomingReadRemoteExtendedFeatures(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_EXTENDED_FEATURES_RESPONSE):
      IncomingReadRemoteExtendedFeaturesResponse(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_VERSION_INFORMATION):
      IncomingReadRemoteVersion(incoming);
      break;
    case (model::packets::PacketType::READ_REMOTE_VERSION_INFORMATION_RESPONSE):
      IncomingReadRemoteVersionResponse(incoming);
      break;
    case (model::packets::PacketType::READ_CLOCK_OFFSET):
      IncomingReadClockOffset(incoming);
      break;
    case (model::packets::PacketType::READ_CLOCK_OFFSET_RESPONSE):
      IncomingReadClockOffsetResponse(incoming);
      break;
    case model::packets::PacketType::SCO_CONNECTION_REQUEST:
      IncomingScoConnectionRequest(incoming);
      break;
    case model::packets::PacketType::SCO_CONNECTION_RESPONSE:
      IncomingScoConnectionResponse(incoming);
      break;
    case model::packets::PacketType::SCO_DISCONNECT:
      IncomingScoDisconnect(incoming);
      break;
    case model::packets::PacketType::PING_REQUEST:
      IncomingPingRequest(incoming);
      break;
    case model::packets::PacketType::PING_RESPONSE:
      // ping responses require no action
      break;
    case model::packets::PacketType::ROLE_SWITCH_REQUEST:
      IncomingRoleSwitchRequest(incoming);
      break;
    case model::packets::PacketType::ROLE_SWITCH_RESPONSE:
      IncomingRoleSwitchResponse(incoming);
      break;
    case model::packets::PacketType::LL_PHY_REQ:
      IncomingLlPhyReq(incoming);
      break;
    case model::packets::PacketType::LL_PHY_RSP:
      IncomingLlPhyRsp(incoming);
      break;
    case model::packets::PacketType::LL_PHY_UPDATE_IND:
      IncomingLlPhyUpdateInd(incoming);
      break;
    default:
      WARNING(id_, "Dropping unhandled packet of type {}",
              model::packets::PacketTypeText(incoming.GetType()));
  }
}

void LinkLayerController::IncomingAclPacket(
    model::packets::LinkLayerPacketView incoming, int8_t rssi) {
  auto acl = model::packets::AclView::Create(incoming);
  ASSERT(acl.IsValid());

  auto acl_data = acl.GetData();
  auto packet_boundary_flag =
      bluetooth::hci::PacketBoundaryFlag(acl.GetPacketBoundaryFlag());
  auto broadcast_flag = bluetooth::hci::BroadcastFlag(acl.GetBroadcastFlag());

  if (packet_boundary_flag ==
      bluetooth::hci::PacketBoundaryFlag::FIRST_NON_AUTOMATICALLY_FLUSHABLE) {
    packet_boundary_flag =
        bluetooth::hci::PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
  }

  INFO(id_, "Acl Packet [{}] {} -> {}", acl_data.size(),
       incoming.GetSourceAddress(), incoming.GetDestinationAddress());

  uint16_t connection_handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  if (connection_handle == kReservedHandle) {
    INFO(id_, "Dropping packet since connection does not exist");
    return;
  }

  // Update the RSSI for the local ACL connection.
  connections_.SetRssi(connection_handle, rssi);

  // Send the packet to the host segmented according to the
  // controller ACL data packet length.
  size_t acl_buffer_size = properties_.acl_data_packet_length;
  size_t offset = 0;

  while (offset < acl_data.size()) {
    size_t fragment_size = std::min(acl_buffer_size, acl_data.size() - offset);
    std::vector<uint8_t> fragment(acl_data.begin() + offset,
                                  acl_data.begin() + offset + fragment_size);

    auto acl_packet = bluetooth::hci::AclBuilder::Create(
        connection_handle, packet_boundary_flag, broadcast_flag,
        std::move(fragment));

    send_acl_(std::move(acl_packet));

    packet_boundary_flag =
        bluetooth::hci::PacketBoundaryFlag::CONTINUING_FRAGMENT;
    offset += fragment_size;
  }
}

void LinkLayerController::IncomingScoPacket(
    model::packets::LinkLayerPacketView incoming) {
  Address source = incoming.GetSourceAddress();
  uint16_t sco_handle = connections_.GetScoHandle(source);
  if (!connections_.HasScoHandle(sco_handle)) {
    INFO(id_, "Spurious SCO packet from {}", source);
    return;
  }

  auto sco = model::packets::ScoView::Create(incoming);
  ASSERT(sco.IsValid());
  auto sco_data = sco.GetPayload();
  std::vector<uint8_t> sco_data_bytes(sco_data.begin(), sco_data.end());

  INFO(id_, "Sco Packet [{}] {} -> {}", static_cast<int>(sco_data_bytes.size()),
       incoming.GetSourceAddress(), incoming.GetDestinationAddress());

  send_sco_(bluetooth::hci::ScoBuilder::Create(
      sco_handle, bluetooth::hci::PacketStatusFlag::CORRECTLY_RECEIVED,
      sco_data_bytes));
}

void LinkLayerController::IncomingRemoteNameRequest(
    model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::RemoteNameRequestView::Create(incoming);
  ASSERT(view.IsValid());

  SendLinkLayerPacket(model::packets::RemoteNameRequestResponseBuilder::Create(
      incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
      local_name_));
}

void LinkLayerController::IncomingRemoteNameRequestResponse(
    model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::RemoteNameRequestResponseView::Create(incoming);
  ASSERT(view.IsValid());

  if (IsEventUnmasked(EventCode::REMOTE_NAME_REQUEST_COMPLETE)) {
    send_event_(bluetooth::hci::RemoteNameRequestCompleteBuilder::Create(
        ErrorCode::SUCCESS, incoming.GetSourceAddress(), view.GetName()));
  }
}

void LinkLayerController::IncomingReadRemoteLmpFeatures(
    model::packets::LinkLayerPacketView incoming) {
  SendLinkLayerPacket(
      model::packets::ReadRemoteLmpFeaturesResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
          host_supported_features_));
}

void LinkLayerController::IncomingReadRemoteLmpFeaturesResponse(
    model::packets::LinkLayerPacketView incoming) {
  auto view =
      model::packets::ReadRemoteLmpFeaturesResponseView::Create(incoming);
  ASSERT(view.IsValid());
  if (IsEventUnmasked(EventCode::REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION)) {
    send_event_(
        bluetooth::hci::RemoteHostSupportedFeaturesNotificationBuilder::Create(
            incoming.GetSourceAddress(), view.GetFeatures()));
  }
}

void LinkLayerController::IncomingReadRemoteSupportedFeatures(
    model::packets::LinkLayerPacketView incoming) {
  SendLinkLayerPacket(
      model::packets::ReadRemoteSupportedFeaturesResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
          properties_.lmp_features[0]));
}

void LinkLayerController::IncomingReadRemoteSupportedFeaturesResponse(
    model::packets::LinkLayerPacketView incoming) {
  auto view =
      model::packets::ReadRemoteSupportedFeaturesResponseView::Create(incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(source);
  if (handle == kReservedHandle) {
    INFO(id_, "Discarding response from a disconnected device {}", source);
    return;
  }
  if (IsEventUnmasked(EventCode::READ_REMOTE_SUPPORTED_FEATURES_COMPLETE)) {
    send_event_(
        bluetooth::hci::ReadRemoteSupportedFeaturesCompleteBuilder::Create(
            ErrorCode::SUCCESS, handle, view.GetFeatures()));
  }
}

void LinkLayerController::IncomingReadRemoteExtendedFeatures(
    model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadRemoteExtendedFeaturesView::Create(incoming);
  ASSERT(view.IsValid());
  uint8_t page_number = view.GetPageNumber();
  uint8_t error_code = static_cast<uint8_t>(ErrorCode::SUCCESS);
  if (page_number >= properties_.lmp_features.size()) {
    error_code = static_cast<uint8_t>(ErrorCode::INVALID_LMP_OR_LL_PARAMETERS);
  }
  SendLinkLayerPacket(
      model::packets::ReadRemoteExtendedFeaturesResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
          error_code, page_number, GetMaxLmpFeaturesPageNumber(),
          GetLmpFeatures(page_number)));
}

void LinkLayerController::IncomingReadRemoteExtendedFeaturesResponse(
    model::packets::LinkLayerPacketView incoming) {
  auto view =
      model::packets::ReadRemoteExtendedFeaturesResponseView::Create(incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(source);
  if (handle == kReservedHandle) {
    INFO(id_, "Discarding response from a disconnected device {}", source);
    return;
  }
  if (IsEventUnmasked(EventCode::READ_REMOTE_EXTENDED_FEATURES_COMPLETE)) {
    send_event_(
        bluetooth::hci::ReadRemoteExtendedFeaturesCompleteBuilder::Create(
            static_cast<ErrorCode>(view.GetStatus()), handle,
            view.GetPageNumber(), view.GetMaxPageNumber(), view.GetFeatures()));
  }
}

void LinkLayerController::IncomingReadRemoteVersion(
    model::packets::LinkLayerPacketView incoming) {
  SendLinkLayerPacket(
      model::packets::ReadRemoteVersionInformationResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
          static_cast<uint8_t>(properties_.lmp_version),
          static_cast<uint16_t>(properties_.lmp_subversion),
          properties_.company_identifier));
}

void LinkLayerController::IncomingReadRemoteVersionResponse(
    model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadRemoteVersionInformationResponseView::Create(
      incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(source);
  if (handle == kReservedHandle) {
    INFO(id_, "Discarding response from a disconnected device {}", source);
    return;
  }
  if (IsEventUnmasked(EventCode::READ_REMOTE_VERSION_INFORMATION_COMPLETE)) {
    send_event_(
        bluetooth::hci::ReadRemoteVersionInformationCompleteBuilder::Create(
            ErrorCode::SUCCESS, handle, view.GetLmpVersion(),
            view.GetManufacturerName(), view.GetLmpSubversion()));
  }
}

void LinkLayerController::IncomingReadClockOffset(
    model::packets::LinkLayerPacketView incoming) {
  SendLinkLayerPacket(model::packets::ReadClockOffsetResponseBuilder::Create(
      incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
      GetClockOffset()));
}

void LinkLayerController::IncomingReadClockOffsetResponse(
    model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadClockOffsetResponseView::Create(incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(source);
  if (handle == kReservedHandle) {
    INFO(id_, "Discarding response from a disconnected device {}", source);
    return;
  }
  if (IsEventUnmasked(EventCode::READ_CLOCK_OFFSET_COMPLETE)) {
    send_event_(bluetooth::hci::ReadClockOffsetCompleteBuilder::Create(
        ErrorCode::SUCCESS, handle, view.GetOffset()));
  }
}

void LinkLayerController::IncomingDisconnectPacket(
    model::packets::LinkLayerPacketView incoming) {
  INFO(id_, "Disconnect Packet");
  auto disconnect = model::packets::DisconnectView::Create(incoming);
  ASSERT(disconnect.IsValid());

  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    INFO(id_, "Discarding disconnect from a disconnected device {}", peer);
    return;
  }
  auto is_br_edr = connections_.GetPhyType(handle) == Phy::Type::BR_EDR;
  ASSERT_LOG(
      connections_.Disconnect(
          handle, [this](TaskId task_id) { CancelScheduledTask(task_id); }),
      "GetHandle() returned invalid handle 0x{:x}", handle);

  uint8_t reason = disconnect.GetReason();
  SendDisconnectionCompleteEvent(handle, ErrorCode(reason));
  if (is_br_edr) {
    ASSERT(link_manager_remove_link(
        lm_.get(), reinterpret_cast<uint8_t(*)[6]>(peer.data())));
  } else {
    ASSERT(link_layer_remove_link(ll_.get(), handle));
  }
}

void LinkLayerController::IncomingInquiryPacket(
    model::packets::LinkLayerPacketView incoming, uint8_t rssi) {
  auto inquiry = model::packets::InquiryView::Create(incoming);
  ASSERT(inquiry.IsValid());

  Address peer = incoming.GetSourceAddress();
  uint8_t lap = inquiry.GetLap();

  // Filter out inquiry packets with IAC not present in the
  // list Current_IAC_LAP.
  if (std::none_of(current_iac_lap_list_.cbegin(), current_iac_lap_list_.cend(),
                   [lap](auto iac_lap) { return iac_lap.lap_ == lap; })) {
    return;
  }

  switch (inquiry.GetInquiryType()) {
    case (model::packets::InquiryType::STANDARD): {
      SendLinkLayerPacket(model::packets::InquiryResponseBuilder::Create(
          GetAddress(), peer, static_cast<uint8_t>(GetPageScanRepetitionMode()),
          class_of_device_, GetClockOffset()));
    } break;
    case (model::packets::InquiryType::RSSI): {
      SendLinkLayerPacket(
          model::packets::InquiryResponseWithRssiBuilder::Create(
              GetAddress(), peer,
              static_cast<uint8_t>(GetPageScanRepetitionMode()),
              class_of_device_, GetClockOffset(), rssi));
    } break;
    case (model::packets::InquiryType::EXTENDED): {
      SendLinkLayerPacket(
          model::packets::ExtendedInquiryResponseBuilder::Create(
              GetAddress(), peer,
              static_cast<uint8_t>(GetPageScanRepetitionMode()),
              class_of_device_, GetClockOffset(), rssi,
              extended_inquiry_response_));
    } break;
    default:
      WARNING(id_, "Unhandled Incoming Inquiry of type {}",
              static_cast<int>(inquiry.GetType()));
      return;
  }
  // TODO: Send an Inquiry Response Notification Event 7.7.74
}

void LinkLayerController::IncomingInquiryResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto basic_inquiry_response =
      model::packets::BasicInquiryResponseView::Create(incoming);
  ASSERT(basic_inquiry_response.IsValid());
  std::vector<uint8_t> eir;

  switch (basic_inquiry_response.GetInquiryType()) {
    case (model::packets::InquiryType::STANDARD): {
      // TODO: Support multiple inquiries in the same packet.
      auto inquiry_response =
          model::packets::InquiryResponseView::Create(basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      auto page_scan_repetition_mode =
          (bluetooth::hci::PageScanRepetitionMode)
              inquiry_response.GetPageScanRepetitionMode();

      std::vector<bluetooth::hci::InquiryResponse> responses;
      responses.emplace_back();
      responses.back().bd_addr_ = inquiry_response.GetSourceAddress();
      responses.back().page_scan_repetition_mode_ = page_scan_repetition_mode;
      responses.back().class_of_device_ = inquiry_response.GetClassOfDevice();
      responses.back().clock_offset_ = inquiry_response.GetClockOffset();
      if (IsEventUnmasked(EventCode::INQUIRY_RESULT)) {
        send_event_(bluetooth::hci::InquiryResultBuilder::Create(responses));
      }
    } break;

    case (model::packets::InquiryType::RSSI): {
      auto inquiry_response =
          model::packets::InquiryResponseWithRssiView::Create(
              basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      auto page_scan_repetition_mode =
          (bluetooth::hci::PageScanRepetitionMode)
              inquiry_response.GetPageScanRepetitionMode();

      std::vector<bluetooth::hci::InquiryResponseWithRssi> responses;
      responses.emplace_back();
      responses.back().address_ = inquiry_response.GetSourceAddress();
      responses.back().page_scan_repetition_mode_ = page_scan_repetition_mode;
      responses.back().class_of_device_ = inquiry_response.GetClassOfDevice();
      responses.back().clock_offset_ = inquiry_response.GetClockOffset();
      responses.back().rssi_ = inquiry_response.GetRssi();
      if (IsEventUnmasked(EventCode::INQUIRY_RESULT_WITH_RSSI)) {
        send_event_(
            bluetooth::hci::InquiryResultWithRssiBuilder::Create(responses));
      }
    } break;

    case (model::packets::InquiryType::EXTENDED): {
      auto inquiry_response =
          model::packets::ExtendedInquiryResponseView::Create(
              basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      send_event_(bluetooth::hci::ExtendedInquiryResultBuilder::Create(
          inquiry_response.GetSourceAddress(),
          static_cast<bluetooth::hci::PageScanRepetitionMode>(
              inquiry_response.GetPageScanRepetitionMode()),
          inquiry_response.GetClassOfDevice(),
          inquiry_response.GetClockOffset(), inquiry_response.GetRssi(),
          inquiry_response.GetExtendedInquiryResponse()));
    } break;

    default:
      WARNING(id_, "Unhandled Incoming Inquiry Response of type {}",
              static_cast<int>(basic_inquiry_response.GetInquiryType()));
  }
}

Address LinkLayerController::generate_rpa(
    std::array<uint8_t, LinkLayerController::kIrkSize> irk) {
  // most significant bit, bit7, bit6 is 01 to be resolvable random
  // Bits of the random part of prand shall not be all 1 or all 0
  std::array<uint8_t, 3> prand;
  prand[0] = std::rand();
  prand[1] = std::rand();
  prand[2] = std::rand();

  constexpr uint8_t BLE_RESOLVE_ADDR_MSB = 0x40;
  prand[2] &= ~0xC0;  // BLE Address mask
  if ((prand[0] == 0x00 && prand[1] == 0x00 && prand[2] == 0x00) ||
      (prand[0] == 0xFF && prand[1] == 0xFF && prand[2] == 0x3F)) {
    prand[0] = (uint8_t)(std::rand() % 0xFE + 1);
  }
  prand[2] |= BLE_RESOLVE_ADDR_MSB;

  Address rpa;
  rpa.address[3] = prand[0];
  rpa.address[4] = prand[1];
  rpa.address[5] = prand[2];

  /* encrypt with IRK */
  rootcanal::crypto::Octet16 p =
      rootcanal::crypto::aes_128(irk, prand.data(), 3);

  /* set hash to be LSB of rpAddress */
  rpa.address[0] = p[0];
  rpa.address[1] = p[1];
  rpa.address[2] = p[2];
  INFO("RPA {}", rpa);
  return rpa;
}

bool LinkLayerController::irk_is_zero(std::array<uint8_t, LinkLayerController::kIrkSize> irk) {
    return std::all_of(irk.begin(), irk.end(), [](uint8_t b) { return b == 0; });
}

// Handle legacy advertising PDUs while in the Scanning state.
void LinkLayerController::ScanIncomingLeLegacyAdvertisingPdu(
    model::packets::LeLegacyAdvertisingPduView& pdu, uint8_t rssi) {
  if (!scanner_.IsEnabled()) {
    return;
  }

  auto advertising_type = pdu.GetAdvertisingType();
  std::vector<uint8_t> advertising_data = pdu.GetAdvertisingData();

  AddressWithType advertising_address{
      pdu.GetSourceAddress(),
      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};

  AddressWithType target_address{
      pdu.GetDestinationAddress(),
      static_cast<AddressType>(pdu.GetTargetAddressType())};

  bool scannable_advertising =
      advertising_type == model::packets::LegacyAdvertisingType::ADV_IND ||
      advertising_type == model::packets::LegacyAdvertisingType::ADV_SCAN_IND;

  bool directed_advertising =
      advertising_type == model::packets::LegacyAdvertisingType::ADV_DIRECT_IND;

  bool connectable_advertising =
      advertising_type == model::packets::LegacyAdvertisingType::ADV_IND ||
      advertising_type == model::packets::LegacyAdvertisingType::ADV_DIRECT_IND;

  // TODO: check originating PHY, compare against active scanning PHYs
  // (scanner_.le_1m_phy or scanner_.le_coded_phy).

  // When a scanner receives an advertising packet that contains a resolvable
  // private address for the advertiser’s device address (AdvA field) and
  // address resolution is enabled, the Link Layer shall resolve the private
  // address. The scanner’s filter policy shall then determine if the scanner
  // responds with a scan request.
  AddressWithType resolved_advertising_address =
      ResolvePrivateAddress(advertising_address).value_or(advertising_address);

  if (resolved_advertising_address != advertising_address) {
    DEBUG(id_, "Resolved the advertising address {} to {}", advertising_address,
          resolved_advertising_address);
  }

  // Vol 6, Part B § 4.3.3 Scanner filter policy
  switch (scanner_.scan_filter_policy) {
    case bluetooth::hci::LeScanningFilterPolicy::ACCEPT_ALL:
    case bluetooth::hci::LeScanningFilterPolicy::CHECK_INITIATORS_IDENTITY:
      break;
    case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY:
    case bluetooth::hci::LeScanningFilterPolicy::
        FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY:
      if (!LeFilterAcceptListContainsDevice(resolved_advertising_address)) {
        DEBUG(id_,
              "Legacy advertising ignored by scanner because the advertising "
              "address {} is not in the filter accept list",
              resolved_advertising_address);
        return;
      }
      break;
  }

  // When LE_Set_Scan_Enable is used:
  //
  // When the Scanning_Filter_Policy is set to 0x02 or 0x03 (see Section 7.8.10)
  // and a directed advertisement was received where the advertiser used a
  // resolvable private address which the Controller is unable to resolve, an
  // HCI_LE_Directed_Advertising_Report event shall be generated instead of an
  // HCI_LE_Advertising_Report event.
  bool should_send_directed_advertising_report = false;

  if (directed_advertising) {
    switch (scanner_.scan_filter_policy) {
      // In both basic scanner filter policy modes, a directed advertising PDU
      // shall be ignored unless either:
      //  • the TargetA field is identical to the scanner's device address, or
      //  • the TargetA field is a resolvable private address, address
      //  resolution is enabled, and the address is resolved successfully
      case bluetooth::hci::LeScanningFilterPolicy::ACCEPT_ALL:
      case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY:
        if (!ValidateTargetA(target_address, resolved_advertising_address)) {
          DEBUG(id_,
                "Legacy advertising ignored by scanner because the directed "
                "address {} does not match the current device or cannot be "
                "resolved",
                target_address);
          return;
        }
        break;
      // These are identical to the basic modes except
      // that a directed advertising PDU shall be ignored unless either:
      //  • the TargetA field is identical to the scanner's device address, or
      //  • the TargetA field is a resolvable private address.
      case bluetooth::hci::LeScanningFilterPolicy::CHECK_INITIATORS_IDENTITY:
      case bluetooth::hci::LeScanningFilterPolicy::
          FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY:
        if (!IsLocalPublicOrRandomAddress(target_address) &&
            !target_address.IsRpa()) {
          DEBUG(id_,
                "Legacy advertising ignored by scanner because the directed "
                "address {} does not match the current device or is not a "
                "resovable private address",
                target_address);
          return;
        }
        should_send_directed_advertising_report =
            target_address.IsRpa() &&
            !ResolveTargetA(target_address, resolved_advertising_address);
        break;
    }
  }

  bool should_send_advertising_report = true;
  if (scanner_.filter_duplicates !=
      bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(pdu.bytes())) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(pdu.bytes());
    }
  }

  // Legacy scanning, directed advertising.
  if (LegacyAdvertising() && should_send_advertising_report &&
      should_send_directed_advertising_report &&
      IsLeEventUnmasked(SubeventCode::DIRECTED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeDirectedAdvertisingResponse response;
    response.event_type_ =
        bluetooth::hci::DirectAdvertisingEventType::ADV_DIRECT_IND;
    response.address_type_ =
        static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
            resolved_advertising_address.GetAddressType());
    response.address_ = resolved_advertising_address.GetAddress();
    response.direct_address_type_ =
        bluetooth::hci::DirectAddressType::RANDOM_DEVICE_ADDRESS;
    response.direct_address_ = target_address.GetAddress();
    response.rssi_ = rssi;

    send_event_(
        bluetooth::hci::LeDirectedAdvertisingReportBuilder::Create({response}));
  }

  // Legacy scanning, un-directed advertising.
  if (LegacyAdvertising() && should_send_advertising_report &&
      !should_send_directed_advertising_report &&
      IsLeEventUnmasked(SubeventCode::ADVERTISING_REPORT)) {
    bluetooth::hci::LeAdvertisingResponse response;
    response.address_type_ = resolved_advertising_address.GetAddressType();
    response.address_ = resolved_advertising_address.GetAddress();
    response.advertising_data_ = advertising_data;
    response.rssi_ = rssi;

    switch (advertising_type) {
      case model::packets::LegacyAdvertisingType::ADV_IND:
        response.event_type_ = bluetooth::hci::AdvertisingEventType::ADV_IND;
        break;
      case model::packets::LegacyAdvertisingType::ADV_DIRECT_IND:
        response.event_type_ =
            bluetooth::hci::AdvertisingEventType::ADV_DIRECT_IND;
        break;
      case model::packets::LegacyAdvertisingType::ADV_SCAN_IND:
        response.event_type_ =
            bluetooth::hci::AdvertisingEventType::ADV_SCAN_IND;
        break;
      case model::packets::LegacyAdvertisingType::ADV_NONCONN_IND:
        response.event_type_ =
            bluetooth::hci::AdvertisingEventType::ADV_NONCONN_IND;
        break;
    }

    send_event_(bluetooth::hci::LeAdvertisingReportBuilder::Create({response}));
  }

  // Extended scanning.
  if (ExtendedAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponse response;
    response.connectable_ = connectable_advertising;
    response.scannable_ = scannable_advertising;
    response.directed_ = directed_advertising;
    response.scan_response_ = false;
    response.legacy_ = true;
    response.data_status_ = bluetooth::hci::DataStatus::COMPLETE;
    response.address_type_ =
        static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
            resolved_advertising_address.GetAddressType());
    response.address_ = resolved_advertising_address.GetAddress();
    response.primary_phy_ = bluetooth::hci::PrimaryPhyType::LE_1M;
    response.secondary_phy_ = bluetooth::hci::SecondaryPhyType::NO_PACKETS;
    response.advertising_sid_ = 0xff;  // ADI not provided.
    response.tx_power_ = 0x7f;         // TX power information not available.
    response.rssi_ = rssi;
    response.periodic_advertising_interval_ = 0;  // No periodic advertising.
    if (directed_advertising) {
      response.direct_address_type_ =
          bluetooth::hci::DirectAdvertisingAddressType(
              target_address.GetAddressType());
      response.direct_address_ = target_address.GetAddress();
    } else {
      response.direct_address_type_ =
          bluetooth::hci::DirectAdvertisingAddressType::NO_ADDRESS_PROVIDED;
      response.direct_address_ = Address::kEmpty;
    }
    response.advertising_data_ = advertising_data;

    send_event_(
        bluetooth::hci::LeExtendedAdvertisingReportBuilder::Create({response}));
  }

  // Did the user enable Active scanning ?
  bool active_scanning =
      (scanner_.le_1m_phy.enabled &&
       scanner_.le_1m_phy.scan_type == bluetooth::hci::LeScanType::ACTIVE) ||
      (scanner_.le_coded_phy.enabled &&
       scanner_.le_coded_phy.scan_type == bluetooth::hci::LeScanType::ACTIVE);

  // Active scanning.
  // Note: only send SCAN requests in response to scannable advertising
  // events (ADV_IND, ADV_SCAN_IND).
  if (!scannable_advertising) {
    DEBUG(id_,
          "Not sending LE Scan request to advertising address {} because "
          "it is not scannable",
          advertising_address);
  } else if (!active_scanning) {
    DEBUG(id_,
          "Not sending LE Scan request to advertising address {} because "
          "the scanner is passive",
          advertising_address);
  } else if (scanner_.pending_scan_request) {
    DEBUG(id_,
          "Not sending LE Scan request to advertising address {} because "
          "an LE Scan request is already pending",
          advertising_address);
  } else if (!should_send_advertising_report) {
    DEBUG(id_,
          "Not sending LE Scan request to advertising address {} because "
          "the advertising message was filtered",
          advertising_address);
  } else {
    // TODO: apply privacy mode in resolving list.
    // Scan requests with public or random device addresses must be ignored
    // when the peer has network privacy mode.

    AddressWithType public_address{address_,
                                   AddressType::PUBLIC_DEVICE_ADDRESS};
    AddressWithType random_address{random_address_,
                                   AddressType::RANDOM_DEVICE_ADDRESS};
    std::optional<AddressWithType> resolvable_scanning_address =
        GenerateResolvablePrivateAddress(resolved_advertising_address,
                                         IrkSelection::Local);

    // The ScanA field of the scanning PDU is generated using the
    // Resolving List’s Local IRK value and the Resolvable Private Address
    // Generation procedure (see Section 1.3.2.2), or the address is provided
    // by the Host.
    AddressWithType scanning_address;
    switch (scanner_.own_address_type) {
      case bluetooth::hci::OwnAddressType::PUBLIC_DEVICE_ADDRESS:
        scanning_address = public_address;
        break;
      case bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS:
        // The random address is checked in Le_Set_Scan_Enable or
        // Le_Set_Extended_Scan_Enable.
        ASSERT(random_address_ != Address::kEmpty);
        scanning_address = random_address;
        break;
      case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS:
        scanning_address = resolvable_scanning_address.value_or(public_address);
        break;
      case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
        // The random address is checked in Le_Set_Scan_Enable or
        // Le_Set_Extended_Scan_Enable.
        ASSERT(random_address_ != Address::kEmpty);
        scanning_address = resolvable_scanning_address.value_or(random_address);
        break;
    }

    // Save the original advertising type to report if the advertising
    // is connectable in the scan response report.
    scanner_.connectable_scan_response = connectable_advertising;
    scanner_.extended_scan_response = false;
    scanner_.pending_scan_request = advertising_address;
    scanner_.pending_scan_request_timeout =
        std::chrono::steady_clock::now() + kScanRequestTimeout;

    INFO(id_,
         "Sending LE Scan request to advertising address {} with scanning "
         "address {}",
         advertising_address, scanning_address);

    // The advertiser’s device address (AdvA field) in the scan request PDU
    // shall be the same as the advertiser’s device address (AdvA field)
    // received in the advertising PDU to which the scanner is responding.
    SendLeLinkLayerPacket(model::packets::LeScanBuilder::Create(
        scanning_address.GetAddress(), advertising_address.GetAddress(),
        static_cast<model::packets::AddressType>(
            scanning_address.GetAddressType()),
        static_cast<model::packets::AddressType>(
            advertising_address.GetAddressType())));
  }
}

void LinkLayerController::ConnectIncomingLeLegacyAdvertisingPdu(
    model::packets::LeLegacyAdvertisingPduView& pdu) {
  if (!initiator_.IsEnabled()) {
    return;
  }

  auto advertising_type = pdu.GetAdvertisingType();
  bool connectable_advertising =
      advertising_type == model::packets::LegacyAdvertisingType::ADV_IND ||
      advertising_type == model::packets::LegacyAdvertisingType::ADV_DIRECT_IND;
  bool directed_advertising =
      advertising_type == model::packets::LegacyAdvertisingType::ADV_DIRECT_IND;

  // Connection.
  // Note: only send CONNECT requests in response to connectable advertising
  // events (ADV_IND, ADV_DIRECT_IND).
  if (!connectable_advertising) {
    DEBUG(id_,
          "Legacy advertising ignored by initiator because it is not "
          "connectable");
    return;
  }
  if (initiator_.pending_connect_request) {
    DEBUG(id_,
          "Legacy advertising ignored because an LE Connect request is already "
          "pending");
    return;
  }

  AddressWithType advertising_address{
      pdu.GetSourceAddress(),
      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};

  AddressWithType target_address{
      pdu.GetDestinationAddress(),
      static_cast<AddressType>(pdu.GetTargetAddressType())};

  AddressWithType resolved_advertising_address =
      ResolvePrivateAddress(advertising_address).value_or(advertising_address);

  // Vol 6, Part B § 4.3.5 Initiator filter policy.
  switch (initiator_.initiator_filter_policy) {
    case bluetooth::hci::InitiatorFilterPolicy::USE_PEER_ADDRESS:
      if (resolved_advertising_address != initiator_.peer_address) {
        DEBUG(id_,
              "Legacy advertising ignored by initiator because the "
              "advertising address {} does not match the peer address {}",
              resolved_advertising_address, initiator_.peer_address);
        return;
      }
      break;
    case bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST:
      if (!LeFilterAcceptListContainsDevice(resolved_advertising_address)) {
        DEBUG(id_,
              "Legacy advertising ignored by initiator because the "
              "advertising address {} is not in the filter accept list",
              resolved_advertising_address);
        return;
      }
      break;
  }

  // When an initiator receives a directed connectable advertising event that
  // contains a resolvable private address for the target’s address
  // (TargetA field) and address resolution is enabled, the Link Layer shall
  // resolve the private address using the resolving list’s Local IRK values.
  // An initiator that has been instructed by the Host to use Resolvable Private
  // Addresses shall not respond to directed connectable advertising events that
  // contain Public or Static addresses for the target’s address (TargetA
  // field).
  if (directed_advertising) {
    if (!ValidateTargetA(target_address, resolved_advertising_address)) {
      DEBUG(id_,
            "Directed legacy advertising ignored by initiator because the "
            "target address {} does not match the current device addresses",
            target_address);
      return;
    }
    if (!target_address.IsRpa() &&
        (initiator_.own_address_type ==
             OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS ||
         initiator_.own_address_type ==
             OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS)) {
      DEBUG(id_,
            "Directed legacy advertising ignored by initiator because the "
            "target address {} is static or public and the initiator is "
            "configured to use resolvable addresses",
            target_address);
      return;
    }
  }

  AddressWithType public_address{address_, AddressType::PUBLIC_DEVICE_ADDRESS};
  AddressWithType random_address{random_address_,
                                 AddressType::RANDOM_DEVICE_ADDRESS};
  std::optional<AddressWithType> resolvable_initiating_address =
      GenerateResolvablePrivateAddress(resolved_advertising_address,
                                       IrkSelection::Local);

  // The Link Layer shall use resolvable private addresses for the initiator’s
  // device address (InitA field) when initiating connection establishment with
  // an associated device that exists in the Resolving List.
  AddressWithType initiating_address;
  switch (initiator_.own_address_type) {
    case bluetooth::hci::OwnAddressType::PUBLIC_DEVICE_ADDRESS:
      initiating_address = public_address;
      break;
    case bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS:
      // The random address is checked in Le_Create_Connection or
      // Le_Extended_Create_Connection.
      ASSERT(random_address_ != Address::kEmpty);
      initiating_address = random_address;
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS:
      initiating_address =
          resolvable_initiating_address.value_or(public_address);
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
      // The random address is checked in Le_Create_Connection or
      // Le_Extended_Create_Connection.
      ASSERT(random_address_ != Address::kEmpty);
      initiating_address =
          resolvable_initiating_address.value_or(random_address);
      break;
  }

  if (!connections_.CreatePendingLeConnection(
          advertising_address,
          resolved_advertising_address != advertising_address
              ? resolved_advertising_address
              : AddressWithType{},
          initiating_address)) {
    WARNING(id_, "CreatePendingLeConnection failed for connection to {}",
            advertising_address);
  }

  initiator_.pending_connect_request = advertising_address;
  initiator_.initiating_address = initiating_address.GetAddress();

  INFO(id_, "Sending LE Connect request to {} with initiating address {}",
       resolved_advertising_address, initiating_address);

  // The advertiser’s device address (AdvA field) in the initiating PDU
  // shall be the same as the advertiser’s device address (AdvA field)
  // received in the advertising event PDU to which the initiator is
  // responding.
  SendLeLinkLayerPacket(model::packets::LeConnectBuilder::Create(
      initiating_address.GetAddress(), advertising_address.GetAddress(),
      static_cast<model::packets::AddressType>(
          initiating_address.GetAddressType()),
      static_cast<model::packets::AddressType>(
          advertising_address.GetAddressType()),
      // The connection is created with the highest allowed
      // value for the connection interval and the latency.
      initiator_.le_1m_phy.connection_interval_max,
      initiator_.le_1m_phy.max_latency,
      initiator_.le_1m_phy.supervision_timeout));
}

void LinkLayerController::IncomingLeLegacyAdvertisingPdu(
    model::packets::LinkLayerPacketView incoming, uint8_t rssi) {
  auto pdu = model::packets::LeLegacyAdvertisingPduView::Create(incoming);
  ASSERT(pdu.IsValid());

  ScanIncomingLeLegacyAdvertisingPdu(pdu, rssi);
  ConnectIncomingLeLegacyAdvertisingPdu(pdu);
}

// Handle legacy advertising PDUs while in the Scanning state.
void LinkLayerController::ScanIncomingLeExtendedAdvertisingPdu(
    model::packets::LeExtendedAdvertisingPduView& pdu, uint8_t rssi) {
  if (!scanner_.IsEnabled()) {
    return;
  }
  if (!ExtendedAdvertising()) {
    DEBUG(id_, "Extended advertising ignored because the scanner is legacy");
    return;
  }

  std::vector<uint8_t> advertising_data = pdu.GetAdvertisingData();
  AddressWithType advertising_address{
      pdu.GetSourceAddress(),
      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};

  AddressWithType target_address{
      pdu.GetDestinationAddress(),
      static_cast<AddressType>(pdu.GetTargetAddressType())};

  bool scannable_advertising = pdu.GetScannable();
  bool connectable_advertising = pdu.GetConnectable();
  bool directed_advertising = pdu.GetDirected();

  // TODO: check originating PHY, compare against active scanning PHYs
  // (scanner_.le_1m_phy or scanner_.le_coded_phy).

  // When a scanner receives an advertising packet that contains a resolvable
  // private address for the advertiser’s device address (AdvA field) and
  // address resolution is enabled, the Link Layer shall resolve the private
  // address. The scanner’s filter policy shall then determine if the scanner
  // responds with a scan request.
  AddressWithType resolved_advertising_address =
      ResolvePrivateAddress(advertising_address).value_or(advertising_address);

  if (resolved_advertising_address != advertising_address) {
    DEBUG(id_, "Resolved the advertising address {} to {}", advertising_address,
          bluetooth::hci::AddressTypeText(advertising_address.GetAddressType()),
          resolved_advertising_address,
          bluetooth::hci::AddressTypeText(
              resolved_advertising_address.GetAddressType()));
  }

  // Vol 6, Part B § 4.3.3 Scanner filter policy
  switch (scanner_.scan_filter_policy) {
    case bluetooth::hci::LeScanningFilterPolicy::ACCEPT_ALL:
    case bluetooth::hci::LeScanningFilterPolicy::CHECK_INITIATORS_IDENTITY:
      break;
    case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY:
    case bluetooth::hci::LeScanningFilterPolicy::
        FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY:
      if (!LeFilterAcceptListContainsDevice(resolved_advertising_address)) {
        DEBUG(id_,
              "Extended advertising ignored by scanner because the advertising "
              "address {} is not in the filter accept list",
              resolved_advertising_address);
        return;
      }
      break;
  }

  if (directed_advertising) {
    switch (scanner_.scan_filter_policy) {
      // In both basic scanner filter policy modes, a directed advertising PDU
      // shall be ignored unless either:
      //  • the TargetA field is identical to the scanner's device address, or
      //  • the TargetA field is a resolvable private address, address
      //    resolution is enabled, and the address is resolved successfully
      case bluetooth::hci::LeScanningFilterPolicy::ACCEPT_ALL:
      case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY:
        if (!ValidateTargetA(target_address, resolved_advertising_address)) {
          DEBUG(id_,
                "Extended advertising ignored by scanner because the directed "
                "address {} does not match the current device or cannot be "
                "resolved",
                target_address);
          return;
        }
        break;
      // These are identical to the basic modes except
      // that a directed advertising PDU shall be ignored unless either:
      //  • the TargetA field is identical to the scanner's device address, or
      //  • the TargetA field is a resolvable private address.
      case bluetooth::hci::LeScanningFilterPolicy::CHECK_INITIATORS_IDENTITY:
      case bluetooth::hci::LeScanningFilterPolicy::
          FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY:
        if (!IsLocalPublicOrRandomAddress(target_address) &&
            !target_address.IsRpa()) {
          DEBUG(id_,
                "Extended advertising ignored by scanner because the directed "
                "address {} does not match the current device or is not a "
                "resovable private address",
                target_address);
          return;
        }
        break;
    }
  }

  bool should_send_advertising_report = true;
  if (scanner_.filter_duplicates !=
      bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(pdu.bytes())) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(pdu.bytes());
    }
  }

  if (should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponse response;
    response.connectable_ = connectable_advertising;
    response.scannable_ = scannable_advertising;
    response.directed_ = directed_advertising;
    response.scan_response_ = false;
    response.legacy_ = false;
    response.data_status_ = bluetooth::hci::DataStatus::COMPLETE;
    response.address_type_ =
        static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
            resolved_advertising_address.GetAddressType());
    response.address_ = resolved_advertising_address.GetAddress();
    response.primary_phy_ = bluetooth::hci::PrimaryPhyType::LE_1M;
    response.secondary_phy_ = bluetooth::hci::SecondaryPhyType::NO_PACKETS;
    response.advertising_sid_ = pdu.GetSid();
    response.tx_power_ = pdu.GetTxPower();
    response.rssi_ = rssi;
    response.periodic_advertising_interval_ =
        pdu.GetPeriodicAdvertisingInterval();
    if (directed_advertising) {
      response.direct_address_type_ =
          bluetooth::hci::DirectAdvertisingAddressType(
              target_address.GetAddressType());
      response.direct_address_ = target_address.GetAddress();
    } else {
      response.direct_address_type_ =
          bluetooth::hci::DirectAdvertisingAddressType::NO_ADDRESS_PROVIDED;
      response.direct_address_ = Address::kEmpty;
    }
    response.advertising_data_ = advertising_data;

    // Each extended advertising report can only pass 229 bytes of
    // advertising data (255 - size of report fields).
    // RootCanal must fragment the report as necessary.
    const size_t max_fragment_size = 229;
    size_t offset = 0;
    do {
      size_t remaining_size = advertising_data.size() - offset;
      size_t fragment_size = std::min(max_fragment_size, remaining_size);
      response.data_status_ = remaining_size <= max_fragment_size
                                  ? bluetooth::hci::DataStatus::COMPLETE
                                  : bluetooth::hci::DataStatus::CONTINUING;
      response.advertising_data_ =
          std::vector(advertising_data.begin() + offset,
                      advertising_data.begin() + offset + fragment_size);
      offset += fragment_size;
      send_event_(bluetooth::hci::LeExtendedAdvertisingReportBuilder::Create(
          {response}));
    } while (offset < advertising_data.size());
  }

  // Did the user enable Active scanning ?
  bool active_scanning =
      (scanner_.le_1m_phy.enabled &&
       scanner_.le_1m_phy.scan_type == bluetooth::hci::LeScanType::ACTIVE) ||
      (scanner_.le_coded_phy.enabled &&
       scanner_.le_coded_phy.scan_type == bluetooth::hci::LeScanType::ACTIVE);

  // Active scanning.
  // Note: only send SCAN requests in response to scannable advertising
  // events (ADV_IND, ADV_SCAN_IND).
  if (!scannable_advertising) {
    DEBUG(id_,
          "Not sending LE Scan request to advertising address {} because "
          "it is not scannable",
          advertising_address);
  } else if (!active_scanning) {
    DEBUG(id_,
          "Not sending LE Scan request to advertising address {} because "
          "the scanner is passive",
          advertising_address);
  } else if (scanner_.pending_scan_request) {
    DEBUG(id_,
          "Not sending LE Scan request to advertising address {} because "
          "an LE Scan request is already pending",
          advertising_address);
  } else if (!should_send_advertising_report) {
    DEBUG(id_,
          "Not sending LE Scan request to advertising address {} because "
          "the advertising message was filtered",
          advertising_address);
  } else {
    // TODO: apply privacy mode in resolving list.
    // Scan requests with public or random device addresses must be ignored
    // when the peer has network privacy mode.

    AddressWithType public_address{address_,
                                   AddressType::PUBLIC_DEVICE_ADDRESS};
    AddressWithType random_address{random_address_,
                                   AddressType::RANDOM_DEVICE_ADDRESS};
    std::optional<AddressWithType> resolvable_address =
        GenerateResolvablePrivateAddress(resolved_advertising_address,
                                         IrkSelection::Local);

    // The ScanA field of the scanning PDU is generated using the
    // Resolving List’s Local IRK value and the Resolvable Private Address
    // Generation procedure (see Section 1.3.2.2), or the address is provided
    // by the Host.
    AddressWithType scanning_address;
    std::optional<AddressWithType> resolvable_scanning_address;
    switch (scanner_.own_address_type) {
      case bluetooth::hci::OwnAddressType::PUBLIC_DEVICE_ADDRESS:
        scanning_address = public_address;
        break;
      case bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS:
        // The random address is checked in Le_Set_Scan_Enable or
        // Le_Set_Extended_Scan_Enable.
        ASSERT(random_address_ != Address::kEmpty);
        scanning_address = random_address;
        break;
      case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS:
        scanning_address = resolvable_address.value_or(public_address);
        break;
      case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
        // The random address is checked in Le_Set_Scan_Enable or
        // Le_Set_Extended_Scan_Enable.
        ASSERT(random_address_ != Address::kEmpty);
        scanning_address = resolvable_address.value_or(random_address);
        break;
    }

    // Save the original advertising type to report if the advertising
    // is connectable in the scan response report.
    scanner_.connectable_scan_response = connectable_advertising;
    scanner_.extended_scan_response = true;
    scanner_.pending_scan_request = advertising_address;

    INFO(id_,
         "Sending LE Scan request to advertising address {} with scanning "
         "address {}",
         advertising_address, scanning_address);

    // The advertiser’s device address (AdvA field) in the scan request PDU
    // shall be the same as the advertiser’s device address (AdvA field)
    // received in the advertising PDU to which the scanner is responding.
    SendLeLinkLayerPacket(model::packets::LeScanBuilder::Create(
        scanning_address.GetAddress(), advertising_address.GetAddress(),
        static_cast<model::packets::AddressType>(
            scanning_address.GetAddressType()),
        static_cast<model::packets::AddressType>(
            advertising_address.GetAddressType())));
  }
}

void LinkLayerController::ConnectIncomingLeExtendedAdvertisingPdu(
    model::packets::LeExtendedAdvertisingPduView& pdu) {
  if (!initiator_.IsEnabled()) {
    return;
  }
  if (!ExtendedAdvertising()) {
    DEBUG(id_, "Extended advertising ignored because the initiator is legacy");
    return;
  }

  // Connection.
  // Note: only send CONNECT requests in response to connectable advertising
  // events (ADV_IND, ADV_DIRECT_IND).
  if (!pdu.GetConnectable()) {
    DEBUG(id_,
          "Extended advertising ignored by initiator because it is not "
          "connectable");
    return;
  }
  if (initiator_.pending_connect_request) {
    DEBUG(
        id_,
        "Extended advertising ignored because an LE Connect request is already "
        "pending");
    return;
  }

  AddressWithType advertising_address{
      pdu.GetSourceAddress(),
      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};

  AddressWithType target_address{
      pdu.GetDestinationAddress(),
      static_cast<AddressType>(pdu.GetTargetAddressType())};

  AddressWithType resolved_advertising_address =
      ResolvePrivateAddress(advertising_address).value_or(advertising_address);

  // Vol 6, Part B § 4.3.5 Initiator filter policy.
  switch (initiator_.initiator_filter_policy) {
    case bluetooth::hci::InitiatorFilterPolicy::USE_PEER_ADDRESS:
      if (resolved_advertising_address != initiator_.peer_address) {
        DEBUG(id_,
              "Extended advertising ignored by initiator because the "
              "advertising address {} does not match the peer address {}",
              resolved_advertising_address, initiator_.peer_address);
        return;
      }
      break;
    case bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST:
      if (!LeFilterAcceptListContainsDevice(resolved_advertising_address)) {
        DEBUG(id_,
              "Extended advertising ignored by initiator because the "
              "advertising address {} is not in the filter accept list",
              resolved_advertising_address);
        return;
      }
      break;
  }

  // When an initiator receives a directed connectable advertising event that
  // contains a resolvable private address for the target’s address
  // (TargetA field) and address resolution is enabled, the Link Layer shall
  // resolve the private address using the resolving list’s Local IRK values.
  // An initiator that has been instructed by the Host to use Resolvable Private
  // Addresses shall not respond to directed connectable advertising events that
  // contain Public or Static addresses for the target’s address (TargetA
  // field).
  if (pdu.GetDirected()) {
    if (!ValidateTargetA(target_address, resolved_advertising_address)) {
      DEBUG(id_,
            "Directed extended advertising ignored by initiator because the "
            "target address {} does not match the current device addresses",
            target_address);
      return;
    }
    if (!target_address.IsRpa() &&
        (initiator_.own_address_type ==
             OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS ||
         initiator_.own_address_type ==
             OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS)) {
      DEBUG(id_,
            "Directed extended advertising ignored by initiator because the "
            "target address {} is static or public and the initiator is "
            "configured to use resolvable addresses",
            target_address);
      return;
    }
  }

  AddressWithType public_address{address_, AddressType::PUBLIC_DEVICE_ADDRESS};
  AddressWithType random_address{random_address_,
                                 AddressType::RANDOM_DEVICE_ADDRESS};
  std::optional<AddressWithType> resolvable_initiating_address =
      GenerateResolvablePrivateAddress(resolved_advertising_address,
                                       IrkSelection::Local);

  // The Link Layer shall use resolvable private addresses for the initiator’s
  // device address (InitA field) when initiating connection establishment with
  // an associated device that exists in the Resolving List.
  AddressWithType initiating_address;
  switch (initiator_.own_address_type) {
    case bluetooth::hci::OwnAddressType::PUBLIC_DEVICE_ADDRESS:
      initiating_address = public_address;
      break;
    case bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS:
      // The random address is checked in Le_Create_Connection or
      // Le_Extended_Create_Connection.
      ASSERT(random_address_ != Address::kEmpty);
      initiating_address = random_address;
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS:
      initiating_address =
          resolvable_initiating_address.value_or(public_address);
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
      // The random address is checked in Le_Create_Connection or
      // Le_Extended_Create_Connection.
      ASSERT(random_address_ != Address::kEmpty);
      initiating_address =
          resolvable_initiating_address.value_or(random_address);
      break;
  }

  if (!connections_.CreatePendingLeConnection(
          advertising_address,
          resolved_advertising_address != advertising_address
              ? resolved_advertising_address
              : AddressWithType{},
          initiating_address)) {
    WARNING(id_, "CreatePendingLeConnection failed for connection to {}",
            advertising_address);
  }

  initiator_.pending_connect_request = advertising_address;
  initiator_.initiating_address = initiating_address.GetAddress();

  INFO(id_, "Sending LE Connect request to {} with initiating address {}",
       resolved_advertising_address, initiating_address);

  // The advertiser’s device address (AdvA field) in the initiating PDU
  // shall be the same as the advertiser’s device address (AdvA field)
  // received in the advertising event PDU to which the initiator is
  // responding.
  SendLeLinkLayerPacket(model::packets::LeConnectBuilder::Create(
      initiating_address.GetAddress(), advertising_address.GetAddress(),
      static_cast<model::packets::AddressType>(
          initiating_address.GetAddressType()),
      static_cast<model::packets::AddressType>(
          advertising_address.GetAddressType()),
      // The connection is created with the highest allowed value
      // for the connection interval and the latency.
      initiator_.le_1m_phy.connection_interval_max,
      initiator_.le_1m_phy.max_latency,
      initiator_.le_1m_phy.supervision_timeout));
}

void LinkLayerController::IncomingLeExtendedAdvertisingPdu(
    model::packets::LinkLayerPacketView incoming, uint8_t rssi) {
  auto pdu = model::packets::LeExtendedAdvertisingPduView::Create(incoming);
  ASSERT(pdu.IsValid());

  ScanIncomingLeExtendedAdvertisingPdu(pdu, rssi);
  ConnectIncomingLeExtendedAdvertisingPdu(pdu);
}

void LinkLayerController::IncomingLePeriodicAdvertisingPdu(
    model::packets::LinkLayerPacketView incoming, uint8_t rssi) {
  auto pdu = model::packets::LePeriodicAdvertisingPduView::Create(incoming);
  ASSERT(pdu.IsValid());

  // Synchronization with periodic advertising only occurs while extended
  // scanning is enabled.
  if (!scanner_.IsEnabled()) {
    return;
  }
  if (!ExtendedAdvertising()) {
    DEBUG(id_, "Extended advertising ignored because the scanner is legacy");
    return;
  }

  AddressWithType advertiser_address{
      pdu.GetSourceAddress(),
      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};
  uint8_t advertising_sid = pdu.GetSid();

  // When a scanner receives an advertising packet that contains a resolvable
  // private address for the advertiser's device address (AdvA field) and
  // address resolution is enabled, the Link Layer shall resolve the private
  // address. The scanner's periodic sync establishment filter policy shall
  // determine if the scanner processes the advertising packet.
  AddressWithType resolved_advertiser_address =
      ResolvePrivateAddress(advertiser_address).value_or(advertiser_address);

  bluetooth::hci::AdvertiserAddressType advertiser_address_type;
  switch (resolved_advertiser_address.GetAddressType()) {
    case AddressType::PUBLIC_DEVICE_ADDRESS:
    case AddressType::PUBLIC_IDENTITY_ADDRESS:
    default:
      advertiser_address_type = bluetooth::hci::AdvertiserAddressType::
          PUBLIC_DEVICE_OR_IDENTITY_ADDRESS;
      break;
    case AddressType::RANDOM_DEVICE_ADDRESS:
    case AddressType::RANDOM_IDENTITY_ADDRESS:
      advertiser_address_type = bluetooth::hci::AdvertiserAddressType::
          RANDOM_DEVICE_OR_IDENTITY_ADDRESS;
      break;
  }

  // Check if the periodic advertising PDU matches a pending
  // LE Periodic Advertising Create Sync command.
  // The direct parameters or the periodic advertiser list are used
  // depending on the synchronizing options.
  bool matches_synchronizing = false;
  if (synchronizing_.has_value()) {
    matches_synchronizing =
        synchronizing_->options.use_periodic_advertiser_list_
            ? LePeriodicAdvertiserListContainsDevice(
                  advertiser_address_type,
                  resolved_advertiser_address.GetAddress(), advertising_sid)
            : synchronizing_->advertiser_address_type ==
                      advertiser_address_type &&
                  synchronizing_->advertiser_address ==
                      resolved_advertiser_address.GetAddress() &&
                  synchronizing_->advertising_sid == advertising_sid;
  }

  // If the periodic advertising event matches the synchronizing state,
  // create the synchronized train and report to the Host.
  if (matches_synchronizing) {
    INFO(id_, "Established Sync with advertiser {}[{}] - SID 0x{:x}",
         advertiser_address,
         bluetooth::hci::AdvertiserAddressTypeText(advertiser_address_type),
         advertising_sid);
    // Use the first unused Sync_Handle.
    // Note: sync handles are allocated from a different number space
    // compared to connection handles.
    uint16_t sync_handle = 0;
    for (; synchronized_.count(sync_handle) != 0; sync_handle++) {
    }

    // Notify of the new Synchronized train.
    if (IsLeEventUnmasked(
            SubeventCode::PERIODIC_ADVERTISING_SYNC_ESTABLISHED)) {
      send_event_(
          bluetooth::hci::LePeriodicAdvertisingSyncEstablishedBuilder::Create(
              ErrorCode::SUCCESS, sync_handle, advertising_sid,
              resolved_advertiser_address.GetAddressType(),
              resolved_advertiser_address.GetAddress(),
              bluetooth::hci::SecondaryPhyType::LE_1M,
              pdu.GetAdvertisingInterval(),
              bluetooth::hci::ClockAccuracy::PPM_500));
    }

    // Update the synchronization state.
    synchronized_.insert(
        {sync_handle,
         Synchronized{
             .advertiser_address_type = advertiser_address_type,
             .advertiser_address = resolved_advertiser_address.GetAddress(),
             .advertising_sid = advertising_sid,
             .sync_handle = sync_handle,
             .sync_timeout = synchronizing_->sync_timeout,
             .timeout = std::chrono::steady_clock::now() +
                        synchronizing_->sync_timeout,
         }});

    // Quit synchronizing state.
    synchronizing_ = {};

    // Create Sync ensure that they are no other established syncs that
    // already match the advertiser address and advertising SID;
    // no need to check again.
    return;
  }

  // Check if the periodic advertising PDU matches any of the established
  // syncs.
  for (auto& [_, sync] : synchronized_) {
    if (sync.advertiser_address_type != advertiser_address_type ||
        sync.advertiser_address != resolved_advertiser_address.GetAddress() ||
        sync.advertising_sid != advertising_sid) {
      continue;
    }

    // Send a Periodic Advertising event for the matching Sync,
    // and refresh the timeout for sync termination. The periodic
    // advertising event might need to be fragmented to fit the maximum
    // size of an HCI event.
    if (IsLeEventUnmasked(SubeventCode::PERIODIC_ADVERTISING_REPORT)) {
      // Each extended advertising report can only pass 229 bytes of
      // advertising data (255 - 8 = size of report fields).
      std::vector<uint8_t> advertising_data = pdu.GetAdvertisingData();
      const size_t max_fragment_size = 247;
      size_t offset = 0;
      do {
        size_t remaining_size = advertising_data.size() - offset;
        size_t fragment_size = std::min(max_fragment_size, remaining_size);

        bluetooth::hci::DataStatus data_status =
            remaining_size <= max_fragment_size
                ? bluetooth::hci::DataStatus::COMPLETE
                : bluetooth::hci::DataStatus::CONTINUING;
        std::vector<uint8_t> fragment_data(
            advertising_data.begin() + offset,
            advertising_data.begin() + offset + fragment_size);
        offset += fragment_size;
        send_event_(bluetooth::hci::LePeriodicAdvertisingReportBuilder::Create(
            sync.sync_handle, pdu.GetTxPower(), rssi,
            bluetooth::hci::CteType::NO_CONSTANT_TONE_EXTENSION, data_status,
            fragment_data));
      } while (offset < advertising_data.size());
    }

    // Refresh the timeout for the sync disconnection.
    sync.timeout = std::chrono::steady_clock::now() + sync.sync_timeout;
  }
}

void LinkLayerController::IncomingScoConnectionRequest(
    model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto request = model::packets::ScoConnectionRequestView::Create(incoming);
  ASSERT(request.IsValid());

  INFO(id_, "Received eSCO connection request from {}", address);

  // Automatically reject if connection request was already sent
  // from the current device.
  if (connections_.HasPendingScoConnection(address)) {
    INFO(id_,
         "Rejecting eSCO connection request from {}, "
         "an eSCO connection already exist with this device",
         address);

    SendLinkLayerPacket(model::packets::ScoConnectionResponseBuilder::Create(
        GetAddress(), address,
        (uint8_t)ErrorCode::SYNCHRONOUS_CONNECTION_LIMIT_EXCEEDED, 0, 0, 0, 0,
        0, 0));
    return;
  }

  // Create local connection context.
  ScoConnectionParameters connection_parameters = {
      request.GetTransmitBandwidth(),    request.GetReceiveBandwidth(),
      request.GetMaxLatency(),           request.GetVoiceSetting(),
      request.GetRetransmissionEffort(), request.GetPacketType()};

  bool extended = connection_parameters.IsExtended();
  connections_.CreateScoConnection(
      address, connection_parameters,
      extended ? ScoState::SCO_STATE_SENT_ESCO_CONNECTION_REQUEST
               : ScoState::SCO_STATE_SENT_SCO_CONNECTION_REQUEST,
      ScoDatapath::NORMAL);

  // Send connection request event and wait for Accept or Reject command.
  send_event_(bluetooth::hci::ConnectionRequestBuilder::Create(
      address, request.GetClassOfDevice(),
      extended ? bluetooth::hci::ConnectionRequestLinkType::ESCO
               : bluetooth::hci::ConnectionRequestLinkType::SCO));
}

void LinkLayerController::IncomingScoConnectionResponse(
    model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto response = model::packets::ScoConnectionResponseView::Create(incoming);
  ASSERT(response.IsValid());
  auto status = ErrorCode(response.GetStatus());
  bool is_legacy = connections_.IsLegacyScoConnection(address);

  INFO(id_, "Received eSCO connection response with status 0x{:02x} from {}",
       static_cast<unsigned>(status), incoming.GetSourceAddress());

  if (status == ErrorCode::SUCCESS) {
    bool extended = response.GetExtended();
    ScoLinkParameters link_parameters = {
        response.GetTransmissionInterval(),
        response.GetRetransmissionWindow(),
        response.GetRxPacketLength(),
        response.GetTxPacketLength(),
        response.GetAirMode(),
        extended,
    };

    connections_.AcceptPendingScoConnection(
        address, link_parameters, [this, address] {
          return LinkLayerController::StartScoStream(address);
        });

    if (is_legacy) {
      send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
          ErrorCode::SUCCESS, connections_.GetScoHandle(address), address,
          bluetooth::hci::LinkType::SCO, bluetooth::hci::Enable::DISABLED));
    } else {
      send_event_(bluetooth::hci::SynchronousConnectionCompleteBuilder::Create(
          ErrorCode::SUCCESS, connections_.GetScoHandle(address), address,
          extended ? bluetooth::hci::ScoLinkType::ESCO
                   : bluetooth::hci::ScoLinkType::SCO,
          extended ? response.GetTransmissionInterval() : 0,
          extended ? response.GetRetransmissionWindow() : 0,
          extended ? response.GetRxPacketLength() : 0,
          extended ? response.GetTxPacketLength() : 0,
          bluetooth::hci::ScoAirMode(response.GetAirMode())));
    }
  } else {
    connections_.CancelPendingScoConnection(address);
    if (is_legacy) {
      send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
          status, 0, address, bluetooth::hci::LinkType::SCO,
          bluetooth::hci::Enable::DISABLED));
    } else {
      ScoConnectionParameters connection_parameters =
          connections_.GetScoConnectionParameters(address);
      send_event_(bluetooth::hci::SynchronousConnectionCompleteBuilder::Create(
          status, 0, address,
          connection_parameters.IsExtended() ? bluetooth::hci::ScoLinkType::ESCO
                                             : bluetooth::hci::ScoLinkType::SCO,
          0, 0, 0, 0, bluetooth::hci::ScoAirMode::TRANSPARENT));
    }
  }
}

void LinkLayerController::IncomingScoDisconnect(
    model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto request = model::packets::ScoDisconnectView::Create(incoming);
  ASSERT(request.IsValid());
  auto reason = request.GetReason();
  uint16_t handle = connections_.GetScoHandle(address);

  INFO(id_,
       "Received eSCO disconnection request with"
       " reason 0x{:02x} from {}",
       static_cast<unsigned>(reason), incoming.GetSourceAddress());

  if (handle != kReservedHandle) {
    connections_.Disconnect(
        handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
    SendDisconnectionCompleteEvent(handle, ErrorCode(reason));
  }
}

void LinkLayerController::IncomingLmpPacket(
    model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto request = model::packets::LmpView::Create(incoming);
  ASSERT(request.IsValid());
  auto payload = request.GetPayload();
  auto packet = std::vector(payload.begin(), payload.end());

  ASSERT(link_manager_ingest_lmp(
      lm_.get(), reinterpret_cast<uint8_t(*)[6]>(address.data()), packet.data(),
      packet.size()));
}

void LinkLayerController::IncomingLlcpPacket(
    model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto request = model::packets::LlcpView::Create(incoming);
  ASSERT(request.IsValid());
  auto payload = request.GetPayload();
  auto packet = std::vector(payload.begin(), payload.end());
  uint16_t acl_connection_handle = connections_.GetHandleOnlyAddress(address);

  if (acl_connection_handle == kReservedHandle) {
    INFO(id_, "Dropping LLCP packet since connection does not exist");
    return;
  }

  ASSERT(link_layer_ingest_llcp(ll_.get(), acl_connection_handle, packet.data(),
                                packet.size()));
}

void LinkLayerController::IncomingLeConnectedIsochronousPdu(
    LinkLayerPacketView incoming) {
  auto pdu = model::packets::LeConnectedIsochronousPduView::Create(incoming);
  ASSERT(pdu.IsValid());
  auto data = pdu.GetData();
  auto packet = std::vector(data.begin(), data.end());
  uint8_t cig_id = pdu.GetCigId();
  uint8_t cis_id = pdu.GetCisId();
  uint16_t cis_connection_handle = 0;
  uint16_t iso_sdu_length = packet.size();

  if (!link_layer_get_cis_connection_handle(ll_.get(), cig_id, cis_id,
                                            &cis_connection_handle)) {
    INFO(id_,
         "Dropping CIS pdu received on disconnected CIS cig_id={}, cis_id={}",
         cig_id, cis_id);
    return;
  }

  // Fragment the ISO SDU if larger than the maximum payload size (4095).
  constexpr size_t kMaxPayloadSize = 4095 - 4;  // remove sequence_number and
                                                // iso_sdu_length
  size_t remaining_size = packet.size();
  size_t offset = 0;
  auto packet_boundary_flag =
      remaining_size <= kMaxPayloadSize
          ? bluetooth::hci::IsoPacketBoundaryFlag::COMPLETE_SDU
          : bluetooth::hci::IsoPacketBoundaryFlag::FIRST_FRAGMENT;

  do {
    size_t fragment_size = std::min(kMaxPayloadSize, remaining_size);
    std::vector<uint8_t> fragment(packet.data() + offset,
                                  packet.data() + offset + fragment_size);

    send_iso_(bluetooth::hci::IsoWithoutTimestampBuilder::Create(
        cis_connection_handle, packet_boundary_flag, pdu.GetSequenceNumber(),
        iso_sdu_length, bluetooth::hci::IsoPacketStatusFlag::VALID,
        std::move(fragment)));

    remaining_size -= fragment_size;
    offset += fragment_size;
    packet_boundary_flag =
        remaining_size <= kMaxPayloadSize
            ? bluetooth::hci::IsoPacketBoundaryFlag::LAST_FRAGMENT
            : bluetooth::hci::IsoPacketBoundaryFlag::CONTINUATION_FRAGMENT;
  } while (remaining_size > 0);
}

void LinkLayerController::HandleIso(bluetooth::hci::IsoView iso) {
  uint16_t cis_connection_handle = iso.GetConnectionHandle();
  auto pb_flag = iso.GetPbFlag();
  auto ts_flag = iso.GetTsFlag();
  auto iso_data_load = iso.GetPayload();

  // In the Host to Controller direction, ISO_Data_Load_Length
  // shall be less than or equal to the size of the buffer supported by the
  // Controller (which is returned using the ISO_Data_Packet_Length return
  // parameter of the LE Read Buffer Size command).
  if (iso_data_load.size() > properties_.iso_data_packet_length) {
    FATAL(id_,
          "Received ISO HCI packet with ISO_Data_Load_Length ({}) larger than"
          " the controller buffer size ISO_Data_Packet_Length ({})",
          iso_data_load.size(), properties_.iso_data_packet_length);
  }

  // The TS_Flag bit shall only be set if the PB_Flag field equals 0b00 or 0b10.
  if (ts_flag == bluetooth::hci::TimeStampFlag::PRESENT &&
      (pb_flag ==
           bluetooth::hci::IsoPacketBoundaryFlag::CONTINUATION_FRAGMENT ||
       pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::LAST_FRAGMENT)) {
    FATAL(id_,
          "Received ISO HCI packet with TS_Flag set, but no ISO Header is "
          "expected");
  }

  uint8_t cig_id = 0;
  uint8_t cis_id = 0;
  uint16_t acl_connection_handle = kReservedHandle;
  uint16_t packet_sequence_number = 0;
  uint16_t max_sdu_length = 0;

  if (!link_layer_get_cis_information(ll_.get(), cis_connection_handle,
                                      &acl_connection_handle, &cig_id, &cis_id,
                                      &max_sdu_length)) {
    INFO(id_, "Ignoring CIS pdu received on disconnected CIS handle={}",
         cis_connection_handle);
    return;
  }

  if (pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::FIRST_FRAGMENT ||
      pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::COMPLETE_SDU) {
    iso_sdu_.clear();
  }

  switch (ts_flag) {
    case bluetooth::hci::TimeStampFlag::PRESENT: {
      auto iso_with_timestamp =
          bluetooth::hci::IsoWithTimestampView::Create(iso);
      ASSERT(iso_with_timestamp.IsValid());
      auto iso_payload = iso_with_timestamp.GetPayload();
      iso_sdu_.insert(iso_sdu_.end(), iso_payload.begin(), iso_payload.end());
      packet_sequence_number = iso_with_timestamp.GetPacketSequenceNumber();
      break;
    }
    default:
    case bluetooth::hci::TimeStampFlag::NOT_PRESENT: {
      auto iso_without_timestamp =
          bluetooth::hci::IsoWithoutTimestampView::Create(iso);
      ASSERT(iso_without_timestamp.IsValid());
      auto iso_payload = iso_without_timestamp.GetPayload();
      iso_sdu_.insert(iso_sdu_.end(), iso_payload.begin(), iso_payload.end());
      packet_sequence_number = iso_without_timestamp.GetPacketSequenceNumber();
      break;
    }
  }

  if (pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::LAST_FRAGMENT ||
      pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::COMPLETE_SDU) {
    // Validate that the Host stack is not sending ISO SDUs that are larger
    // that what was configured for the CIS.
    if (iso_sdu_.size() > max_sdu_length) {
      WARNING(
          id_,
          "attempted to send an SDU of length {} that exceeds the configure "
          "Max_SDU_Length ({})",
          iso_sdu_.size(), max_sdu_length);
      return;
    }

    SendLeLinkLayerPacket(
        model::packets::LeConnectedIsochronousPduBuilder::Create(
            address_,
            connections_.GetAddress(acl_connection_handle).GetAddress(), cig_id,
            cis_id, packet_sequence_number, std::move(iso_sdu_)));
  }
}

uint16_t LinkLayerController::HandleLeConnection(
    AddressWithType address, AddressWithType own_address,
    bluetooth::hci::Role role, uint16_t connection_interval,
    uint16_t connection_latency, uint16_t supervision_timeout,
    bool send_le_channel_selection_algorithm_event) {
  // Note: the HCI_LE_Connection_Complete event is not sent if the
  // HCI_LE_Enhanced_Connection_Complete event (see Section 7.7.65.10) is
  // unmasked.

  uint16_t handle = connections_.CreateLeConnection(address, own_address, role);
  if (handle == kReservedHandle) {
    WARNING(id_, "No pending connection for connection from {}", address);
    return kReservedHandle;
  }

  if (IsLeEventUnmasked(SubeventCode::ENHANCED_CONNECTION_COMPLETE)) {
    AddressWithType peer_resolved_address =
        connections_.GetResolvedAddress(handle);
    Address peer_resolvable_private_address;
    Address connection_address = address.GetAddress();
    AddressType peer_address_type = address.GetAddressType();
    if (peer_resolved_address != AddressWithType()) {
      peer_resolvable_private_address = address.GetAddress();
      peer_address_type = peer_resolved_address.GetAddressType();
      connection_address = peer_resolved_address.GetAddress();
    }
    Address local_resolved_address = own_address.GetAddress();
    if (local_resolved_address == GetAddress() ||
        local_resolved_address == random_address_) {
      local_resolved_address = Address::kEmpty;
    }

    send_event_(bluetooth::hci::LeEnhancedConnectionCompleteBuilder::Create(
        ErrorCode::SUCCESS, handle, role, peer_address_type, connection_address,
        local_resolved_address, peer_resolvable_private_address,
        connection_interval, connection_latency, supervision_timeout,
        static_cast<bluetooth::hci::ClockAccuracy>(0x00)));
  } else if (IsLeEventUnmasked(SubeventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::LeConnectionCompleteBuilder::Create(
        ErrorCode::SUCCESS, handle, role, address.GetAddressType(),
        address.GetAddress(), connection_interval, connection_latency,
        supervision_timeout, static_cast<bluetooth::hci::ClockAccuracy>(0x00)));
  }

  // Update the link layer with the new link.
  ASSERT(link_layer_add_link(
      ll_.get(), handle,
      reinterpret_cast<const uint8_t(*)[6]>(address.GetAddress().data()),
      static_cast<uint8_t>(role)));

  // Note: the HCI_LE_Connection_Complete event is immediately followed by
  // an HCI_LE_Channel_Selection_Algorithm event if the connection is created
  // using the LE_Extended_Create_Connection command (see Section 7.7.8.66).
  if (send_le_channel_selection_algorithm_event &&
      IsLeEventUnmasked(SubeventCode::CHANNEL_SELECTION_ALGORITHM)) {
    // The selection channel algorithm probably will have no impact
    // on emulation.
    send_event_(bluetooth::hci::LeChannelSelectionAlgorithmBuilder::Create(
        handle, bluetooth::hci::ChannelSelectionAlgorithm::ALGORITHM_1));
  }

  if (own_address.GetAddress() == initiator_.initiating_address) {
    initiator_.initiating_address = Address::kEmpty;
  }
  return handle;
}

// Handle CONNECT_IND PDUs for the legacy advertiser.
bool LinkLayerController::ProcessIncomingLegacyConnectRequest(
    model::packets::LeConnectView const& connect_ind) {
  if (!legacy_advertiser_.IsEnabled()) {
    return false;
  }
  if (!legacy_advertiser_.IsConnectable()) {
    DEBUG(id_,
          "LE Connect request ignored by legacy advertiser because it is not "
          "connectable");
    return false;
  }

  AddressWithType advertising_address{
      connect_ind.GetDestinationAddress(),
      static_cast<AddressType>(connect_ind.GetAdvertisingAddressType()),
  };

  AddressWithType initiating_address{
      connect_ind.GetSourceAddress(),
      static_cast<AddressType>(connect_ind.GetInitiatingAddressType()),
  };

  if (legacy_advertiser_.GetAdvertisingAddress() != advertising_address) {
    DEBUG(id_,
          "LE Connect request ignored by legacy advertiser because the "
          "advertising address {} does not match {}",
          advertising_address, legacy_advertiser_.GetAdvertisingAddress());
    return false;
  }

  // When an advertiser receives a connection request that contains a resolvable
  // private address for the initiator’s address (InitA field) and address
  // resolution is enabled, the Link Layer shall resolve the private address.
  // The advertising filter policy shall then determine if the
  // advertiser establishes a connection.
  AddressWithType resolved_initiating_address =
      ResolvePrivateAddress(initiating_address).value_or(initiating_address);

  if (resolved_initiating_address != initiating_address) {
    DEBUG(id_, "Resolved the initiating address {} to {}", initiating_address,
          resolved_initiating_address);
  }

  // When the Link Layer is [...] connectable directed advertising events the
  // advertising filter policy shall be ignored.
  if (legacy_advertiser_.IsDirected()) {
    if (resolved_initiating_address !=
        PeerDeviceAddress(legacy_advertiser_.peer_address,
                          legacy_advertiser_.peer_address_type)) {
      DEBUG(id_,
            "LE Connect request ignored by legacy advertiser because the "
            "initiating address {} does not match the target address {}[{}]",
            resolved_initiating_address, legacy_advertiser_.peer_address,
            PeerAddressTypeText(legacy_advertiser_.peer_address_type));
      return false;
    }
  } else {
    // Check if initiator address is in the filter accept list
    // for this advertiser.
    switch (legacy_advertiser_.advertising_filter_policy) {
      case bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES:
      case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN:
        break;
      case bluetooth::hci::AdvertisingFilterPolicy::LISTED_CONNECT:
      case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN_AND_CONNECT:
        if (!LeFilterAcceptListContainsDevice(resolved_initiating_address)) {
          DEBUG(id_,
                "LE Connect request ignored by legacy advertiser because the "
                "initiating address {} is not in the filter accept list",
                resolved_initiating_address);
          return false;
        }
        break;
    }
  }

  INFO(id_,
       "Accepting LE Connect request to legacy advertiser from initiating "
       "address {}",
       resolved_initiating_address);

  if (!connections_.CreatePendingLeConnection(
          initiating_address,
          resolved_initiating_address != initiating_address
              ? resolved_initiating_address
              : AddressWithType{},
          advertising_address)) {
    WARNING(id_, "CreatePendingLeConnection failed for connection from {}",
            initiating_address.GetAddress());
    return false;
  }

  (void)HandleLeConnection(
      initiating_address, advertising_address, bluetooth::hci::Role::PERIPHERAL,
      connect_ind.GetConnInterval(), connect_ind.GetConnPeripheralLatency(),
      connect_ind.GetConnSupervisionTimeout(), false);

  SendLeLinkLayerPacket(model::packets::LeConnectCompleteBuilder::Create(
      advertising_address.GetAddress(), initiating_address.GetAddress(),
      static_cast<model::packets::AddressType>(
          initiating_address.GetAddressType()),
      static_cast<model::packets::AddressType>(
          advertising_address.GetAddressType()),
      connect_ind.GetConnInterval(), connect_ind.GetConnPeripheralLatency(),
      connect_ind.GetConnSupervisionTimeout()));

  legacy_advertiser_.Disable();
  return true;
}

// Handle CONNECT_IND PDUs for the selected extended advertiser.
bool LinkLayerController::ProcessIncomingExtendedConnectRequest(
    ExtendedAdvertiser& advertiser,
    model::packets::LeConnectView const& connect_ind) {
  if (!advertiser.IsEnabled()) {
    return false;
  }
  if (!advertiser.IsConnectable()) {
    DEBUG(id_,
          "LE Connect request ignored by extended advertiser {} because it is "
          "not connectable",
          advertiser.advertising_handle);
    return false;
  }

  AddressWithType advertising_address{
      connect_ind.GetDestinationAddress(),
      static_cast<AddressType>(connect_ind.GetAdvertisingAddressType()),
  };

  AddressWithType initiating_address{
      connect_ind.GetSourceAddress(),
      static_cast<AddressType>(connect_ind.GetInitiatingAddressType()),
  };

  if (advertiser.GetAdvertisingAddress() != advertising_address) {
    DEBUG(id_,
          "LE Connect request ignored by extended advertiser {} because the "
          "advertising address {} does not match {}",
          advertiser.advertising_handle, advertising_address,
          advertiser.GetAdvertisingAddress());
    return false;
  }

  // When an advertiser receives a connection request that contains a resolvable
  // private address for the initiator’s address (InitA field) and address
  // resolution is enabled, the Link Layer shall resolve the private address.
  // The advertising filter policy shall then determine if the
  // advertiser establishes a connection.
  AddressWithType resolved_initiating_address =
      ResolvePrivateAddress(initiating_address).value_or(initiating_address);

  if (resolved_initiating_address != initiating_address) {
    DEBUG(id_, "Resolved the initiating address {} to {}", initiating_address,
          resolved_initiating_address);
  }

  // When the Link Layer is [...] connectable directed advertising events the
  // advertising filter policy shall be ignored.
  if (advertiser.IsDirected()) {
    if (resolved_initiating_address !=
        PeerDeviceAddress(advertiser.peer_address,
                          advertiser.peer_address_type)) {
      DEBUG(id_,
            "LE Connect request ignored by extended advertiser {} because the "
            "initiating address {} does not match the target address {}[{}]",
            advertiser.advertising_handle, resolved_initiating_address,
            advertiser.peer_address,
            PeerAddressTypeText(advertiser.peer_address_type));
      return false;
    }
  } else {
    // Check if initiator address is in the filter accept list
    // for this advertiser.
    switch (advertiser.advertising_filter_policy) {
      case bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES:
      case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN:
        break;
      case bluetooth::hci::AdvertisingFilterPolicy::LISTED_CONNECT:
      case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN_AND_CONNECT:
        if (!LeFilterAcceptListContainsDevice(resolved_initiating_address)) {
          DEBUG(id_,
                "LE Connect request ignored by extended advertiser {} because "
                "the initiating address {} is not in the filter accept list",
                advertiser.advertising_handle, resolved_initiating_address);
          return false;
        }
        break;
    }
  }

  INFO(id_,
       "Accepting LE Connect request to extended advertiser {} from initiating "
       "address {}",
       advertiser.advertising_handle, resolved_initiating_address);

  if (!connections_.CreatePendingLeConnection(
          initiating_address,
          resolved_initiating_address != initiating_address
              ? resolved_initiating_address
              : AddressWithType{},
          advertising_address)) {
    WARNING(id_, "CreatePendingLeConnection failed for connection from {}",
            initiating_address.GetAddress());
    return false;
  }

  advertiser.Disable();

  uint16_t connection_handle = HandleLeConnection(
      initiating_address, advertising_address, bluetooth::hci::Role::PERIPHERAL,
      connect_ind.GetConnInterval(), connect_ind.GetConnPeripheralLatency(),
      connect_ind.GetConnSupervisionTimeout(), false);

  SendLeLinkLayerPacket(model::packets::LeConnectCompleteBuilder::Create(
      advertising_address.GetAddress(), initiating_address.GetAddress(),
      static_cast<model::packets::AddressType>(
          initiating_address.GetAddressType()),
      static_cast<model::packets::AddressType>(
          advertising_address.GetAddressType()),
      connect_ind.GetConnInterval(), connect_ind.GetConnPeripheralLatency(),
      connect_ind.GetConnSupervisionTimeout()));

  // If the advertising set is connectable and a connection gets created, an
  // HCI_LE_Connection_Complete or HCI_LE_Enhanced_Connection_Complete
  // event shall be generated followed by an HCI_LE_Advertising_Set_Terminated
  // event with the Status parameter set to 0x00. The Controller should not send
  // any other events in between these two events

  if (IsLeEventUnmasked(SubeventCode::ADVERTISING_SET_TERMINATED)) {
    send_event_(bluetooth::hci::LeAdvertisingSetTerminatedBuilder::Create(
        ErrorCode::SUCCESS, advertiser.advertising_handle, connection_handle,
        advertiser.num_completed_extended_advertising_events));
  }

  return true;
}

void LinkLayerController::IncomingLeConnectPacket(
    model::packets::LinkLayerPacketView incoming) {
  model::packets::LeConnectView connect =
      model::packets::LeConnectView::Create(incoming);
  ASSERT(connect.IsValid());

  if (ProcessIncomingLegacyConnectRequest(connect)) {
    return;
  }

  for (auto& [_, advertiser] : extended_advertisers_) {
    if (ProcessIncomingExtendedConnectRequest(advertiser, connect)) {
      return;
    }
  }
}

void LinkLayerController::IncomingLeConnectCompletePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto complete = model::packets::LeConnectCompleteView::Create(incoming);
  ASSERT(complete.IsValid());

  AddressWithType advertising_address{
      incoming.GetSourceAddress(), static_cast<bluetooth::hci::AddressType>(
                                       complete.GetAdvertisingAddressType())};

  INFO(id_, "Received LE Connect complete response with advertising address {}",
       advertising_address);

  HandleLeConnection(advertising_address,
                     AddressWithType(incoming.GetDestinationAddress(),
                                     static_cast<bluetooth::hci::AddressType>(
                                         complete.GetInitiatingAddressType())),
                     bluetooth::hci::Role::CENTRAL, complete.GetConnInterval(),
                     complete.GetConnPeripheralLatency(),
                     complete.GetConnSupervisionTimeout(),
                     ExtendedAdvertising());

  initiator_.pending_connect_request = {};
  initiator_.Disable();
}

void LinkLayerController::IncomingLeConnectionParameterRequest(
    model::packets::LinkLayerPacketView incoming) {
  auto request =
      model::packets::LeConnectionParameterRequestView::Create(incoming);
  ASSERT(request.IsValid());
  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    INFO(id_, "@{}: Unknown connection @{}", incoming.GetDestinationAddress(),
         peer);
    return;
  }

  if (IsLeEventUnmasked(SubeventCode::REMOTE_CONNECTION_PARAMETER_REQUEST)) {
    send_event_(
        bluetooth::hci::LeRemoteConnectionParameterRequestBuilder::Create(
            handle, request.GetIntervalMin(), request.GetIntervalMax(),
            request.GetLatency(), request.GetTimeout()));
  } else {
    // If the request is being indicated to the Host and the event to the Host
    // is masked, then the Link Layer shall issue an LL_REJECT_EXT_IND PDU with
    // the ErrorCode set to Unsupported Remote Feature (0x1A).
    SendLeLinkLayerPacket(
        model::packets::LeConnectionParameterUpdateBuilder::Create(
            request.GetDestinationAddress(), request.GetSourceAddress(),
            static_cast<uint8_t>(ErrorCode::UNSUPPORTED_REMOTE_OR_LMP_FEATURE),
            0, 0, 0));
  }
}

void LinkLayerController::IncomingLeConnectionParameterUpdate(
    model::packets::LinkLayerPacketView incoming) {
  auto update =
      model::packets::LeConnectionParameterUpdateView::Create(incoming);
  ASSERT(update.IsValid());
  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    INFO(id_, "@{}: Unknown connection @{}", incoming.GetDestinationAddress(),
         peer);
    return;
  }
  if (IsLeEventUnmasked(SubeventCode::CONNECTION_UPDATE_COMPLETE)) {
    send_event_(bluetooth::hci::LeConnectionUpdateCompleteBuilder::Create(
        static_cast<ErrorCode>(update.GetStatus()), handle,
        update.GetInterval(), update.GetLatency(), update.GetTimeout()));
  }
}

void LinkLayerController::IncomingLeEncryptConnection(
    model::packets::LinkLayerPacketView incoming) {
  INFO(id_, "IncomingLeEncryptConnection");

  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    INFO(id_, "@{}: Unknown connection @{}", incoming.GetDestinationAddress(),
         peer);
    return;
  }
  auto le_encrypt = model::packets::LeEncryptConnectionView::Create(incoming);
  ASSERT(le_encrypt.IsValid());

  // TODO: Save keys to check

  if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
    send_event_(bluetooth::hci::LeLongTermKeyRequestBuilder::Create(
        handle, le_encrypt.GetRand(), le_encrypt.GetEdiv()));
  }
}

void LinkLayerController::IncomingLeEncryptConnectionResponse(
    model::packets::LinkLayerPacketView incoming) {
  INFO(id_, "IncomingLeEncryptConnectionResponse");
  // TODO: Check keys
  uint16_t handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  if (handle == kReservedHandle) {
    INFO(id_, "@{}: Unknown connection @{}", incoming.GetDestinationAddress(),
         incoming.GetSourceAddress());
    return;
  }
  ErrorCode status = ErrorCode::SUCCESS;
  auto response =
      model::packets::LeEncryptConnectionResponseView::Create(incoming);
  ASSERT(response.IsValid());

  bool success = true;
  // Zero LTK is a rejection
  if (response.GetLtk() == std::array<uint8_t, 16>{0}) {
    status = ErrorCode::AUTHENTICATION_FAILURE;
    success = false;
  }

  if (connections_.IsEncrypted(handle)) {
    if (IsEventUnmasked(EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE)) {
      send_event_(bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(
          status, handle));
    }
  } else if (success) {
    connections_.Encrypt(handle);
    if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
      send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
          status, handle, bluetooth::hci::EncryptionEnabled::ON));
    }
  } else {
    if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
      send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
          status, handle, bluetooth::hci::EncryptionEnabled::OFF));
    }
  }
}

void LinkLayerController::IncomingLeReadRemoteFeatures(
    model::packets::LinkLayerPacketView incoming) {
  uint16_t handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  ErrorCode status = ErrorCode::SUCCESS;
  if (handle == kReservedHandle) {
    WARNING(id_, "@{}: Unknown connection @{}",
            incoming.GetDestinationAddress(), incoming.GetSourceAddress());
  }
  SendLeLinkLayerPacket(
      model::packets::LeReadRemoteFeaturesResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
          GetLeSupportedFeatures(), static_cast<uint8_t>(status)));
}

void LinkLayerController::IncomingLeReadRemoteFeaturesResponse(
    model::packets::LinkLayerPacketView incoming) {
  uint16_t handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  ErrorCode status = ErrorCode::SUCCESS;
  auto response =
      model::packets::LeReadRemoteFeaturesResponseView::Create(incoming);
  ASSERT(response.IsValid());
  if (handle == kReservedHandle) {
    INFO(id_, "@{}: Unknown connection @{}", incoming.GetDestinationAddress(),
         incoming.GetSourceAddress());
    status = ErrorCode::UNKNOWN_CONNECTION;
  } else {
    status = static_cast<ErrorCode>(response.GetStatus());
  }
  if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
    send_event_(bluetooth::hci::LeReadRemoteFeaturesCompleteBuilder::Create(
        status, handle, response.GetFeatures()));
  }
}

void LinkLayerController::ProcessIncomingLegacyScanRequest(
    AddressWithType scanning_address, AddressWithType resolved_scanning_address,
    AddressWithType advertising_address) {
  // Check if the advertising addresses matches the legacy
  // advertising address.
  if (!legacy_advertiser_.IsEnabled()) {
    return;
  }
  if (!legacy_advertiser_.IsScannable()) {
    DEBUG(id_,
          "LE Scan request ignored by legacy advertiser because it is not "
          "scannable");
    return;
  }

  if (advertising_address != legacy_advertiser_.advertising_address) {
    DEBUG(
        id_,
        "LE Scan request ignored by legacy advertiser because the advertising "
        "address {} does not match {}",
        advertising_address, legacy_advertiser_.GetAdvertisingAddress());
    return;
  }

  // Check if scanner address is in the filter accept list
  // for this advertiser.
  switch (legacy_advertiser_.advertising_filter_policy) {
    case bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES:
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_CONNECT:
      break;
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN:
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN_AND_CONNECT:
      if (!LeFilterAcceptListContainsDevice(resolved_scanning_address)) {
        DEBUG(
            id_,
            "LE Scan request ignored by legacy advertiser because the scanning "
            "address {} is not in the filter accept list",
            resolved_scanning_address);
        return;
      }
      break;
  }

  INFO(id_,
       "Accepting LE Scan request to legacy advertiser from scanning address "
       "{}",
       resolved_scanning_address);

  // Generate the SCAN_RSP packet.
  // Note: If the advertiser processes the scan request, the advertiser’s
  // device address (AdvA field) in the SCAN_RSP PDU shall be the same as
  // the advertiser’s device address (AdvA field) in the SCAN_REQ PDU to
  // which it is responding.
  SendLeLinkLayerPacket(
      model::packets::LeScanResponseBuilder::Create(
          advertising_address.GetAddress(), scanning_address.GetAddress(),
          static_cast<model::packets::AddressType>(
              advertising_address.GetAddressType()),
          legacy_advertiser_.scan_response_data),
      properties_.le_advertising_physical_channel_tx_power);
}

void LinkLayerController::ProcessIncomingExtendedScanRequest(
    ExtendedAdvertiser const& advertiser, AddressWithType scanning_address,
    AddressWithType resolved_scanning_address,
    AddressWithType advertising_address) {
  // Check if the advertising addresses matches the legacy
  // advertising address.
  if (!advertiser.IsEnabled()) {
    return;
  }
  if (!advertiser.IsScannable()) {
    DEBUG(id_,
          "LE Scan request ignored by extended advertiser {} because it is not "
          "scannable",
          advertiser.advertising_handle);
    return;
  }

  if (advertising_address != advertiser.advertising_address) {
    DEBUG(id_,
          "LE Scan request ignored by extended advertiser {} because the "
          "advertising address {} does not match {}",
          advertiser.advertising_handle, advertising_address,
          advertiser.GetAdvertisingAddress());
    return;
  }

  // Check if scanner address is in the filter accept list
  // for this advertiser.
  switch (advertiser.advertising_filter_policy) {
    case bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES:
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_CONNECT:
      break;
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN:
    case bluetooth::hci::AdvertisingFilterPolicy::LISTED_SCAN_AND_CONNECT:
      if (!LeFilterAcceptListContainsDevice(resolved_scanning_address)) {
        DEBUG(id_,
              "LE Scan request ignored by extended advertiser {} because the "
              "scanning address {} is not in the filter accept list",
              advertiser.advertising_handle, resolved_scanning_address);
        return;
      }
      break;
  }

  // Check if the scanner address is the target address in the case of
  // scannable directed event types.
  if (advertiser.IsDirected() &&
      advertiser.target_address != resolved_scanning_address) {
    DEBUG(id_,
          "LE Scan request ignored by extended advertiser {} because the "
          "scanning address {} does not match the target address {}",
          advertiser.advertising_handle, resolved_scanning_address,
          advertiser.GetTargetAddress());
    return;
  }

  INFO(id_,
       "Accepting LE Scan request to extended advertiser {} from scanning "
       "address {}",
       advertiser.advertising_handle, resolved_scanning_address);

  // Generate the SCAN_RSP packet.
  // Note: If the advertiser processes the scan request, the advertiser’s
  // device address (AdvA field) in the SCAN_RSP PDU shall be the same as
  // the advertiser’s device address (AdvA field) in the SCAN_REQ PDU to
  // which it is responding.
  SendLeLinkLayerPacket(
      model::packets::LeScanResponseBuilder::Create(
          advertising_address.GetAddress(), scanning_address.GetAddress(),
          static_cast<model::packets::AddressType>(
              advertising_address.GetAddressType()),
          advertiser.scan_response_data),
      advertiser.advertising_tx_power);
}

void LinkLayerController::IncomingLeScanPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto scan_request = model::packets::LeScanView::Create(incoming);
  ASSERT(scan_request.IsValid());

  AddressWithType scanning_address{
      scan_request.GetSourceAddress(),
      static_cast<AddressType>(scan_request.GetScanningAddressType())};

  AddressWithType advertising_address{
      scan_request.GetDestinationAddress(),
      static_cast<AddressType>(scan_request.GetAdvertisingAddressType())};

  // Note: Vol 6, Part B § 6.2 Privacy in the Advertising State.
  //
  // When an advertiser receives a scan request that contains a resolvable
  // private address for the scanner’s device address (ScanA field) and
  // address resolution is enabled, the Link Layer shall resolve the private
  // address. The advertising filter policy shall then determine if
  // the advertiser processes the scan request.
  AddressWithType resolved_scanning_address =
      ResolvePrivateAddress(scanning_address).value_or(scanning_address);

  if (resolved_scanning_address != scanning_address) {
    DEBUG(id_, "Resolved the scanning address {} to {}", scanning_address,
          resolved_scanning_address);
  }

  ProcessIncomingLegacyScanRequest(scanning_address, resolved_scanning_address,
                                   advertising_address);
  for (auto& [_, advertiser] : extended_advertisers_) {
    ProcessIncomingExtendedScanRequest(advertiser, scanning_address,
                                       resolved_scanning_address,
                                       advertising_address);
  }
}

void LinkLayerController::IncomingLeScanResponsePacket(
    model::packets::LinkLayerPacketView incoming, uint8_t rssi) {
  auto scan_response = model::packets::LeScanResponseView::Create(incoming);
  ASSERT(scan_response.IsValid());

  if (!scanner_.IsEnabled()) {
    return;
  }

  if (!scanner_.pending_scan_request) {
    DEBUG(id_,
          "LE Scan response ignored by scanner because no request is currently "
          "pending");
    return;
  }

  AddressWithType advertising_address{
      scan_response.GetSourceAddress(),
      static_cast<AddressType>(scan_response.GetAdvertisingAddressType())};

  // If the advertiser processes the scan request, the advertiser’s device
  // address (AdvA field) in the scan response PDU shall be the same as the
  // advertiser’s device address (AdvA field) in the scan request PDU to which
  // it is responding.
  if (advertising_address != scanner_.pending_scan_request) {
    DEBUG(id_,
          "LE Scan response ignored by scanner because the advertising address "
          "{} does not match the pending request {}",
          advertising_address, scanner_.pending_scan_request.value());
    return;
  }

  AddressWithType resolved_advertising_address =
      ResolvePrivateAddress(advertising_address).value_or(advertising_address);

  if (advertising_address != resolved_advertising_address) {
    DEBUG(id_, "Resolved the advertising address {} to {}", advertising_address,
          resolved_advertising_address);
  }

  INFO(id_, "Accepting LE Scan response from advertising address {}",
       resolved_advertising_address);

  scanner_.pending_scan_request = {};

  bool should_send_advertising_report = true;
  if (scanner_.filter_duplicates !=
      bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(incoming.bytes())) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(incoming.bytes());
    }
  }

  if (LegacyAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::ADVERTISING_REPORT)) {
    bluetooth::hci::LeAdvertisingResponse response;
    response.event_type_ = bluetooth::hci::AdvertisingEventType::SCAN_RESPONSE;
    response.address_ = resolved_advertising_address.GetAddress();
    response.address_type_ = resolved_advertising_address.GetAddressType();
    response.advertising_data_ = scan_response.GetScanResponseData();
    response.rssi_ = rssi;
    send_event_(bluetooth::hci::LeAdvertisingReportBuilder::Create({response}));
  }

  if (ExtendedAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponse response;
    response.address_ = resolved_advertising_address.GetAddress();
    response.address_type_ =
        static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
            resolved_advertising_address.GetAddressType());
    response.connectable_ = scanner_.connectable_scan_response;
    response.scannable_ = true;
    response.legacy_ = !scanner_.extended_scan_response;
    response.scan_response_ = true;
    response.primary_phy_ = bluetooth::hci::PrimaryPhyType::LE_1M;
    // TODO: SID should be set in scan response PDU
    response.advertising_sid_ = 0xFF;
    response.tx_power_ = 0x7F;
    response.rssi_ = rssi;
    response.direct_address_type_ =
        bluetooth::hci::DirectAdvertisingAddressType::NO_ADDRESS_PROVIDED;

    // Each extended advertising report can only pass 229 bytes of
    // advertising data (255 - size of report fields).
    // RootCanal must fragment the report as necessary.
    const size_t max_fragment_size = 229;
    size_t offset = 0;
    std::vector<uint8_t> advertising_data = scan_response.GetScanResponseData();

    do {
      size_t remaining_size = advertising_data.size() - offset;
      size_t fragment_size = std::min(max_fragment_size, remaining_size);
      response.data_status_ = remaining_size <= max_fragment_size
                                  ? bluetooth::hci::DataStatus::COMPLETE
                                  : bluetooth::hci::DataStatus::CONTINUING;
      response.advertising_data_ =
          std::vector(advertising_data.begin() + offset,
                      advertising_data.begin() + offset + fragment_size);
      offset += fragment_size;
      send_event_(bluetooth::hci::LeExtendedAdvertisingReportBuilder::Create(
          {response}));
    } while (offset < advertising_data.size());
  }
}

void LinkLayerController::LeScanning() {
  if (!scanner_.IsEnabled()) {
    return;
  }

  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

  // Extended Scanning Timeout

  // Generate HCI Connection Complete or Enhanced HCI Connection Complete
  // events with Advertising Timeout error code when the advertising
  // type is ADV_DIRECT_IND and the connection failed to be established.

  if (scanner_.timeout.has_value() &&
      !scanner_.periodical_timeout.has_value() &&
      now >= scanner_.timeout.value()) {
    // At the end of a single scan (Duration non-zero but Period zero),
    // an HCI_LE_Scan_Timeout event shall be generated.
    INFO(id_, "Extended Scan Timeout");
    scanner_.scan_enable = false;
    scanner_.pending_scan_request = {};
    scanner_.history.clear();
    if (IsLeEventUnmasked(SubeventCode::SCAN_TIMEOUT)) {
      send_event_(bluetooth::hci::LeScanTimeoutBuilder::Create());
    }
  }

  // End of duration with scan enabled
  if (scanner_.timeout.has_value() && scanner_.periodical_timeout.has_value() &&
      now >= scanner_.timeout.value()) {
    scanner_.timeout = {};
  }

  // End of period
  if (!scanner_.timeout.has_value() &&
      scanner_.periodical_timeout.has_value() &&
      now >= scanner_.periodical_timeout.value()) {
    if (scanner_.filter_duplicates == FilterDuplicates::RESET_EACH_PERIOD) {
      scanner_.history.clear();
    }
    scanner_.timeout = now + scanner_.duration;
    scanner_.periodical_timeout = now + scanner_.period;
  }

  // Pending scan timeout.
  // Cancel the pending scan request. This may condition may be triggered
  // when the advertiser is stopped before sending the scan request.
  if (scanner_.pending_scan_request_timeout.has_value() &&
      now >= scanner_.pending_scan_request_timeout.value()) {
    scanner_.pending_scan_request = {};
    scanner_.pending_scan_request_timeout = {};
  }
}

void LinkLayerController::LeSynchronization() {
  std::vector<uint16_t> removed_sync_handles;
  for (auto& [_, sync] : synchronized_) {
    if (sync.timeout > std::chrono::steady_clock::now()) {
      INFO(id_, "Periodic advertising sync with handle 0x{:x} lost",
           sync.sync_handle);
      removed_sync_handles.push_back(sync.sync_handle);
    }
    if (IsLeEventUnmasked(SubeventCode::PERIODIC_ADVERTISING_SYNC_LOST)) {
      send_event_(bluetooth::hci::LePeriodicAdvertisingSyncLostBuilder::Create(
          sync.sync_handle));
    }
  }

  for (auto sync_handle : removed_sync_handles) {
    synchronized_.erase(sync_handle);
  }
}

void LinkLayerController::IncomingPagePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto bd_addr = incoming.GetSourceAddress();
  auto page = model::packets::PageView::Create(incoming);
  ASSERT(page.IsValid());

  // [HCI] 7.3.3 Set Event Filter command
  // If the Auto_Accept_Flag is off and the Host has masked the
  // HCI_Connection_Request event, the Controller shall reject the
  // connection attempt.
  if (!IsEventUnmasked(EventCode::CONNECTION_REQUEST)) {
    INFO(id_,
         "rejecting connection request from {} because the HCI_Connection_Request"
         " event is masked by the Host", bd_addr);
    SendLinkLayerPacket(
        model::packets::PageRejectBuilder::Create(
            GetAddress(), bd_addr, static_cast<uint8_t>(ErrorCode::CONNECTION_TIMEOUT)));
    return;
  }

  // Cannot establish two BR-EDR connections with the same peer.
  if (connections_.GetAclConnectionHandle(bd_addr).has_value()) {
    return;
  }

  bool allow_role_switch = page.GetAllowRoleSwitch();
  if (!connections_.CreatePendingConnection(
          bd_addr, authentication_enable_ == AuthenticationEnable::REQUIRED,
          allow_role_switch)) {
    // Will be triggered when multiple hosts are paging simultaneously;
    // only one connection will be accepted.
    WARNING(id_, "Failed to create a pending connection for {}", bd_addr);
    return;
  }

  send_event_(bluetooth::hci::ConnectionRequestBuilder::Create(
      bd_addr, page.GetClassOfDevice(),
      bluetooth::hci::ConnectionRequestLinkType::ACL));
}

void LinkLayerController::IncomingPageRejectPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto bd_addr = incoming.GetSourceAddress();
  auto reject = model::packets::PageRejectView::Create(incoming);
  ASSERT(reject.IsValid());

  if (!page_.has_value() || page_->bd_addr != bd_addr) {
    INFO(id_,
         "ignoring Page Reject packet received when not in Page state,"
         " or paging to a different address");
    return;
  }

  INFO(id_, "Received Page Reject packet from {}", bd_addr);
  page_ = {};

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        static_cast<ErrorCode>(reject.GetReason()), 0, bd_addr,
        bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));
  }
}

void LinkLayerController::IncomingPageResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto bd_addr = incoming.GetSourceAddress();
  auto response = model::packets::PageResponseView::Create(incoming);
  ASSERT(response.IsValid());

  if (!page_.has_value() || page_->bd_addr != bd_addr) {
    INFO(id_,
         "ignoring Page Response packet received when not in Page state,"
         " or paging to a different address");
    return;
  }

  INFO(id_, "Received Page Response packet from {}", bd_addr);

  uint16_t connection_handle =
      connections_.CreateConnection(bd_addr, GetAddress(), false);
  ASSERT(connection_handle != kReservedHandle);

  bluetooth::hci::Role role =
      page_->allow_role_switch && response.GetTryRoleSwitch()
          ? bluetooth::hci::Role::PERIPHERAL
          : bluetooth::hci::Role::CENTRAL;

  AclConnection& connection = connections_.GetAclConnection(connection_handle);
  CheckExpiringConnection(connection_handle);
  connection.SetLinkPolicySettings(default_link_policy_settings_);
  connection.SetRole(role);
  page_ = {};

  ASSERT(link_manager_add_link(
      lm_.get(), reinterpret_cast<const uint8_t(*)[6]>(bd_addr.data())));

  // Role change event before connection complete generates an HCI Role Change
  // event on the initiator side if accepted; the event is sent before the
  // HCI Connection Complete event.
  if (role == bluetooth::hci::Role::PERIPHERAL &&
      IsEventUnmasked(EventCode::ROLE_CHANGE)) {
    send_event_(bluetooth::hci::RoleChangeBuilder::Create(ErrorCode::SUCCESS,
                                                          bd_addr, role));
  }

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        ErrorCode::SUCCESS, connection_handle, bd_addr,
        bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));
  }
}

void LinkLayerController::Tick() {
  RunPendingTasks();
  Paging();

  if (inquiry_timer_task_id_ != kInvalidTaskId) {
    Inquiry();
  }
  LeAdvertising();
  LeScanning();
  link_manager_tick(lm_.get());
}

void LinkLayerController::Close() {
  for (auto handle : connections_.GetAclHandles()) {
    Disconnect(handle, ErrorCode::REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF,
               ErrorCode::REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF);
  }
}

void LinkLayerController::RegisterEventChannel(
    const std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>&
        send_event) {
  send_event_ = send_event;
}

void LinkLayerController::RegisterAclChannel(
    const std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)>&
        send_acl) {
  send_acl_ = send_acl;
}

void LinkLayerController::RegisterScoChannel(
    const std::function<void(std::shared_ptr<bluetooth::hci::ScoBuilder>)>&
        send_sco) {
  send_sco_ = send_sco;
}

void LinkLayerController::RegisterIsoChannel(
    const std::function<void(std::shared_ptr<bluetooth::hci::IsoBuilder>)>&
        send_iso) {
  send_iso_ = send_iso;
}

void LinkLayerController::RegisterRemoteChannel(
    const std::function<
        void(std::shared_ptr<model::packets::LinkLayerPacketBuilder>, Phy::Type,
             int8_t)>& send_to_remote) {
  send_to_remote_ = send_to_remote;
}

void LinkLayerController::ForwardToLm(bluetooth::hci::CommandView command) {
  auto packet = command.bytes().bytes();
  ASSERT(link_manager_ingest_hci(lm_.get(), packet.data(), packet.size()));
}

void LinkLayerController::ForwardToLl(bluetooth::hci::CommandView command) {
  auto packet = command.bytes().bytes();
  ASSERT(link_layer_ingest_hci(ll_.get(), packet.data(), packet.size()));
}

std::vector<bluetooth::hci::Lap> const& LinkLayerController::ReadCurrentIacLap()
    const {
  return current_iac_lap_list_;
}

void LinkLayerController::WriteCurrentIacLap(
    std::vector<bluetooth::hci::Lap> iac_lap) {
  current_iac_lap_list_.swap(iac_lap);

  //  If Num_Current_IAC is greater than Num_Supported_IAC then only the first
  //  Num_Supported_IAC shall be stored in the Controller
  if (current_iac_lap_list_.size() > properties_.num_supported_iac) {
    current_iac_lap_list_.resize(properties_.num_supported_iac);
  }
}

ErrorCode LinkLayerController::AcceptConnectionRequest(const Address& bd_addr,
                                                       bool try_role_switch) {
  if (connections_.HasPendingConnection(bd_addr)) {
    INFO(id_, "Accepting connection request from {}", bd_addr);
    ScheduleTask(kNoDelayMs, [this, bd_addr, try_role_switch]() {
      INFO(id_, "Accepted connection from {}", bd_addr);
      MakePeripheralConnection(bd_addr, try_role_switch);
    });

    return ErrorCode::SUCCESS;
  }

  // The HCI command Accept Connection may be used to accept incoming SCO
  // connection requests.
  if (connections_.HasPendingScoConnection(bd_addr)) {
    ErrorCode status = ErrorCode::SUCCESS;
    uint16_t sco_handle = 0;
    ScoLinkParameters link_parameters = {};
    ScoConnectionParameters connection_parameters =
        connections_.GetScoConnectionParameters(bd_addr);

    if (!connections_.AcceptPendingScoConnection(
            bd_addr, connection_parameters, [this, bd_addr] {
              return LinkLayerController::StartScoStream(bd_addr);
            })) {
      connections_.CancelPendingScoConnection(bd_addr);
      status = ErrorCode::SCO_INTERVAL_REJECTED;  // TODO: proper status code
    } else {
      sco_handle = connections_.GetScoHandle(bd_addr);
      link_parameters = connections_.GetScoLinkParameters(bd_addr);
    }

    // Send eSCO connection response to peer.
    SendLinkLayerPacket(model::packets::ScoConnectionResponseBuilder::Create(
        GetAddress(), bd_addr, (uint8_t)status,
        link_parameters.transmission_interval,
        link_parameters.retransmission_window, link_parameters.rx_packet_length,
        link_parameters.tx_packet_length, link_parameters.air_mode,
        link_parameters.extended));

    // Schedule HCI Connection Complete event.
    if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
      ScheduleTask(kNoDelayMs, [this, status, sco_handle, bd_addr]() {
        send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
            ErrorCode(status), sco_handle, bd_addr,
            bluetooth::hci::LinkType::SCO, bluetooth::hci::Enable::DISABLED));
      });
    }

    return ErrorCode::SUCCESS;
  }

  INFO(id_, "No pending connection for {}", bd_addr);
  return ErrorCode::UNKNOWN_CONNECTION;
}

void LinkLayerController::MakePeripheralConnection(const Address& bd_addr,
                                                   bool try_role_switch) {
  uint16_t connection_handle =
      connections_.CreateConnection(bd_addr, GetAddress());
  if (connection_handle == kReservedHandle) {
    INFO(id_, "CreateConnection failed");
    return;
  }

  bluetooth::hci::Role role =
      try_role_switch && connections_.IsRoleSwitchAllowedForPendingConnection()
          ? bluetooth::hci::Role::CENTRAL
          : bluetooth::hci::Role::PERIPHERAL;

  AclConnection& connection = connections_.GetAclConnection(connection_handle);
  CheckExpiringConnection(connection_handle);
  connection.SetLinkPolicySettings(default_link_policy_settings_);
  connection.SetRole(role);

  ASSERT(link_manager_add_link(
      lm_.get(), reinterpret_cast<const uint8_t(*)[6]>(bd_addr.data())));

  // Role change event before connection complete generates an HCI Role Change
  // event on the acceptor side if accepted; the event is sent before the
  // HCI Connection Complete event.
  if (role == bluetooth::hci::Role::CENTRAL &&
      IsEventUnmasked(EventCode::ROLE_CHANGE)) {
    INFO(id_, "Role at connection setup accepted");
    send_event_(bluetooth::hci::RoleChangeBuilder::Create(ErrorCode::SUCCESS,
                                                          bd_addr, role));
  }

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        ErrorCode::SUCCESS, connection_handle, bd_addr,
        bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));
  }

  // If the current Host was initiating a connection to the same bd_addr,
  // send a connection complete event for the pending Create Connection
  // command and cancel the paging.
  if (page_.has_value() && page_->bd_addr == bd_addr) {
    // TODO: the core specification is very unclear as to what behavior
    // is expected when two connections are established simultaneously.
    // This implementation considers that a unique HCI Connection Complete
    // event is expected for both the HCI Create Connection and HCI Accept
    // Connection Request commands.
    page_ = {};
  }

  INFO(id_, "Sending page response to {}", bd_addr.ToString());
  SendLinkLayerPacket(model::packets::PageResponseBuilder::Create(
      GetAddress(), bd_addr, try_role_switch));
}

ErrorCode LinkLayerController::RejectConnectionRequest(const Address& addr,
                                                       uint8_t reason) {
  if (!connections_.HasPendingConnection(addr)) {
    INFO(id_, "No pending connection for {}", addr);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(kNoDelayMs, [this, addr, reason]() {
    RejectPeripheralConnection(addr, reason);
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::RejectPeripheralConnection(const Address& addr,
                                                     uint8_t reason) {
  INFO(id_, "Sending page reject to {} (reason 0x{:02x})", addr, reason);
  SendLinkLayerPacket(
      model::packets::PageRejectBuilder::Create(GetAddress(), addr, reason));

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        static_cast<ErrorCode>(reason), 0xeff, addr,
        bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));
  }
}

ErrorCode LinkLayerController::CreateConnection(const Address& bd_addr,
                                                uint16_t /* packet_type */,
                                                uint8_t /* page_scan_mode */,
                                                uint16_t /* clock_offset */,
                                                uint8_t allow_role_switch) {
  // RootCanal only accepts one pending outgoing connection at any time.
  if (page_.has_value()) {
    INFO(id_, "Create Connection command is already pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // Reject the command if a connection or pending connection already exists
  // for the selected peer address.
  if (connections_.HasPendingConnection(bd_addr) ||
      connections_.GetAclConnectionHandle(bd_addr).has_value()) {
    INFO(id_, "Connection with {} already exists", bd_addr.ToString());
    return ErrorCode::CONNECTION_ALREADY_EXISTS;
  }

  auto now = std::chrono::steady_clock::now();
  page_ = Page{
      .bd_addr = bd_addr,
      .allow_role_switch = allow_role_switch,
      .next_page_event = now + kPageInterval,
      .page_timeout = now + slots(page_timeout_),
  };

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::CreateConnectionCancel(const Address& bd_addr) {
  // If the HCI_Create_Connection_Cancel command is sent to the Controller
  // without a preceding HCI_Create_Connection command to the same device,
  // the BR/EDR Controller shall return an HCI_Command_Complete event with
  // the error code Unknown Connection Identifier (0x02)
  if (!page_.has_value() || page_->bd_addr != bd_addr) {
    INFO(id_, "no pending connection to {}", bd_addr.ToString());
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // The HCI_Connection_Complete event for the corresponding HCI_Create_-
  // Connection command shall always be sent. The HCI_Connection_Complete
  // event shall be sent after the HCI_Command_Complete event for the
  // HCI_Create_Connection_Cancel command. If the cancellation was successful,
  // the HCI_Connection_Complete event will be generated with the error code
  // Unknown Connection Identifier (0x02).
  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    ScheduleTask(kNoDelayMs, [this, bd_addr]() {
      send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
          ErrorCode::UNKNOWN_CONNECTION, 0, bd_addr,
          bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));
    });
  }

  page_ = {};
  return ErrorCode::SUCCESS;
}

void LinkLayerController::SendDisconnectionCompleteEvent(uint16_t handle,
                                                         ErrorCode reason) {
  if (IsEventUnmasked(EventCode::DISCONNECTION_COMPLETE)) {
    ScheduleTask(kNoDelayMs, [this, handle, reason]() {
      send_event_(bluetooth::hci::DisconnectionCompleteBuilder::Create(
          ErrorCode::SUCCESS, handle, reason));
    });
  }
}

ErrorCode LinkLayerController::Disconnect(uint16_t handle,
                                          ErrorCode host_reason,
                                          ErrorCode controller_reason) {
  if (connections_.HasScoHandle(handle)) {
    const Address remote = connections_.GetScoAddress(handle);
    INFO(id_, "Disconnecting eSCO connection with {}", remote);

    SendLinkLayerPacket(model::packets::ScoDisconnectBuilder::Create(
        GetAddress(), remote, static_cast<uint8_t>(host_reason)));

    connections_.Disconnect(
        handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
    SendDisconnectionCompleteEvent(handle, controller_reason);
    return ErrorCode::SUCCESS;
  }

  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  const AddressWithType remote = connections_.GetAddress(handle);
  auto is_br_edr = connections_.GetPhyType(handle) == Phy::Type::BR_EDR;

  if (is_br_edr) {
    INFO(id_, "Disconnecting ACL connection with {}", remote);

    uint16_t sco_handle = connections_.GetScoHandle(remote.GetAddress());
    if (sco_handle != kReservedHandle) {
      SendLinkLayerPacket(model::packets::ScoDisconnectBuilder::Create(
          GetAddress(), remote.GetAddress(),
          static_cast<uint8_t>(host_reason)));

      connections_.Disconnect(
          sco_handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
      SendDisconnectionCompleteEvent(sco_handle, controller_reason);
    }

    SendLinkLayerPacket(model::packets::DisconnectBuilder::Create(
        GetAddress(), remote.GetAddress(), static_cast<uint8_t>(host_reason)));
  } else {
    INFO(id_, "Disconnecting LE connection with {}", remote);

    SendLeLinkLayerPacket(model::packets::DisconnectBuilder::Create(
        connections_.GetOwnAddress(handle).GetAddress(), remote.GetAddress(),
        static_cast<uint8_t>(host_reason)));
  }

  connections_.Disconnect(
      handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
  SendDisconnectionCompleteEvent(handle, controller_reason);
  if (is_br_edr) {
    ASSERT(link_manager_remove_link(
        lm_.get(),
        reinterpret_cast<uint8_t(*)[6]>(remote.GetAddress().data())));
  } else {
    ASSERT(link_layer_remove_link(ll_.get(), handle));
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::ChangeConnectionPacketType(uint16_t handle,
                                                          uint16_t types) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(kNoDelayMs, [this, handle, types]() {
    if (IsEventUnmasked(EventCode::CONNECTION_PACKET_TYPE_CHANGED)) {
      send_event_(bluetooth::hci::ConnectionPacketTypeChangedBuilder::Create(
          ErrorCode::SUCCESS, handle, types));
    }
  });

  return ErrorCode::SUCCESS;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ErrorCode LinkLayerController::ChangeConnectionLinkKey(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ErrorCode LinkLayerController::CentralLinkKey(uint8_t /* key_flag */) {
  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::HoldMode(uint16_t handle,
                                        uint16_t hold_mode_max_interval,
                                        uint16_t hold_mode_min_interval) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (hold_mode_max_interval < hold_mode_min_interval) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::SniffMode(uint16_t handle,
                                         uint16_t sniff_max_interval,
                                         uint16_t sniff_min_interval,
                                         uint16_t sniff_attempt,
                                         uint16_t sniff_timeout) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (sniff_max_interval < sniff_min_interval || sniff_attempt < 0x0001 ||
      sniff_attempt > 0x7FFF || sniff_timeout > 0x7FFF) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::ExitSniffMode(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::QosSetup(uint16_t handle, uint8_t service_type,
                                        uint32_t /* token_rate */,
                                        uint32_t /* peak_bandwidth */,
                                        uint32_t /* latency */,
                                        uint32_t /* delay_variation */) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (service_type > 0x02) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::RoleDiscovery(uint16_t handle,
                                             bluetooth::hci::Role* role) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  *role = connections_.GetAclRole(handle);
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SwitchRole(Address bd_addr,
                                          bluetooth::hci::Role role) {
  // The BD_ADDR command parameter indicates for which connection
  // the role switch is to be performed and shall specify a BR/EDR Controller
  // for which a connection already exists.
  uint16_t connection_handle = connections_.GetHandleOnlyAddress(bd_addr);
  if (connection_handle == kReservedHandle) {
    INFO(id_, "unknown connection address {}", bd_addr);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  AclConnection& connection = connections_.GetAclConnection(connection_handle);

  // If there is an (e)SCO connection between the local device and the device
  // identified by the BD_ADDR parameter, an attempt to perform a role switch
  // shall be rejected by the local device.
  if (connections_.GetScoHandle(bd_addr) != kReservedHandle) {
    INFO(id_,
         "role switch rejected because an Sco link is opened with"
         " the target device");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the connection between the local device and the device identified by the
  // BD_ADDR parameter is placed in Sniff mode, an attempt to perform a role
  // switch shall be rejected by the local device.
  if (connection.GetMode() == AclConnectionState::kSniffMode) {
    INFO(id_,
         "role switch rejected because the acl connection is in sniff mode");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (role != connection.GetRole()) {
    SendLinkLayerPacket(model::packets::RoleSwitchRequestBuilder::Create(
        GetAddress(), bd_addr));
  } else if (IsEventUnmasked(EventCode::ROLE_CHANGE)) {
    // Note: the status is Success only if the role change procedure was
    // actually performed, otherwise the status is >0.
    ScheduleTask(kNoDelayMs, [this, bd_addr, role]() {
      send_event_(bluetooth::hci::RoleChangeBuilder::Create(
          ErrorCode::ROLE_SWITCH_FAILED, bd_addr, role));
    });
  }

  return ErrorCode::SUCCESS;
}

void LinkLayerController::IncomingRoleSwitchRequest(
    model::packets::LinkLayerPacketView incoming) {
  auto bd_addr = incoming.GetSourceAddress();
  auto connection_handle = connections_.GetHandleOnlyAddress(bd_addr);
  auto switch_req = model::packets::RoleSwitchRequestView::Create(incoming);
  ASSERT(switch_req.IsValid());

  if (connection_handle == kReservedHandle) {
    INFO(id_, "ignoring Switch Request received on unknown connection");
    return;
  }

  AclConnection& connection = connections_.GetAclConnection(connection_handle);

  if (!connection.IsRoleSwitchEnabled()) {
    INFO(id_, "role switch disabled by local link policy settings");
    SendLinkLayerPacket(model::packets::RoleSwitchResponseBuilder::Create(
        GetAddress(), bd_addr,
        static_cast<uint8_t>(ErrorCode::ROLE_CHANGE_NOT_ALLOWED)));
  } else {
    INFO(id_, "role switch request accepted by local device");
    SendLinkLayerPacket(model::packets::RoleSwitchResponseBuilder::Create(
        GetAddress(), bd_addr, static_cast<uint8_t>(ErrorCode::SUCCESS)));

    bluetooth::hci::Role new_role =
        connection.GetRole() == bluetooth::hci::Role::CENTRAL
            ? bluetooth::hci::Role::PERIPHERAL
            : bluetooth::hci::Role::CENTRAL;

    connection.SetRole(new_role);

    if (IsEventUnmasked(EventCode::ROLE_CHANGE)) {
      ScheduleTask(kNoDelayMs, [this, bd_addr, new_role]() {
        send_event_(bluetooth::hci::RoleChangeBuilder::Create(
            ErrorCode::SUCCESS, bd_addr, new_role));
      });
    }
  }
}

void LinkLayerController::IncomingRoleSwitchResponse(
    model::packets::LinkLayerPacketView incoming) {
  auto bd_addr = incoming.GetSourceAddress();
  auto connection_handle = connections_.GetHandleOnlyAddress(bd_addr);
  auto switch_rsp = model::packets::RoleSwitchResponseView::Create(incoming);
  ASSERT(switch_rsp.IsValid());

  if (connection_handle == kReservedHandle) {
    INFO(id_, "ignoring Switch Response received on unknown connection");
    return;
  }

  AclConnection& connection = connections_.GetAclConnection(connection_handle);
  ErrorCode status = ErrorCode(switch_rsp.GetStatus());
  bluetooth::hci::Role new_role =
      status != ErrorCode::SUCCESS ? connection.GetRole()
      : connection.GetRole() == bluetooth::hci::Role::CENTRAL
          ? bluetooth::hci::Role::PERIPHERAL
          : bluetooth::hci::Role::CENTRAL;

  connection.SetRole(new_role);

  if (IsEventUnmasked(EventCode::ROLE_CHANGE)) {
    ScheduleTask(kNoDelayMs, [this, status, bd_addr, new_role]() {
      send_event_(
          bluetooth::hci::RoleChangeBuilder::Create(status, bd_addr, new_role));
    });
  }
}

ErrorCode LinkLayerController::ReadLinkPolicySettings(uint16_t handle,
                                                      uint16_t* settings) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  *settings = connections_.GetAclLinkPolicySettings(handle);
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::WriteLinkPolicySettings(uint16_t handle,
                                                       uint16_t settings) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  if (settings > 7 /* Sniff + Hold + Role switch */) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  connections_.SetAclLinkPolicySettings(handle, settings);
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::WriteDefaultLinkPolicySettings(
    uint16_t settings) {
  if (settings > 7 /* Sniff + Hold + Role switch */) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  default_link_policy_settings_ = settings;
  return ErrorCode::SUCCESS;
}

uint16_t LinkLayerController::ReadDefaultLinkPolicySettings() const {
  return default_link_policy_settings_;
}

void LinkLayerController::ReadLocalOobData() {
  std::array<uint8_t, 16> c_array(
      {'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '0', '0', '0', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  std::array<uint8_t, 16> r_array(
      {'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '0', '0', '0', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  send_event_(bluetooth::hci::ReadLocalOobDataCompleteBuilder::Create(
      1, ErrorCode::SUCCESS, c_array, r_array));
  oob_id_ += 1;
}

void LinkLayerController::ReadLocalOobExtendedData() {
  std::array<uint8_t, 16> c_192_array(
      {'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '1', '9', '2', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  std::array<uint8_t, 16> r_192_array(
      {'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '1', '9', '2', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  std::array<uint8_t, 16> c_256_array(
      {'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '2', '5', '6', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  std::array<uint8_t, 16> r_256_array(
      {'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '2', '5', '6', '0', '0', '0',
       static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
       static_cast<uint8_t>(oob_id_ % 0x100)});

  send_event_(bluetooth::hci::ReadLocalOobExtendedDataCompleteBuilder::Create(
      1, ErrorCode::SUCCESS, c_192_array, r_192_array, c_256_array,
      r_256_array));
  oob_id_ += 1;
}

ErrorCode LinkLayerController::FlowSpecification(
    uint16_t handle, uint8_t flow_direction, uint8_t service_type,
    uint32_t /* token_rate */, uint32_t /* token_bucket_size */,
    uint32_t /* peak_bandwidth */, uint32_t /* access_latency */) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (flow_direction > 0x01 || service_type > 0x02) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

ErrorCode LinkLayerController::WriteLinkSupervisionTimeout(
    uint16_t handle, uint16_t /* timeout */) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

void LinkLayerController::LeConnectionUpdateComplete(
    uint16_t handle, uint16_t interval_min, uint16_t interval_max,
    uint16_t latency, uint16_t supervision_timeout) {
  ErrorCode status = ErrorCode::SUCCESS;
  if (!connections_.HasHandle(handle)) {
    status = ErrorCode::UNKNOWN_CONNECTION;
  }

  if (interval_min < 6 || interval_max > 0xC80 || interval_min > interval_max ||
      interval_max < interval_min || latency > 0x1F3 ||
      supervision_timeout < 0xA || supervision_timeout > 0xC80 ||
      // The Supervision_Timeout in milliseconds (*10) shall be larger than (1 +
      // Connection_Latency) * Connection_Interval_Max (* 5/4) * 2
      supervision_timeout <= ((((1 + latency) * interval_max * 10) / 4) / 10)) {
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  uint16_t interval = (interval_min + interval_max) / 2;

  SendLeLinkLayerPacket(LeConnectionParameterUpdateBuilder::Create(
      connections_.GetOwnAddress(handle).GetAddress(),
      connections_.GetAddress(handle).GetAddress(),
      static_cast<uint8_t>(ErrorCode::SUCCESS), interval, latency,
      supervision_timeout));

  if (IsLeEventUnmasked(SubeventCode::CONNECTION_UPDATE_COMPLETE)) {
    send_event_(bluetooth::hci::LeConnectionUpdateCompleteBuilder::Create(
        status, handle, interval, latency, supervision_timeout));
  }
}

ErrorCode LinkLayerController::LeConnectionUpdate(
    uint16_t handle, uint16_t interval_min, uint16_t interval_max,
    uint16_t latency, uint16_t supervision_timeout) {
  if (!connections_.HasHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  bluetooth::hci::Role role = connections_.GetAclRole(handle);

  if (role == bluetooth::hci::Role::CENTRAL) {
    // As Central, it is allowed to directly send
    // LL_CONNECTION_PARAM_UPDATE_IND to update the parameters.
    SendLeLinkLayerPacket(LeConnectionParameterUpdateBuilder::Create(
        connections_.GetOwnAddress(handle).GetAddress(),
        connections_.GetAddress(handle).GetAddress(),
        static_cast<uint8_t>(ErrorCode::SUCCESS), interval_max, latency,
        supervision_timeout));

    if (IsLeEventUnmasked(SubeventCode::CONNECTION_UPDATE_COMPLETE)) {
      send_event_(bluetooth::hci::LeConnectionUpdateCompleteBuilder::Create(
          ErrorCode::SUCCESS, handle, interval_max, latency,
          supervision_timeout));
    }
  } else {
    // Send LL_CONNECTION_PARAM_REQ and wait for LL_CONNECTION_PARAM_RSP
    // in return.
    SendLeLinkLayerPacket(LeConnectionParameterRequestBuilder::Create(
        connections_.GetOwnAddress(handle).GetAddress(),
        connections_.GetAddress(handle).GetAddress(), interval_min,
        interval_max, latency, supervision_timeout));
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeRemoteConnectionParameterRequestReply(
    uint16_t connection_handle, uint16_t interval_min, uint16_t interval_max,
    uint16_t timeout, uint16_t latency, uint16_t minimum_ce_length,
    uint16_t maximum_ce_length) {
  if (!connections_.HasHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if ((interval_min > interval_max) ||
      (minimum_ce_length > maximum_ce_length)) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  ScheduleTask(kNoDelayMs, [this, connection_handle, interval_min, interval_max,
                            latency, timeout]() {
    LeConnectionUpdateComplete(connection_handle, interval_min, interval_max,
                               latency, timeout);
  });
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeRemoteConnectionParameterRequestNegativeReply(
    uint16_t connection_handle, bluetooth::hci::ErrorCode reason) {
  if (!connections_.HasHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  uint16_t interval = 0;
  uint16_t latency = 0;
  uint16_t timeout = 0;
  SendLeLinkLayerPacket(LeConnectionParameterUpdateBuilder::Create(
      connections_.GetOwnAddress(connection_handle).GetAddress(),
      connections_.GetAddress(connection_handle).GetAddress(),
      static_cast<uint8_t>(reason), interval, latency, timeout));
  return ErrorCode::SUCCESS;
}

bool LinkLayerController::HasAclConnection() {
  return !connections_.GetAclHandles().empty();
}

bool LinkLayerController::HasAclConnection(uint16_t connection_handle) {
  return connections_.HasHandle(connection_handle);
}

void LinkLayerController::HandleLeEnableEncryption(
    uint16_t handle, std::array<uint8_t, 8> rand, uint16_t ediv,
    std::array<uint8_t, kLtkSize> ltk) {
  // TODO: Check keys
  // TODO: Block ACL traffic or at least guard against it
  if (!connections_.HasHandle(handle)) {
    return;
  }
  SendLeLinkLayerPacket(model::packets::LeEncryptConnectionBuilder::Create(
      connections_.GetOwnAddress(handle).GetAddress(),
      connections_.GetAddress(handle).GetAddress(), rand, ediv, ltk));
}

ErrorCode LinkLayerController::LeEnableEncryption(
    uint16_t handle, std::array<uint8_t, 8> rand, uint16_t ediv,
    std::array<uint8_t, kLtkSize> ltk) {
  if (!connections_.HasHandle(handle)) {
    INFO(id_, "Unknown handle 0x{:04x}", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(kNoDelayMs, [this, handle, rand, ediv, ltk]() {
    HandleLeEnableEncryption(handle, rand, ediv, ltk);
  });
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeLongTermKeyRequestReply(
    uint16_t handle, std::array<uint8_t, kLtkSize> ltk) {
  if (!connections_.HasHandle(handle)) {
    INFO(id_, "Unknown handle {:04x}", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: Check keys
  if (connections_.IsEncrypted(handle)) {
    if (IsEventUnmasked(EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE)) {
      send_event_(bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(
          ErrorCode::SUCCESS, handle));
    }
  } else {
    connections_.Encrypt(handle);
    if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
      send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
          ErrorCode::SUCCESS, handle, bluetooth::hci::EncryptionEnabled::ON));
    }
  }
  SendLeLinkLayerPacket(
      model::packets::LeEncryptConnectionResponseBuilder::Create(
          connections_.GetOwnAddress(handle).GetAddress(),
          connections_.GetAddress(handle).GetAddress(),
          std::array<uint8_t, 8>(), uint16_t(), ltk));

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeLongTermKeyRequestNegativeReply(
    uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    INFO(id_, "Unknown handle {:04x}", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  SendLeLinkLayerPacket(
      model::packets::LeEncryptConnectionResponseBuilder::Create(
          connections_.GetOwnAddress(handle).GetAddress(),
          connections_.GetAddress(handle).GetAddress(),
          std::array<uint8_t, 8>(), uint16_t(), std::array<uint8_t, 16>()));
  return ErrorCode::SUCCESS;
}

void LinkLayerController::Reset() {
  host_supported_features_ = 0;
  le_host_support_ = false;
  secure_simple_pairing_host_support_ = false;
  secure_connections_host_support_ = false;
  le_host_supported_features_ = 0;
  connected_isochronous_stream_host_support_ = false;
  connection_subrating_host_support_ = false;
  random_address_ = Address::kEmpty;
  page_scan_enable_ = false;
  inquiry_scan_enable_ = false;
  inquiry_scan_interval_ = 0x1000;
  inquiry_scan_window_ = 0x0012;
  page_timeout_ = 0x2000;
  connection_accept_timeout_ = 0x1FA0;
  page_scan_interval_ = 0x0800;
  page_scan_window_ = 0x0012;
  voice_setting_ = 0x0060;
  authentication_enable_ = AuthenticationEnable::NOT_REQUIRED;
  default_link_policy_settings_ = 0x0000;
  sco_flow_control_enable_ = false;
  local_name_.fill(0);
  extended_inquiry_response_.fill(0);
  class_of_device_ = 0;
  min_encryption_key_size_ = 16;
  event_mask_ = 0x00001fffffffffff;
  event_mask_page_2_ = 0x0;
  le_event_mask_ = 0x01f;
  le_suggested_max_tx_octets_ = 0x001b;
  le_suggested_max_tx_time_ = 0x0148;
  resolvable_private_address_timeout_ = std::chrono::seconds(0x0384);
  page_scan_repetition_mode_ = PageScanRepetitionMode::R0;
  connections_ = AclConnectionHandler();
  oob_id_ = 1;
  key_id_ = 1;
  le_periodic_advertiser_list_.clear();
  le_filter_accept_list_.clear();
  le_resolving_list_.clear();
  le_resolving_list_enabled_ = false;
  legacy_advertising_in_use_ = false;
  extended_advertising_in_use_ = false;
  legacy_advertiser_ = LegacyAdvertiser{};
  extended_advertisers_.clear();
  scanner_ = Scanner{};
  initiator_ = Initiator{};
  synchronizing_ = {};
  synchronized_ = {};
  last_inquiry_ = steady_clock::now();
  inquiry_mode_ = InquiryType::STANDARD;
  inquiry_lap_ = 0;
  inquiry_max_responses_ = 0;
  default_tx_phys_ = properties_.LeSupportedPhys();
  default_rx_phys_ = properties_.LeSupportedPhys();

  bluetooth::hci::Lap general_iac;
  general_iac.lap_ = 0x33;  // 0x9E8B33
  current_iac_lap_list_.clear();
  current_iac_lap_list_.emplace_back(general_iac);

  page_ = {};

  if (inquiry_timer_task_id_ != kInvalidTaskId) {
    CancelScheduledTask(inquiry_timer_task_id_);
    inquiry_timer_task_id_ = kInvalidTaskId;
  }

  lm_.reset(link_manager_create(controller_ops_));
  ll_.reset(link_layer_create(controller_ops_));
}

/// Drive the logic for the Page controller substate.
void LinkLayerController::Paging() {
  auto now = std::chrono::steady_clock::now();

  if (page_.has_value() && now >= page_->page_timeout) {
    INFO("page timeout triggered for connection with {}",
         page_->bd_addr.ToString());

    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        ErrorCode::PAGE_TIMEOUT, 0, page_->bd_addr,
        bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));

    page_ = {};
    return;
  }

  // Send a Page packet to the peer when a paging interval has passed.
  // Paging is suppressed while a pending connection with the same peer is
  // being established (i.e. two hosts initiated a connection simultaneously).
  if (page_.has_value() && now >= page_->next_page_event &&
      !connections_.HasPendingConnection(page_->bd_addr)) {
    SendLinkLayerPacket(model::packets::PageBuilder::Create(
        GetAddress(), page_->bd_addr, class_of_device_,
        page_->allow_role_switch));
    page_->next_page_event = now + kPageInterval;
  }
}

void LinkLayerController::StartInquiry(milliseconds timeout) {
  inquiry_timer_task_id_ = ScheduleTask(milliseconds(timeout), [this]() {
    LinkLayerController::InquiryTimeout();
  });
}

void LinkLayerController::InquiryCancel() {
  ASSERT(inquiry_timer_task_id_ != kInvalidTaskId);
  CancelScheduledTask(inquiry_timer_task_id_);
  inquiry_timer_task_id_ = kInvalidTaskId;
}

void LinkLayerController::InquiryTimeout() {
  if (inquiry_timer_task_id_ != kInvalidTaskId) {
    inquiry_timer_task_id_ = kInvalidTaskId;
    if (IsEventUnmasked(EventCode::INQUIRY_COMPLETE)) {
      send_event_(
          bluetooth::hci::InquiryCompleteBuilder::Create(ErrorCode::SUCCESS));
    }
  }
}

void LinkLayerController::SetInquiryMode(uint8_t mode) {
  inquiry_mode_ = static_cast<model::packets::InquiryType>(mode);
}

void LinkLayerController::SetInquiryLAP(uint64_t lap) { inquiry_lap_ = lap; }

void LinkLayerController::SetInquiryMaxResponses(uint8_t max) {
  inquiry_max_responses_ = max;
}

void LinkLayerController::Inquiry() {
  steady_clock::time_point now = steady_clock::now();
  if (duration_cast<milliseconds>(now - last_inquiry_) < milliseconds(2000)) {
    return;
  }

  SendLinkLayerPacket(model::packets::InquiryBuilder::Create(
      GetAddress(), Address::kEmpty, inquiry_mode_, inquiry_lap_));
  last_inquiry_ = now;
}

void LinkLayerController::SetInquiryScanEnable(bool enable) {
  inquiry_scan_enable_ = enable;
}

void LinkLayerController::SetPageScanEnable(bool enable) {
  page_scan_enable_ = enable;
}

void LinkLayerController::SetPageTimeout(uint16_t page_timeout) {
  page_timeout_ = page_timeout;
}

ErrorCode LinkLayerController::AddScoConnection(uint16_t connection_handle,
                                                uint16_t packet_type,
                                                ScoDatapath datapath) {
  if (!connections_.HasHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  Address bd_addr = connections_.GetAddress(connection_handle).GetAddress();
  if (connections_.HasPendingScoConnection(bd_addr)) {
    return ErrorCode::COMMAND_DISALLOWED;
  }

  INFO(id_, "Creating SCO connection with {}", bd_addr);

  // Save connection parameters.
  ScoConnectionParameters connection_parameters = {
      8000,
      8000,
      0xffff,
      0x60 /* 16bit CVSD */,
      (uint8_t)bluetooth::hci::RetransmissionEffort::NO_RETRANSMISSION,
      (uint16_t)((uint16_t)((packet_type >> 5) & 0x7U) |
                 (uint16_t)bluetooth::hci::SynchronousPacketTypeBits::
                     NO_2_EV3_ALLOWED |
                 (uint16_t)bluetooth::hci::SynchronousPacketTypeBits::
                     NO_3_EV3_ALLOWED |
                 (uint16_t)bluetooth::hci::SynchronousPacketTypeBits::
                     NO_2_EV5_ALLOWED |
                 (uint16_t)bluetooth::hci::SynchronousPacketTypeBits::
                     NO_3_EV5_ALLOWED)};
  connections_.CreateScoConnection(
      connections_.GetAddress(connection_handle).GetAddress(),
      connection_parameters, SCO_STATE_PENDING, datapath, true);

  // Send SCO connection request to peer.
  SendLinkLayerPacket(model::packets::ScoConnectionRequestBuilder::Create(
      GetAddress(), bd_addr, connection_parameters.transmit_bandwidth,
      connection_parameters.receive_bandwidth,
      connection_parameters.max_latency, connection_parameters.voice_setting,
      connection_parameters.retransmission_effort,
      connection_parameters.packet_type, class_of_device_));
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SetupSynchronousConnection(
    uint16_t connection_handle, uint32_t transmit_bandwidth,
    uint32_t receive_bandwidth, uint16_t max_latency, uint16_t voice_setting,
    uint8_t retransmission_effort, uint16_t packet_types,
    ScoDatapath datapath) {
  if (!connections_.HasHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  Address bd_addr = connections_.GetAddress(connection_handle).GetAddress();
  if (connections_.HasPendingScoConnection(bd_addr)) {
    // This command may be used to modify an exising eSCO link.
    // Skip for now. TODO: should return an event
    // HCI_Synchronous_Connection_Changed on both sides.
    return ErrorCode::COMMAND_DISALLOWED;
  }

  INFO(id_, "Creating eSCO connection with {}", bd_addr);

  // Save connection parameters.
  ScoConnectionParameters connection_parameters = {
      transmit_bandwidth, receive_bandwidth,     max_latency,
      voice_setting,      retransmission_effort, packet_types};
  connections_.CreateScoConnection(
      connections_.GetAddress(connection_handle).GetAddress(),
      connection_parameters, SCO_STATE_PENDING, datapath);

  // Send eSCO connection request to peer.
  SendLinkLayerPacket(model::packets::ScoConnectionRequestBuilder::Create(
      GetAddress(), bd_addr, transmit_bandwidth, receive_bandwidth, max_latency,
      voice_setting, retransmission_effort, packet_types, class_of_device_));
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::AcceptSynchronousConnection(
    Address bd_addr, uint32_t transmit_bandwidth, uint32_t receive_bandwidth,
    uint16_t max_latency, uint16_t voice_setting, uint8_t retransmission_effort,
    uint16_t packet_types) {
  INFO(id_, "Accepting eSCO connection request from {}", bd_addr);

  if (!connections_.HasPendingScoConnection(bd_addr)) {
    INFO(id_, "No pending eSCO connection for {}", bd_addr);
    return ErrorCode::COMMAND_DISALLOWED;
  }

  ErrorCode status = ErrorCode::SUCCESS;
  uint16_t sco_handle = 0;
  ScoLinkParameters link_parameters = {};
  ScoConnectionParameters connection_parameters = {
      transmit_bandwidth, receive_bandwidth,     max_latency,
      voice_setting,      retransmission_effort, packet_types};

  if (!connections_.AcceptPendingScoConnection(
          bd_addr, connection_parameters, [this, bd_addr] {
            return LinkLayerController::StartScoStream(bd_addr);
          })) {
    connections_.CancelPendingScoConnection(bd_addr);
    status = ErrorCode::STATUS_UNKNOWN;  // TODO: proper status code
  } else {
    sco_handle = connections_.GetScoHandle(bd_addr);
    link_parameters = connections_.GetScoLinkParameters(bd_addr);
  }

  // Send eSCO connection response to peer.
  SendLinkLayerPacket(model::packets::ScoConnectionResponseBuilder::Create(
      GetAddress(), bd_addr, (uint8_t)status,
      link_parameters.transmission_interval,
      link_parameters.retransmission_window, link_parameters.rx_packet_length,
      link_parameters.tx_packet_length, link_parameters.air_mode,
      link_parameters.extended));

  // Schedule HCI Synchronous Connection Complete event.
  ScheduleTask(kNoDelayMs, [this, status, sco_handle, bd_addr,
                            link_parameters]() {
    send_event_(bluetooth::hci::SynchronousConnectionCompleteBuilder::Create(
        ErrorCode(status), sco_handle, bd_addr,
        link_parameters.extended ? bluetooth::hci::ScoLinkType::ESCO
                                 : bluetooth::hci::ScoLinkType::SCO,
        link_parameters.extended ? link_parameters.transmission_interval : 0,
        link_parameters.extended ? link_parameters.retransmission_window : 0,
        link_parameters.extended ? link_parameters.rx_packet_length : 0,
        link_parameters.extended ? link_parameters.tx_packet_length : 0,
        bluetooth::hci::ScoAirMode(link_parameters.air_mode)));
  });

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::RejectSynchronousConnection(Address bd_addr,
                                                           uint16_t reason) {
  INFO(id_, "Rejecting eSCO connection request from {}", bd_addr);

  if (reason == (uint8_t)ErrorCode::SUCCESS) {
    reason = (uint8_t)ErrorCode::REMOTE_USER_TERMINATED_CONNECTION;
  }
  if (!connections_.HasPendingScoConnection(bd_addr)) {
    return ErrorCode::COMMAND_DISALLOWED;
  }

  connections_.CancelPendingScoConnection(bd_addr);

  // Send eSCO connection response to peer.
  SendLinkLayerPacket(model::packets::ScoConnectionResponseBuilder::Create(
      GetAddress(), bd_addr, reason, 0, 0, 0, 0, 0, 0));

  // Schedule HCI Synchronous Connection Complete event.
  ScheduleTask(kNoDelayMs, [this, reason, bd_addr]() {
    send_event_(bluetooth::hci::SynchronousConnectionCompleteBuilder::Create(
        ErrorCode(reason), 0, bd_addr, bluetooth::hci::ScoLinkType::ESCO, 0, 0,
        0, 0, bluetooth::hci::ScoAirMode::TRANSPARENT));
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::CheckExpiringConnection(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    return;
  }

  if (connections_.HasLinkExpired(handle)) {
    Disconnect(handle, ErrorCode::CONNECTION_TIMEOUT,
               ErrorCode::CONNECTION_TIMEOUT);
    return;
  }

  if (connections_.IsLinkNearExpiring(handle)) {
    AddressWithType my_address = connections_.GetOwnAddress(handle);
    AddressWithType destination = connections_.GetAddress(handle);
    SendLinkLayerPacket(model::packets::PingRequestBuilder::Create(
        my_address.GetAddress(), destination.GetAddress()));
    ScheduleTask(std::chrono::duration_cast<milliseconds>(
                     connections_.TimeUntilLinkExpired(handle)),
                 [this, handle] { CheckExpiringConnection(handle); });
    return;
  }

  ScheduleTask(std::chrono::duration_cast<milliseconds>(
                   connections_.TimeUntilLinkNearExpiring(handle)),
               [this, handle] { CheckExpiringConnection(handle); });
}

void LinkLayerController::IncomingPingRequest(
    model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::PingRequestView::Create(incoming);
  ASSERT(view.IsValid());
  SendLinkLayerPacket(model::packets::PingResponseBuilder::Create(
      incoming.GetDestinationAddress(), incoming.GetSourceAddress()));
}

TaskId LinkLayerController::StartScoStream(Address address) {
  auto sco_builder = bluetooth::hci::ScoBuilder::Create(
      connections_.GetScoHandle(address), PacketStatusFlag::CORRECTLY_RECEIVED,
      {0, 0, 0, 0, 0});

  auto sco_bytes = sco_builder->SerializeToBytes();
  auto sco_view = bluetooth::hci::ScoView::Create(pdl::packet::slice(
      std::make_shared<std::vector<uint8_t>>(std::move(sco_bytes))));
  ASSERT(sco_view.IsValid());

  return SchedulePeriodicTask(0ms, 20ms, [this, address, sco_view]() {
    INFO(id_, "SCO sending...");
    SendScoToRemote(sco_view);
  });
}

TaskId LinkLayerController::NextTaskId() {
  TaskId task_id = task_counter_++;
  while (
      task_id == kInvalidTaskId ||
      std::any_of(task_queue_.begin(), task_queue_.end(),
                  [=](Task const& task) { return task.task_id == task_id; })) {
    task_id = task_counter_++;
  }
  return task_id;
}

TaskId LinkLayerController::ScheduleTask(std::chrono::milliseconds delay,
                                         TaskCallback task_callback) {
  TaskId task_id = NextTaskId();
  task_queue_.emplace(std::chrono::steady_clock::now() + delay,
                      std::move(task_callback), task_id);
  return task_id;
}

TaskId LinkLayerController::SchedulePeriodicTask(
    std::chrono::milliseconds delay, std::chrono::milliseconds period,
    TaskCallback task_callback) {
  TaskId task_id = NextTaskId();
  task_queue_.emplace(std::chrono::steady_clock::now() + delay, period,
                      std::move(task_callback), task_id);
  return task_id;
}

void LinkLayerController::CancelScheduledTask(TaskId task_id) {
  auto it = task_queue_.cbegin();
  for (; it != task_queue_.cend(); it++) {
    if (it->task_id == task_id) {
      task_queue_.erase(it);
      return;
    }
  }
}

void LinkLayerController::RunPendingTasks() {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  while (!task_queue_.empty()) {
    auto it = task_queue_.begin();
    if (it->time > now) {
      break;
    }

    Task task = *it;
    task_queue_.erase(it);
    task.callback();

    // Re-insert periodic tasks after updating the
    // time by the period.
    if (task.periodic) {
      task.time = now + task.period;
      task_queue_.insert(task);
    }
  }
}

}  // namespace rootcanal
