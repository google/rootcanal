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

#include "model/controller/le_controller.h"

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
#include "model/controller/le_acl_connection.h"
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

using TaskId = rootcanal::LeController::TaskId;

namespace rootcanal {

constexpr milliseconds kScanRequestTimeout(200);
constexpr milliseconds kNoDelayMs(0);

const Address& LeController::GetAddress() const { return address_; }

AddressWithType PeerDeviceAddress(Address address, PeerAddressType peer_address_type) {
  switch (peer_address_type) {
    case PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS:
      return AddressWithType(address, AddressType::PUBLIC_DEVICE_ADDRESS);
    case PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS:
      return AddressWithType(address, AddressType::RANDOM_DEVICE_ADDRESS);
  }
}

AddressWithType PeerIdentityAddress(Address address, PeerAddressType peer_address_type) {
  switch (peer_address_type) {
    case PeerAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS:
      return AddressWithType(address, AddressType::PUBLIC_IDENTITY_ADDRESS);
    case PeerAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS:
      return AddressWithType(address, AddressType::RANDOM_IDENTITY_ADDRESS);
  }
}

bool LeController::IsEventUnmasked(EventCode event) const {
  uint8_t evt = static_cast<uint8_t>(event);

  if (evt <= 64) {
    uint64_t bit = UINT64_C(1) << (evt - 1);
    return (event_mask_ & bit) != 0;
  } else {
    evt -= 64;
    uint64_t bit = UINT64_C(1) << (evt - 1);
    return (event_mask_page_2_ & bit) != 0;
  }
}

bool LeController::IsLeEventUnmasked(SubeventCode subevent) const {
  uint64_t bit = UINT64_C(1) << (static_cast<uint8_t>(subevent) - 1);
  return IsEventUnmasked(EventCode::LE_META_EVENT) && (le_event_mask_ & bit) != 0;
}

bool LeController::FilterAcceptListBusy() {
  // Filter Accept List cannot be modified when
  //  • any advertising filter policy uses the Filter Accept List and
  //    advertising is enabled,
  if (legacy_advertiser_.IsEnabled() &&
      legacy_advertiser_.advertising_filter_policy !=
              bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES) {
    return true;
  }

  for (auto const& [_, advertiser] : extended_advertisers_) {
    if (advertiser.IsEnabled() && advertiser.advertising_filter_policy !=
                                          bluetooth::hci::AdvertisingFilterPolicy::ALL_DEVICES) {
      return true;
    }
  }

  //  • the scanning filter policy uses the Filter Accept List and scanning
  //    is enabled,
  if (scanner_.IsEnabled() &&
      (scanner_.scan_filter_policy ==
               bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY ||
       scanner_.scan_filter_policy == bluetooth::hci::LeScanningFilterPolicy::
                                              FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY)) {
    return true;
  }

  //  • the initiator filter policy uses the Filter Accept List and an
  //    HCI_LE_Create_Connection or HCI_LE_Extended_Create_Connection
  //    command is pending.
  if (initiator_.IsEnabled() &&
      initiator_.initiator_filter_policy ==
              bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST_WITH_PEER_ADDRESS) {
    return true;
  }

  return false;
}

bool LeController::LeFilterAcceptListContainsDevice(FilterAcceptListAddressType address_type,
                                                    Address address) {
  for (auto const& entry : le_filter_accept_list_) {
    if (entry.address_type == address_type &&
        (address_type == FilterAcceptListAddressType::ANONYMOUS_ADVERTISERS ||
         entry.address == address)) {
      return true;
    }
  }

  return false;
}

bool LeController::LePeriodicAdvertiserListContainsDevice(
        bluetooth::hci::AdvertiserAddressType advertiser_address_type, Address advertiser_address,
        uint8_t advertising_sid) {
  for (auto const& entry : le_periodic_advertiser_list_) {
    if (entry.advertiser_address_type == advertiser_address_type &&
        entry.advertiser_address == advertiser_address &&
        entry.advertising_sid == advertising_sid) {
      return true;
    }
  }

  return false;
}

bool LeController::LeFilterAcceptListContainsDevice(AddressWithType address) {
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

bool LeController::ResolvingListBusy() {
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

std::optional<AddressWithType> LeController::ResolvePrivateAddress(AddressWithType address) {
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

      return PeerDeviceAddress(entry.peer_identity_address, entry.peer_identity_address_type);
    }
  }

  return {};
}

bool LeController::ResolveTargetA(AddressWithType target_a, AddressWithType adv_a) {
  if (!le_resolving_list_enabled_) {
    return false;
  }

  for (auto const& entry : le_resolving_list_) {
    if (adv_a == PeerDeviceAddress(entry.peer_identity_address, entry.peer_identity_address_type) &&
        target_a.IsRpaThatMatchesIrk(entry.local_irk)) {
      return true;
    }
  }

  return false;
}

bool LeController::ValidateTargetA(AddressWithType target_a, AddressWithType adv_a) {
  if (IsLocalPublicOrRandomAddress(target_a)) {
    return true;
  }
  if (target_a.IsRpa()) {
    return ResolveTargetA(target_a, adv_a);
  }
  return false;
}

std::optional<AddressWithType> LeController::GenerateResolvablePrivateAddress(
        AddressWithType address, IrkSelection irk) {
  for (auto& entry : le_resolving_list_) {
    if (address.GetAddress() == entry.peer_identity_address &&
        address.ToPeerAddressType() == entry.peer_identity_address_type) {
      std::array<uint8_t, LeController::kIrkSize> const& used_irk =
              irk == IrkSelection::Local ? entry.local_irk : entry.peer_irk;
      Address local_resolvable_address = generate_rpa(used_irk);

      // Update the local resolvable address used for the peer
      // with the returned identity address.
      if (irk == IrkSelection::Local) {
        entry.local_resolvable_address = local_resolvable_address;
      }

      return AddressWithType{local_resolvable_address, AddressType::RANDOM_DEVICE_ADDRESS};
    }
  }

  return {};
}

// =============================================================================
//  BR/EDR Commands
// =============================================================================

// HCI Read Rssi command (Vol 4, Part E § 7.5.4).
ErrorCode LeController::ReadRssi(uint16_t connection_handle, int8_t* rssi) {
  if (connections_.HasLeAclHandle(connection_handle)) {
    *rssi = connections_.GetLeAclConnection(connection_handle).GetRssi();
    return ErrorCode::SUCCESS;
  }

  // Not documented: If the connection handle is not found, the Controller
  // shall return the error code Unknown Connection Identifier (0x02).
  INFO(id_, "unknown connection identifier");
  return ErrorCode::UNKNOWN_CONNECTION;
}

// =============================================================================
//  General LE Commands
// =============================================================================

// HCI LE Set Random Address command (Vol 4, Part E § 7.8.4).
ErrorCode LeController::LeSetRandomAddress(Address random_address) {
  // If the Host issues this command when any of advertising (created using
  // legacy advertising commands), scanning, or initiating are enabled,
  // the Controller shall return the error code Command Disallowed (0x0C).
  if (legacy_advertiser_.IsEnabled() || scanner_.IsEnabled() || initiator_.IsEnabled()) {
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
ErrorCode LeController::LeSetResolvablePrivateAddressTimeout(uint16_t rpa_timeout) {
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
ErrorCode LeController::LeReadPhy(uint16_t connection_handle, bluetooth::hci::PhyType* tx_phy,
                                  bluetooth::hci::PhyType* rx_phy) {
  // Note: no documented status code for this case.
  if (!connections_.HasLeAclHandle(connection_handle)) {
    INFO(id_, "unknown or invalid connection handle");
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  LeAclConnection const& connection = connections_.GetLeAclConnection(connection_handle);
  *tx_phy = connection.GetTxPhy();
  *rx_phy = connection.GetRxPhy();
  return ErrorCode::SUCCESS;
}

// HCI LE Set Default Phy command (Vol 4, Part E § 7.8.48).
ErrorCode LeController::LeSetDefaultPhy(bool all_phys_no_transmit_preference,
                                        bool all_phys_no_receive_preference, uint8_t tx_phys,
                                        uint8_t rx_phys) {
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
ErrorCode LeController::LeSetPhy(uint16_t connection_handle, bool all_phys_no_transmit_preference,
                                 bool all_phys_no_receive_preference, uint8_t tx_phys,
                                 uint8_t rx_phys, bluetooth::hci::PhyOptions /*phy_options*/) {
  uint8_t supported_phys = properties_.LeSupportedPhys();

  // Note: no documented status code for this case.
  if (!connections_.HasLeAclHandle(connection_handle)) {
    INFO(id_, "unknown or invalid connection handle");
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetLeAclConnection(connection_handle);

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
    INFO(id_, "TX_PhyS ({:x}) configures unsupported or reserved bits", tx_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }
  if ((rx_phys & ~supported_phys) != 0) {
    INFO(id_, "RX_PhyS ({:x}) configures unsupported or reserved bits", rx_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The HCI_LE_PHY_Update_Complete event shall be generated either when one
  // or both PHY changes or when the Controller determines that neither PHY
  // will change immediately.
  SendLeLinkLayerPacket(model::packets::LlPhyReqBuilder::Create(
          connection.own_address.GetAddress(), connection.address.GetAddress(), tx_phys, rx_phys));

  connection.InitiatePhyUpdate();
  requested_tx_phys_ = tx_phys;
  requested_rx_phys_ = rx_phys;
  return ErrorCode::SUCCESS;
}

// Helper to pick one phy in enabled phys.
static bluetooth::hci::PhyType select_phy(uint8_t phys, bluetooth::hci::PhyType current) {
  return (phys & 0x4)   ? bluetooth::hci::PhyType::LE_CODED
         : (phys & 0x2) ? bluetooth::hci::PhyType::LE_2M
         : (phys & 0x1) ? bluetooth::hci::PhyType::LE_1M
                        : current;
}

// Helper to generate the LL_PHY_UPDATE_IND mask for the selected phy.
// The mask is non zero only if the phy has changed.
static uint8_t indicate_phy(bluetooth::hci::PhyType selected, bluetooth::hci::PhyType current) {
  return selected == current                             ? 0x0
         : selected == bluetooth::hci::PhyType::LE_CODED ? 0x4
         : selected == bluetooth::hci::PhyType::LE_2M    ? 0x2
                                                         : 0x1;
}

void LeController::IncomingLlPhyReq(LeAclConnection& connection,
                                    model::packets::LinkLayerPacketView incoming) {
  auto phy_req = model::packets::LlPhyReqView::Create(incoming);
  ASSERT(phy_req.IsValid());

  if (connection.role == bluetooth::hci::Role::PERIPHERAL) {
    // Peripheral receives the request: respond with local phy preferences
    // in LL_PHY_RSP pdu.
    SendLeLinkLayerPacket(model::packets::LlPhyRspBuilder::Create(
            incoming.GetDestinationAddress(), incoming.GetSourceAddress(), default_tx_phys_,
            default_rx_phys_));
  } else {
    // Central receives the request: respond with LL_PHY_UPDATE_IND and
    // the selected phys.

    // Intersect phy preferences with local preferences.
    uint8_t tx_phys = phy_req.GetRxPhys() & default_tx_phys_;
    uint8_t rx_phys = phy_req.GetTxPhys() & default_rx_phys_;

    // Select valid TX and RX phys from preferences.
    bluetooth::hci::PhyType phy_c_to_p = select_phy(tx_phys, connection.GetTxPhy());
    bluetooth::hci::PhyType phy_p_to_c = select_phy(rx_phys, connection.GetRxPhy());

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
    if ((phy_c_to_p != connection.GetTxPhy() || phy_p_to_c != connection.GetRxPhy()) &&
        IsLeEventUnmasked(SubeventCode::LE_PHY_UPDATE_COMPLETE)) {
      send_event_(bluetooth::hci::LePhyUpdateCompleteBuilder::Create(
              ErrorCode::SUCCESS, connection.handle, phy_c_to_p, phy_p_to_c));
    }

    // Update local state.
    connection.SetTxPhy(phy_c_to_p);
    connection.SetRxPhy(phy_p_to_c);
  }
}

void LeController::IncomingLlPhyRsp(LeAclConnection& connection,
                                    model::packets::LinkLayerPacketView incoming) {
  auto phy_rsp = model::packets::LlPhyRspView::Create(incoming);
  ASSERT(phy_rsp.IsValid());
  ASSERT(connection.role == bluetooth::hci::Role::CENTRAL);

  // Intersect phy preferences with local preferences.
  uint8_t tx_phys = phy_rsp.GetRxPhys() & requested_tx_phys_;
  uint8_t rx_phys = phy_rsp.GetTxPhys() & requested_rx_phys_;

  // Select valid TX and RX phys from preferences.
  bluetooth::hci::PhyType phy_c_to_p = select_phy(tx_phys, connection.GetTxPhy());
  bluetooth::hci::PhyType phy_p_to_c = select_phy(rx_phys, connection.GetRxPhy());

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
  if (IsLeEventUnmasked(SubeventCode::LE_PHY_UPDATE_COMPLETE)) {
    send_event_(bluetooth::hci::LePhyUpdateCompleteBuilder::Create(
            ErrorCode::SUCCESS, connection.handle, phy_c_to_p, phy_p_to_c));
  }

  // Update local state.
  connection.PhyUpdateComplete();
  connection.SetTxPhy(phy_c_to_p);
  connection.SetRxPhy(phy_p_to_c);
}

void LeController::IncomingLlPhyUpdateInd(LeAclConnection& connection,
                                          model::packets::LinkLayerPacketView incoming) {
  auto phy_update_ind = model::packets::LlPhyUpdateIndView::Create(incoming);
  ASSERT(phy_update_ind.IsValid());
  ASSERT(connection.role == bluetooth::hci::Role::PERIPHERAL);

  bluetooth::hci::PhyType tx_phy = select_phy(phy_update_ind.GetPhyPToC(), connection.GetTxPhy());
  bluetooth::hci::PhyType rx_phy = select_phy(phy_update_ind.GetPhyCToP(), connection.GetRxPhy());

  // Update local state, and notify the host.
  // The notification is sent only when the local host is initiator
  // of the Phy update procedure or the phy selection has changed.
  if (IsLeEventUnmasked(SubeventCode::LE_PHY_UPDATE_COMPLETE) &&
      (tx_phy != connection.GetTxPhy() || rx_phy != connection.GetRxPhy() ||
       connection.InitiatedPhyUpdate())) {
    send_event_(bluetooth::hci::LePhyUpdateCompleteBuilder::Create(
            ErrorCode::SUCCESS, connection.handle, tx_phy, rx_phy));
  }

  connection.PhyUpdateComplete();
  connection.SetTxPhy(tx_phy);
  connection.SetRxPhy(rx_phy);
}

// HCI LE Set Data Length (Vol 4, Part E § 7.8.33).
ErrorCode LeController::LeSetDataLength(uint16_t connection_handle, uint16_t tx_octets,
                                        uint16_t tx_time) {
  // Note: no documented status code for this case.
  if (!connections_.HasLeAclHandle(connection_handle)) {
    INFO(id_, "unknown or invalid connection handle");
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // Note: no documented status code for this case.
  if (tx_octets < 0x001B || tx_octets > 0x00FB) {
    INFO(id_, "invalid TX_Octets parameter value: 0x{:x} is not in the range 0x1B .. 0xFB",
         tx_octets);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Note: no documented status code for this case.
  if (tx_time < 0x0148 || tx_time > 0x4290) {
    INFO(id_, "invalid TX_Time parameter value: 0x{:x} is not in the range 0x0148 .. 0x4290",
         tx_time);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // As mentioned in the Core specification: the Controller may use smaller or
  // larger values based on local information.
  // For now the change is ignored and the LE Data Length Change event will
  // not be generated.

  return ErrorCode::SUCCESS;
}

// HCI LE Set Host Feature command (Vol 4, Part E § 7.8.115).
ErrorCode LeController::LeSetHostFeature(uint8_t bit_number, uint8_t bit_value) {
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
  if (!connections_.GetLeAclHandles().empty()) {
    return ErrorCode::COMMAND_DISALLOWED;
  }

  uint64_t bit_mask = UINT64_C(1) << bit_number;
  if (bit_mask ==
      static_cast<uint64_t>(LLFeaturesBits::CONNECTED_ISOCHRONOUS_STREAM_HOST_SUPPORT)) {
    connected_isochronous_stream_host_support_ = bit_value != 0;
  } else if (bit_mask == static_cast<uint64_t>(LLFeaturesBits::CONNECTION_SUBRATING_HOST_SUPPORT)) {
    connection_subrating_host_support_ = bit_value != 0;
  } else {
    // If Bit_Number specifies a feature bit that is not controlled by the Host,
    // the Controller shall return the error code Unsupported Feature or
    // Parameter Value (0x11).
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
ErrorCode LeController::LeAddDeviceToResolvingList(PeerAddressType peer_identity_address_type,
                                                   Address peer_identity_address,
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
ErrorCode LeController::LeRemoveDeviceFromResolvingList(PeerAddressType peer_identity_address_type,
                                                        Address peer_identity_address) {
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

  for (auto it = le_resolving_list_.begin(); it != le_resolving_list_.end(); it++) {
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
ErrorCode LeController::LeClearResolvingList() {
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
ErrorCode LeController::LeReadPeerResolvableAddress(PeerAddressType peer_identity_address_type,
                                                    Address peer_identity_address,
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
ErrorCode LeController::LeReadLocalResolvableAddress(PeerAddressType peer_identity_address_type,
                                                     Address peer_identity_address,
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
ErrorCode LeController::LeSetAddressResolutionEnable(bool enable) {
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
ErrorCode LeController::LeSetPrivacyMode(PeerAddressType peer_identity_address_type,
                                         Address peer_identity_address,
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
ErrorCode LeController::LeClearFilterAcceptList() {
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
ErrorCode LeController::LeAddDeviceToFilterAcceptList(FilterAcceptListAddressType address_type,
                                                      Address address) {
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

  le_filter_accept_list_.emplace_back(FilterAcceptListEntry{address_type, address});
  return ErrorCode::SUCCESS;
}

// HCI command LE_Remove_Device_From_Filter_Accept_List (Vol 4, Part E
// § 7.8.17).
ErrorCode LeController::LeRemoveDeviceFromFilterAcceptList(FilterAcceptListAddressType address_type,
                                                           Address address) {
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

  for (auto it = le_filter_accept_list_.begin(); it != le_filter_accept_list_.end(); it++) {
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
ErrorCode LeController::LeAddDeviceToPeriodicAdvertiserList(
        bluetooth::hci::AdvertiserAddressType advertiser_address_type, Address advertiser_address,
        uint8_t advertising_sid) {
  // If the Host issues this command when an HCI_LE_Periodic_Advertising_-
  // Create_Sync command is pending, the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (synchronizing_.has_value()) {
    INFO(id_, "LE Periodic Advertising Create Sync command is currently pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // When a Controller cannot add an entry to the Periodic Advertiser list
  // because the list is full, the Controller shall return the error code Memory
  // Capacity Exceeded (0x07).
  if (le_periodic_advertiser_list_.size() >= properties_.le_periodic_advertiser_list_size) {
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
ErrorCode LeController::LeRemoveDeviceFromPeriodicAdvertiserList(
        bluetooth::hci::AdvertiserAddressType advertiser_address_type, Address advertiser_address,
        uint8_t advertising_sid) {
  // If this command is used when an HCI_LE_Periodic_Advertising_Create_Sync
  // command is pending, the Controller shall return the error code Command
  // Disallowed (0x0C).
  if (synchronizing_.has_value()) {
    INFO(id_, "LE Periodic Advertising Create Sync command is currently pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  for (auto it = le_periodic_advertiser_list_.begin(); it != le_periodic_advertiser_list_.end();
       it++) {
    if (it->advertiser_address_type == advertiser_address_type &&
        it->advertiser_address == advertiser_address && it->advertising_sid == advertising_sid) {
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
ErrorCode LeController::LeClearPeriodicAdvertiserList() {
  // If this command is used when an HCI_LE_Periodic_Advertising_Create_Sync
  // command is pending, the Controller shall return the error code Command
  // Disallowed (0x0C).
  if (synchronizing_.has_value()) {
    INFO(id_, "LE Periodic Advertising Create Sync command is currently pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  le_periodic_advertiser_list_.clear();
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Periodic Sync
// =============================================================================

// HCI LE Periodic Advertising Create Sync command (Vol 4, Part E § 7.8.67).
ErrorCode LeController::LePeriodicAdvertisingCreateSync(
        bluetooth::hci::PeriodicAdvertisingOptions options, uint8_t advertising_sid,
        bluetooth::hci::AdvertiserAddressType advertiser_address_type, Address advertiser_address,
        uint16_t /*skip*/, uint16_t sync_timeout, uint8_t sync_cte_type) {
  // If the Host issues this command when another HCI_LE_Periodic_Advertising_-
  // Create_Sync command is pending, the Controller shall return the error code
  // Command Disallowed (0x0C).
  if (synchronizing_.has_value()) {
    INFO(id_, "LE Periodic Advertising Create Sync command is currently pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host sets all the non-reserved bits of the Sync_CTE_Type parameter
  // to 1, the Controller shall return the error code Command Disallowed (0x0C).
  uint8_t sync_cte_type_mask = 0x1f;
  if ((sync_cte_type & sync_cte_type_mask) == sync_cte_type_mask) {
    INFO(id_, "Sync_CTE_Type is configured to ignore all types of advertisement");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command with bit 0 of Options not set and with
  // Advertising_SID, Advertiser_Address_Type, and Advertiser_Address the same
  // as those of a periodic advertising train that the Controller is already
  // synchronized to, the Controller shall return the error code
  // Connection Already Exists (0x0B).
  bool has_synchronized_train = false;
  for (auto& [_, sync] : synchronized_) {
    has_synchronized_train |= sync.advertiser_address_type == advertiser_address_type &&
                              sync.advertiser_address == advertiser_address &&
                              sync.advertising_sid == advertising_sid;
  }
  if (!options.use_periodic_advertiser_list_ && has_synchronized_train) {
    INFO(id_,
         "the controller is already synchronized on the periodic advertising"
         " train from {}[{}] - SID=0x{:x}",
         advertiser_address, bluetooth::hci::AdvertiserAddressTypeText(advertiser_address_type),
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
      !properties_.SupportsLLFeature(LLFeaturesBits::PERIODIC_ADVERTISING_ADI_SUPPORT)) {
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
              bluetooth::hci::OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE)) {
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
ErrorCode LeController::LePeriodicAdvertisingCreateSyncCancel() {
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
  if (IsLeEventUnmasked(SubeventCode::LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V1)) {
    ScheduleTask(0ms, [this] {
      send_event_(bluetooth::hci::LePeriodicAdvertisingSyncEstablishedV1Builder::Create(
              ErrorCode::OPERATION_CANCELLED_BY_HOST, 0, 0, AddressType::PUBLIC_DEVICE_ADDRESS,
              Address::kEmpty, bluetooth::hci::SecondaryPhyType::NO_PACKETS, 0,
              bluetooth::hci::ClockAccuracy::PPM_500));
    });
  }

  synchronizing_ = {};
  return ErrorCode::SUCCESS;
}

// HCI LE Periodic Advertising Terminate Sync command (Vol 4, Part E
// § 7.8.69).
ErrorCode LeController::LePeriodicAdvertisingTerminateSync(uint16_t sync_handle) {
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
ErrorCode LeController::LeSetScanParameters(
        bluetooth::hci::LeScanType scan_type, uint16_t scan_interval, uint16_t scan_window,
        bluetooth::hci::OwnAddressType own_address_type,
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
  if (scan_interval < 0x4 || scan_interval > 0x4000 || scan_window < 0x4 || scan_window > 0x4000) {
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
    INFO(id_, "le_scan_window (0x{:04x}) is larger than le_scan_interval (0x{:04x})", scan_window,
         scan_interval);
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
ErrorCode LeController::LeSetScanEnable(bool enable, bool filter_duplicates) {
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
  if ((scanner_.own_address_type == bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS ||
       scanner_.own_address_type == bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS) &&
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
  scanner_.filter_duplicates = filter_duplicates ? bluetooth::hci::FilterDuplicates::ENABLED
                                                 : bluetooth::hci::FilterDuplicates::DISABLED;
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Extended Scanning
// =============================================================================

// HCI command LE_Set_Extended_Scan_Parameters (Vol 4, Part E § 7.8.64).
ErrorCode LeController::LeSetExtendedScanParameters(
        bluetooth::hci::OwnAddressType own_address_type,
        bluetooth::hci::LeScanningFilterPolicy scanning_filter_policy, uint8_t scanning_phys,
        std::vector<bluetooth::hci::ScanningPhyParameters> scanning_phy_parameters) {
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
  if (__builtin_popcount(scanning_phys) != int(scanning_phy_parameters.size())) {
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
ErrorCode LeController::LeSetExtendedScanEnable(bool enable,
                                                bluetooth::hci::FilterDuplicates filter_duplicates,
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
  if (filter_duplicates == bluetooth::hci::FilterDuplicates::RESET_EACH_PERIOD &&
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
  if ((scanner_.own_address_type == bluetooth::hci::OwnAddressType::RANDOM_DEVICE_ADDRESS ||
       scanner_.own_address_type == bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS) &&
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
ErrorCode LeController::LeCreateConnection(
        uint16_t scan_interval, uint16_t scan_window,
        bluetooth::hci::InitiatorFilterPolicy initiator_filter_policy, AddressWithType peer_address,
        bluetooth::hci::OwnAddressType own_address_type, uint16_t connection_interval_min,
        uint16_t connection_interval_max, uint16_t max_latency, uint16_t supervision_timeout,
        uint16_t min_ce_length, uint16_t max_ce_length) {
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
  if (scan_interval < 0x4 || scan_interval > 0x4000 || scan_window < 0x4 || scan_window > 0x4000) {
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
    INFO(id_, "scan_window (0x{:04x}) is larger than scan_interval (0x{:04x})", scan_window,
         scan_interval);
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
  milliseconds min_supervision_timeout =
          duration_cast<milliseconds>((1 + max_latency) * slots(2 * connection_interval_max) * 2);
  if (supervision_timeout * 10ms < min_supervision_timeout) {
    INFO(id_,
         "supervision_timeout ({} ms) is smaller that the minimal supervision "
         "timeout allowed by connection_interval_max and max_latency ({} ms)",
         supervision_timeout * 10, static_cast<unsigned>(min_supervision_timeout / 1ms));
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
ErrorCode LeController::LeCreateConnectionCancel() {
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
  if (IsLeEventUnmasked(SubeventCode::LE_ENHANCED_CONNECTION_COMPLETE_V1)) {
    ScheduleTask(0ms, [this] {
      send_event_(bluetooth::hci::LeEnhancedConnectionCompleteV1Builder::Create(
              ErrorCode::UNKNOWN_CONNECTION, 0, Role::CENTRAL, AddressType::PUBLIC_DEVICE_ADDRESS,
              Address(), Address(), Address(), 0, 0, 0, bluetooth::hci::ClockAccuracy::PPM_500));
    });
  } else if (IsLeEventUnmasked(SubeventCode::LE_CONNECTION_COMPLETE)) {
    ScheduleTask(0ms, [this] {
      send_event_(bluetooth::hci::LeConnectionCompleteBuilder::Create(
              ErrorCode::UNKNOWN_CONNECTION, 0, Role::CENTRAL, AddressType::PUBLIC_DEVICE_ADDRESS,
              Address(), 0, 0, 0, bluetooth::hci::ClockAccuracy::PPM_500));
    });
  }

  initiator_.Disable();
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Extended Connection
// =============================================================================

// HCI LE Extended Create Connection command (Vol 4, Part E § 7.8.66).
ErrorCode LeController::LeExtendedCreateConnection(
        bluetooth::hci::InitiatorFilterPolicy initiator_filter_policy,
        bluetooth::hci::OwnAddressType own_address_type, AddressWithType peer_address,
        uint8_t initiating_phys,
        std::vector<bluetooth::hci::InitiatingPhyParameters> initiating_phy_parameters) {
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
  if (__builtin_popcount(initiating_phys) != int(initiating_phy_parameters.size())) {
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
      INFO(id_, "scan_window (0x{:04x}) is larger than scan_interval (0x{:04x})",
           parameter.scan_window_, parameter.scan_interval_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    // Note: no explicit error code stated for invalid connection interval
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.connection_interval_min_ < 0x6 || parameter.connection_interval_min_ > 0x0c80 ||
        parameter.connection_interval_max_ < 0x6 || parameter.connection_interval_max_ > 0x0c80) {
      INFO(id_,
           "connection_interval_min (0x{:04x}) and/or "
           "connection_interval_max (0x{:04x}) are outside the range"
           " of supported values (0x6 - 0x0c80)",
           parameter.connection_interval_min_, parameter.connection_interval_max_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // The Connection_Interval_Min parameter shall not be greater than the
    // Connection_Interval_Max parameter.
    if (parameter.connection_interval_max_ < parameter.connection_interval_min_) {
      INFO(id_,
           "connection_interval_min (0x{:04x}) is larger than"
           " connection_interval_max (0x{:04x})",
           parameter.connection_interval_min_, parameter.connection_interval_max_);
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
    if (parameter.supervision_timeout_ < 0xa || parameter.supervision_timeout_ > 0x0c80) {
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
            (1 + parameter.max_latency_) * slots(2 * parameter.connection_interval_max_) * 2);
    if (parameter.supervision_timeout_ * 10ms < min_supervision_timeout) {
      INFO(id_,
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
            .connection_interval_min = initiating_phy_parameters[offset].connection_interval_min_,
            .connection_interval_max = initiating_phy_parameters[offset].connection_interval_max_,
            .max_latency = initiating_phy_parameters[offset].max_latency_,
            .supervision_timeout = initiating_phy_parameters[offset].supervision_timeout_,
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
            .connection_interval_min = initiating_phy_parameters[offset].connection_interval_min_,
            .connection_interval_max = initiating_phy_parameters[offset].connection_interval_max_,
            .max_latency = initiating_phy_parameters[offset].max_latency_,
            .supervision_timeout = initiating_phy_parameters[offset].supervision_timeout_,
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
            .connection_interval_min = initiating_phy_parameters[offset].connection_interval_min_,
            .connection_interval_max = initiating_phy_parameters[offset].connection_interval_max_,
            .max_latency = initiating_phy_parameters[offset].max_latency_,
            .supervision_timeout = initiating_phy_parameters[offset].supervision_timeout_,
            .min_ce_length = initiating_phy_parameters[offset].min_ce_length_,
            .max_ce_length = initiating_phy_parameters[offset].max_ce_length_,
    };
    offset++;
  }

  return ErrorCode::SUCCESS;
}

// =============================================================================
//  LE Connection Subrating
// =============================================================================

// HCI LE Set Default Subrate command (Vol 4, Part E § 7.8.123).
ErrorCode LeController::LeSetDefaultSubrate(uint16_t subrate_min, uint16_t subrate_max,
                                            uint16_t max_latency, uint16_t continuation_number,
                                            uint16_t supervision_timeout) {
  // Note: no explicit error code stated for invalid values but assuming
  // Unsupported Feature or Parameter Value (0x11) error code based on similar commands.

  if (subrate_min < 0x0001 || subrate_min > 0x01f4) {
    INFO(id_,
         "subrate_min (0x{:04x}) is outside the range"
         " of supported values (0x0001 - 0x01f4)",
         subrate_min);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (subrate_max < 0x0001 || subrate_max > 0x01f4) {
    INFO(id_,
         "subrate_max (0x{:04x}) is outside the range"
         " of supported values (0x0001 - 0x01f4)",
         subrate_max);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (subrate_min > subrate_max) {
    INFO(id_, "subrate_min (0x{:04x}) is larger than subrate_max (0x{:04x})", subrate_min,
         subrate_max);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (max_latency > 0x01f3) {
    INFO(id_,
         "max_latency (0x{:04x}) is outside the range"
         " of supported values (0x0000 - 0x01f3)",
         max_latency);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (continuation_number > 0x01f3) {
    INFO(id_,
         "continuation_number (0x{:04x}) is outside the range"
         " of supported values (0x0000 - 0x01f3)",
         continuation_number);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (supervision_timeout < 0x000a || supervision_timeout > 0x0c80) {
    INFO(id_,
         "supervision_timeout (0x{:04x}) is outside the range"
         " of supported values (0x000a - 0x0c80)",
         supervision_timeout);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  default_subrate_parameters_ = LeAclSubrateParameters{
          .subrate_min = subrate_min,
          .subrate_max = subrate_max,
          .max_latency = max_latency,
          .continuation_number = continuation_number,
          .supervision_timeout = supervision_timeout,
  };

  return ErrorCode::SUCCESS;
}

// HCI LE Subrate Request command (Vol 4, Part E § 7.8.124).
ErrorCode LeController::LeSubrateRequest(uint16_t connection_handle, uint16_t subrate_min,
                                         uint16_t subrate_max, uint16_t max_latency,
                                         uint16_t continuation_number,
                                         uint16_t supervision_timeout) {
  // If the Connection_Handle parameter does not identify a current ACL connection, the
  // Controller shall return the error code Unknown Connection Identifier (0x02).
  if (!connections_.HasLeAclHandle(connection_handle)) {
    INFO(id_, "unknown connection_handle (0x{:06x})", connection_handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetLeAclConnection(connection_handle);

  // Note: no explicit error code stated for invalid values but assuming
  // Unsupported Feature or Parameter Value (0x11) error code based on similar commands.

  if (subrate_min < 0x0001 || subrate_min > 0x01f4) {
    INFO(id_,
         "subrate_min (0x{:04x}) is outside the range"
         " of supported values (0x0001 - 0x01f4)",
         subrate_min);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (subrate_max < 0x0001 || subrate_max > 0x01f4) {
    INFO(id_,
         "subrate_max (0x{:04x}) is outside the range"
         " of supported values (0x0001 - 0x01f4)",
         subrate_max);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // If the Host issues this command with Subrate_Max less than Subrate_Min, the
  // Controller shall return the error code Invalid HCI Command Parameters (0x12).
  if (subrate_min > subrate_max) {
    INFO(id_, "subrate_min (0x{:04x}) is larger than subrate_max (0x{:04x})", subrate_min,
         subrate_max);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  if (max_latency > 0x01f3) {
    INFO(id_,
         "max_latency (0x{:04x}) is outside the range"
         " of supported values (0x0000 - 0x01f3)",
         max_latency);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (continuation_number > 0x01f3) {
    INFO(id_,
         "continuation_number (0x{:04x}) is outside the range"
         " of supported values (0x0000 - 0x01f3)",
         continuation_number);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  if (supervision_timeout < 0x000a || supervision_timeout > 0x0c80) {
    INFO(id_,
         "supervision_timeout (0x{:04x}) is outside the range"
         " of supported values (0x000a - 0x0c80)",
         supervision_timeout);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // If the Host issues this command with parameters such that
  // Subrate_Max × (Max_Latency + 1) is greater than 500 or the current connection interval
  // × Subrate_Max × (Max_Latency + 1) is greater than or equal to half the
  // Supervision_Timeout parameter, the Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (subrate_max * (max_latency + 1) > 500) {
    INFO(id_, "subrate_max (0x{:04x}) x (max_latency (0x{:04x}) + 1) is greater than 500",
         subrate_max, max_latency);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  if (connection.parameters.conn_interval * subrate_max * (max_latency + 1) >=
      supervision_timeout / 2) {
    INFO(id_,
         "connInterval (0x{:04x}) x subrate_max (0x{:04x}) x (max_latency (0x{:04x}) + 1)"
         " is greater than or equal to supervision_timeout (0x{:04x}) / 2",
         connection.parameters.conn_interval, subrate_max, max_latency, supervision_timeout);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the Host issues this command with Continuation_Number greater than or equal to
  // Subrate_Max, then the Controller shall return the error code Invalid HCI Command
  // Parameters (0x12).
  if (continuation_number >= subrate_max) {
    INFO(id_, "continuation_number (0x{:04x}) is larger than subrate_max (0x{:04x})",
         continuation_number, subrate_max);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  if (connection.role == bluetooth::hci::Role::CENTRAL) {
    // If the Central's Host issues this command when the Connection Subrating
    // (Host Support) bit is not set in the Peripheral's FeatureSet, the Controller
    // shall return the error code Unsupported Remote Feature (0x1A).
    // TODO: implement when the peripheral feature set is tracked in the ACL connection object.

    // If this command is issued on the Central, the following rules shall apply
    // when the Controller initiates the Connection Subrate Update procedure
    // (see [Vol 6] Part B, Section 5.1.19):
    //     - The Peripheral latency shall be less than or equal to Max_Latency.
    //     - The subrate factor shall be between Subrate_Min and Subrate_Max.
    //     - The continuation number shall be equal to the lesser of
    //       Continuation_Number and (subrate factor - 1).
    //     - The connection supervision timeout shall be equal to Supervision_Timeout.

    // As Central, it is allowed to directly send
    // LL_SUBRATE_IND to update the parameters.
    SendLeLinkLayerPacket(LlSubrateIndBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress(),
            static_cast<uint8_t>(ErrorCode::SUCCESS), subrate_max,
            /* subrate_base_event */ 0, max_latency, continuation_number, supervision_timeout));

    // Update the connection parameters.
    connection.parameters.conn_subrate_factor = subrate_max;
    connection.parameters.conn_continuation_number = continuation_number;
    connection.parameters.conn_peripheral_latency = max_latency;
    connection.parameters.conn_supervision_timeout = supervision_timeout;

    // If this command is issued on the Central, it also sets the acceptable parameters
    // for requests from the Peripheral (see [Vol 6] Part B, Section 5.1.20). The acceptable
    // parameters set by this command override those provided via the HCI_LE_Set_Default_Subrate
    // command or any values set by previous uses of this command on the same connection.
    connection.subrate_parameters = LeAclSubrateParameters{
            .subrate_min = subrate_min,
            .subrate_max = subrate_max,
            .max_latency = max_latency,
            .continuation_number = continuation_number,
            .supervision_timeout = supervision_timeout,
    };

    if (IsLeEventUnmasked(SubeventCode::LE_SUBRATE_CHANGE)) {
      ScheduleTask(kNoDelayMs, [=, this]() {
        send_event_(bluetooth::hci::LeSubrateChangeBuilder::Create(
                ErrorCode::SUCCESS, connection_handle, subrate_max, max_latency,
                continuation_number, supervision_timeout));
      });
    }
  } else {
    // Send LL_SUBRATE_REQ and wait for LL_SUBRATE_IND in return.
    SendLeLinkLayerPacket(LlSubrateReqBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress(), subrate_min,
            subrate_max, max_latency, continuation_number, supervision_timeout));
  }

  return ErrorCode::SUCCESS;
}

void LeController::IncomingLlSubrateReq(LeAclConnection& connection,
                                        model::packets::LinkLayerPacketView incoming) {
  auto subrate_req = model::packets::LlSubrateReqView::Create(incoming);
  ASSERT(subrate_req.IsValid());
  ASSERT(connection.role == bluetooth::hci::Role::CENTRAL);

  LeAclSubrateParameters subrate_parameters = connection.subrate_parameters;
  uint16_t subrate_factor_min = subrate_req.GetSubrateFactorMin();
  uint16_t subrate_factor_max = subrate_req.GetSubrateFactorMax();
  uint16_t max_latency = subrate_req.GetMaxLatency();
  uint16_t continuation_number = subrate_req.GetContinuationNumber();
  uint16_t timeout = subrate_req.GetTimeout();

  ErrorCode status = ErrorCode::SUCCESS;

  // Validate parameters according to the rules set in
  // section 5.1.20. Connection Subrate Request procedure.
  if (subrate_factor_max < subrate_parameters.subrate_min ||
      subrate_factor_min > subrate_parameters.subrate_max) {
    INFO(id_, "rejecting LL_Subrate_Req because of incompatible subrate_factor requirement");
    status = ErrorCode::INVALID_LMP_OR_LL_PARAMETERS;
  }

  if (max_latency > subrate_parameters.max_latency) {
    INFO(id_, "rejecting LL_Subrate_Req because of incompatible max_latency requirement");
    status = ErrorCode::INVALID_LMP_OR_LL_PARAMETERS;
  }

  if (timeout > subrate_parameters.supervision_timeout) {
    INFO(id_, "rejecting LL_Subrate_Req because of incompatible timeout requirement");
    status = ErrorCode::INVALID_LMP_OR_LL_PARAMETERS;
  }

  if (max_latency > subrate_parameters.max_latency) {
    INFO(id_, "rejecting LL_Subrate_Req because of incompatible max_latency requirement");
    status = ErrorCode::INVALID_LMP_OR_LL_PARAMETERS;
  }

  if (connection.parameters.conn_interval * subrate_factor_min * (max_latency + 1) * 2 < timeout) {
    INFO(id_, "rejecting LL_Subrate_Req because of incompatible timeout requirement");
    status = ErrorCode::INVALID_LMP_OR_LL_PARAMETERS;
  }

  if (status != ErrorCode::SUCCESS) {
    SendLeLinkLayerPacket(LlSubrateIndBuilder::Create(connection.own_address.GetAddress(),
                                                      connection.address.GetAddress(),
                                                      static_cast<uint8_t>(status), 0, 0, 0, 0, 0));
    return;
  }

  // If the Central accepts the Peripheral’s request, then the new connSubrateFactor shall be
  // between Subrate_Min_acc and Subrate_Max_acc and shall also be between SubrateFactorMin_req and
  // SubrateFactorMax_req.
  uint16_t subrate_factor = std::min(subrate_factor_max, subrate_parameters.subrate_max);

  // If the Central accepts the Peripheral’s request, then the new connContinuationNumber shall
  // equal
  //  min(max(Continuation_Number_acc, ContinuationNumber_req), (new connSubrateFactor) - 1).
  continuation_number =
          std::min<uint16_t>(std::max(continuation_number, subrate_parameters.continuation_number),
                             subrate_factor - 1);

  // If the Central accepts the Peripheral’s request, then the new connPeripheralLatency shall be
  // less than or equal to min(Max_Latency_req, Max_Latency_acc),
  uint16_t perihperal_latency = std::min(max_latency, subrate_parameters.max_latency);

  // If the Central accepts the Peripheral’s request, then the new connSupervisionTimeout shall
  // equal min(Timeout_req, Supervision_Timeout_acc).
  uint16_t supervision_timeout = std::min(timeout, subrate_parameters.supervision_timeout);

  // Update the local connection parameters.
  connection.parameters.conn_subrate_factor = subrate_factor;
  connection.parameters.conn_continuation_number = continuation_number;
  connection.parameters.conn_peripheral_latency = perihperal_latency;
  connection.parameters.conn_supervision_timeout = supervision_timeout;

  if (IsLeEventUnmasked(SubeventCode::LE_SUBRATE_CHANGE)) {
    ScheduleTask(kNoDelayMs, [=, this]() {
      send_event_(bluetooth::hci::LeSubrateChangeBuilder::Create(
              ErrorCode::SUCCESS, connection.handle, subrate_factor, perihperal_latency,
              continuation_number, supervision_timeout));
    });
  }

  SendLeLinkLayerPacket(LlSubrateIndBuilder::Create(
          connection.own_address.GetAddress(), connection.address.GetAddress(),
          static_cast<uint8_t>(status), subrate_factor, /* subrate_base_event */ 0,
          perihperal_latency, continuation_number, supervision_timeout));
}

void LeController::IncomingLlSubrateInd(LeAclConnection& connection,
                                        model::packets::LinkLayerPacketView incoming) {
  auto subrate_ind = model::packets::LlSubrateIndView::Create(incoming);
  ASSERT(subrate_ind.IsValid());
  ASSERT(connection.role == bluetooth::hci::Role::PERIPHERAL);

  uint16_t subrate_factor = subrate_ind.GetSubrateFactor();
  uint16_t latency = subrate_ind.GetLatency();
  uint16_t continuation_number = subrate_ind.GetContinuationNumber();
  uint16_t timeout = subrate_ind.GetTimeout();
  ErrorCode status = static_cast<ErrorCode>(subrate_ind.GetStatus());

  if (status == ErrorCode::SUCCESS) {
    // Update the local connection parameters on success.
    connection.parameters.conn_subrate_factor = subrate_factor;
    connection.parameters.conn_continuation_number = continuation_number;
    connection.parameters.conn_peripheral_latency = latency;
    connection.parameters.conn_supervision_timeout = timeout;
  }

  if (IsLeEventUnmasked(SubeventCode::LE_SUBRATE_CHANGE)) {
    ScheduleTask(kNoDelayMs, [=, this]() {
      send_event_(bluetooth::hci::LeSubrateChangeBuilder::Create(
              status, connection.handle, subrate_factor, latency, continuation_number, timeout));
    });
  }
}

void LeController::SetSecureSimplePairingSupport(bool enable) {
  uint64_t bit = 0x1;
  secure_simple_pairing_host_support_ = enable;
  if (enable) {
    host_supported_features_ |= bit;
  } else {
    host_supported_features_ &= ~bit;
  }
}

void LeController::SetLeHostSupport(bool enable) {
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

void LeController::SetSecureConnectionsSupport(bool enable) {
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

LeController::LeController(const Address& address, const ControllerProperties& properties,
                           uint32_t id)
    : id_(id), address_(address), properties_(properties), ll_(nullptr, link_layer_destroy) {
  if (properties_.quirks.has_default_random_address) {
    WARNING(id_, "Configuring a default random address for this controller");
    random_address_ = Address{0xba, 0xdb, 0xad, 0xba, 0xdb, 0xad};
  }

  controller_ops_ = {
          .user_pointer = this,
          .get_handle =
                  [](void* user, const uint8_t (*address)[6]) {
                    auto controller = static_cast<LeController*>(user);

                    // Returns the connection handle but only for established
                    // BR-EDR connections.
                    return controller->connections_.GetAclConnectionHandle(Address(*address))
                            .value_or(-1);
                  },

          .get_address =
                  [](void* user, uint16_t handle, uint8_t (*result)[6]) {
                    auto controller = static_cast<LeController*>(user);
                    Address address = {};

                    if (controller->connections_.HasLeAclHandle(handle)) {
                      address = controller->connections_.GetLeAclConnection(handle)
                                        .address.GetAddress();
                    }

                    std::copy(address.data(), address.data() + 6,
                              reinterpret_cast<uint8_t*>(result));
                  },

          .get_le_features =
                  [](void* user) {
                    auto controller = static_cast<LeController*>(user);
                    return controller->GetLeSupportedFeatures();
                  },

          .get_le_event_mask =
                  [](void* user) {
                    auto controller = static_cast<LeController*>(user);
                    return controller->le_event_mask_;
                  },

          .send_hci_event =
                  [](void* user, const uint8_t* data, uintptr_t len) {
                    auto controller = static_cast<LeController*>(user);

                    auto event_code = static_cast<EventCode>(data[0]);
                    controller->send_event_(bluetooth::hci::EventBuilder::Create(
                            event_code, std::vector(data + 2, data + len)));
                  },

          .send_llcp_packet =
                  [](void* user, uint16_t acl_connection_handle, const uint8_t* data,
                     uintptr_t len) {
                    auto controller = static_cast<LeController*>(user);

                    if (!controller->connections_.HasLeAclHandle(acl_connection_handle)) {
                      ERROR("Dropping LLCP packet sent for unknown connection handle "
                            "0x{:x}",
                            acl_connection_handle);
                      return;
                    }

                    LeAclConnection const& connection =
                            controller->connections_.GetLeAclConnection(acl_connection_handle);
                    Address source = connection.own_address.GetAddress();
                    Address destination = connection.address.GetAddress();

                    controller->SendLeLinkLayerPacket(model::packets::LlcpBuilder::Create(
                            source, destination, std::vector(data, data + len)));
                  }};

  ll_.reset(link_layer_create(controller_ops_));
}

LeController::~LeController() {}

void LeController::SendLeLinkLayerPacket(
        std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet, int8_t tx_power) {
  std::shared_ptr<model::packets::LinkLayerPacketBuilder> shared_packet = std::move(packet);
  ScheduleTask(kNoDelayMs, [this, shared_packet, tx_power]() {
    send_to_remote_(shared_packet, Phy::Type::LOW_ENERGY, tx_power);
  });
}

ErrorCode LeController::LeReadRemoteFeaturesPage0(uint16_t connection_handle) {
  if (!connections_.HasLeAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto const& connection = connections_.GetLeAclConnection(connection_handle);
  SendLeLinkLayerPacket(model::packets::LeReadRemoteFeaturesBuilder::Create(
          connection.own_address.GetAddress(), connection.address.GetAddress()));

  return ErrorCode::SUCCESS;
}

void LeController::IncomingPacket(model::packets::LinkLayerPacketView incoming, int8_t rssi) {
  ASSERT(incoming.IsValid());
  auto destination_address = incoming.GetDestinationAddress();
  auto source_address = incoming.GetSourceAddress();

  // Handle connection-less packet types.
  // Whether the packet needs to be handled by this controller instance is decided
  // by the current controller state.
  switch (incoming.GetType()) {
    case model::packets::PacketType::LE_SCAN:
      return IncomingLeScanPacket(incoming);
    case model::packets::PacketType::LE_SCAN_RESPONSE:
      return IncomingLeScanResponsePacket(incoming, rssi);
    case model::packets::PacketType::LE_LEGACY_ADVERTISING_PDU:
      return IncomingLeLegacyAdvertisingPdu(incoming, rssi);
    case model::packets::PacketType::LE_EXTENDED_ADVERTISING_PDU:
      return IncomingLeExtendedAdvertisingPdu(incoming, rssi);
    case model::packets::PacketType::LE_PERIODIC_ADVERTISING_PDU:
      return IncomingLePeriodicAdvertisingPdu(incoming, rssi);
    case model::packets::PacketType::LE_CONNECT:
      return IncomingLeConnectPacket(incoming);
    case model::packets::PacketType::LE_CONNECT_COMPLETE:
      return IncomingLeConnectCompletePacket(incoming);
    default:
      break;
  }

  // Verify the existence of an LE-ACL connection with the proper source and
  // destination addresses.
  auto connection_handle =
          connections_.GetLeAclConnectionHandle(destination_address, source_address);
  if (!connection_handle.has_value()) {
    DEBUG(id_, "[LL] {} | Dropping {} packet not addressed to me {}->{}", address_,
          PacketTypeText(incoming.GetType()), source_address, destination_address);
    return;
  }

  // Update link timeout for valid ACL connections
  auto& connection = connections_.GetLeAclConnection(*connection_handle);
  connection.ResetLinkTimer();

  switch (incoming.GetType()) {
    case model::packets::PacketType::ACL:
      IncomingLeAclPacket(connection, incoming, rssi);
      break;
    case model::packets::PacketType::LE_CONNECTED_ISOCHRONOUS_PDU:
      IncomingLeConnectedIsochronousPdu(incoming);
      break;
    case model::packets::PacketType::DISCONNECT:
      IncomingLeDisconnectPacket(connection, incoming);
      break;
    case model::packets::PacketType::LLCP:
      IncomingLlcpPacket(incoming);
      break;
    case model::packets::PacketType::LE_CONNECTION_PARAMETER_REQUEST:
      IncomingLeConnectionParameterRequest(connection, incoming);
      break;
    case model::packets::PacketType::LE_CONNECTION_PARAMETER_UPDATE:
      IncomingLeConnectionParameterUpdate(connection, incoming);
      break;
    case model::packets::PacketType::LE_ENCRYPT_CONNECTION:
      IncomingLeEncryptConnection(connection, incoming);
      break;
    case model::packets::PacketType::LE_ENCRYPT_CONNECTION_RESPONSE:
      IncomingLeEncryptConnectionResponse(connection, incoming);
      break;
    case (model::packets::PacketType::LE_READ_REMOTE_FEATURES):
      IncomingLeReadRemoteFeatures(connection, incoming);
      break;
    case (model::packets::PacketType::LE_READ_REMOTE_FEATURES_RESPONSE):
      IncomingLeReadRemoteFeaturesResponse(connection, incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_VERSION_INFORMATION:
      IncomingReadRemoteVersion(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_VERSION_INFORMATION_RESPONSE:
      IncomingReadRemoteVersionResponse(incoming);
      break;
    case model::packets::PacketType::PING_REQUEST:
      IncomingPingRequest(incoming);
      break;
    case model::packets::PacketType::PING_RESPONSE:
      // ping responses require no action
      break;
    case model::packets::PacketType::LL_PHY_REQ:
      IncomingLlPhyReq(connection, incoming);
      break;
    case model::packets::PacketType::LL_PHY_RSP:
      IncomingLlPhyRsp(connection, incoming);
      break;
    case model::packets::PacketType::LL_PHY_UPDATE_IND:
      IncomingLlPhyUpdateInd(connection, incoming);
      break;
    case model::packets::PacketType::LL_SUBRATE_REQ:
      IncomingLlSubrateReq(connection, incoming);
      break;
    case model::packets::PacketType::LL_SUBRATE_IND:
      IncomingLlSubrateInd(connection, incoming);
      break;
    default:
      WARNING(id_, "Dropping unhandled packet of type {}",
              model::packets::PacketTypeText(incoming.GetType()));
  }
}

void LeController::IncomingLeAclPacket(LeAclConnection& connection,
                                       model::packets::LinkLayerPacketView incoming, int8_t rssi) {
  auto acl = model::packets::AclView::Create(incoming);
  ASSERT(acl.IsValid());

  auto acl_data = acl.GetData();
  auto packet_boundary_flag = bluetooth::hci::PacketBoundaryFlag(acl.GetPacketBoundaryFlag());
  auto broadcast_flag = bluetooth::hci::BroadcastFlag(acl.GetBroadcastFlag());

  if (packet_boundary_flag ==
      bluetooth::hci::PacketBoundaryFlag::FIRST_NON_AUTOMATICALLY_FLUSHABLE) {
    packet_boundary_flag = bluetooth::hci::PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
  }

  INFO(id_, "LE-ACL Packet [{}] {} -> {}", acl_data.size(), incoming.GetSourceAddress(),
       incoming.GetDestinationAddress());

  // Update the RSSI for the local ACL connection.
  connection.SetRssi(rssi);

  send_acl_(bluetooth::hci::AclBuilder::Create(
          connection.handle, packet_boundary_flag, broadcast_flag,
          std::vector<uint8_t>(acl_data.begin(), acl_data.end())));
}

void LeController::IncomingReadRemoteVersion(model::packets::LinkLayerPacketView incoming) {
  SendLeLinkLayerPacket(model::packets::ReadRemoteVersionInformationResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
          static_cast<uint8_t>(properties_.lmp_version),
          static_cast<uint16_t>(properties_.lmp_subversion), properties_.company_identifier));
}

void LeController::IncomingReadRemoteVersionResponse(model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadRemoteVersionInformationResponseView::Create(incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();
  Address destination = incoming.GetDestinationAddress();

  auto handle = connections_.GetLeAclConnectionHandle(destination, source);

  if (!handle.has_value()) {
    INFO(id_, "Discarding response from a disconnected device {}", source);
    return;
  }

  if (IsEventUnmasked(EventCode::READ_REMOTE_VERSION_INFORMATION_COMPLETE)) {
    send_event_(bluetooth::hci::ReadRemoteVersionInformationCompleteBuilder::Create(
            ErrorCode::SUCCESS, *handle, view.GetLmpVersion(), view.GetManufacturerName(),
            view.GetLmpSubversion()));
  }
}

void LeController::IncomingLeDisconnectPacket(LeAclConnection& connection,
                                              model::packets::LinkLayerPacketView incoming) {
  INFO(id_, "Disconnect Packet");
  auto disconnect = model::packets::DisconnectView::Create(incoming);
  ASSERT(disconnect.IsValid());

  // /!\ The connection reference becomes invalid after it is removed from the
  //     connection handler.
  uint16_t connection_handle = connection.handle;
  ASSERT_LOG(connections_.Disconnect(connection_handle,
                                     [this](TaskId task_id) { CancelScheduledTask(task_id); }),
             "GetHandle() returned invalid handle 0x{:x}", connection_handle);

  uint8_t reason = disconnect.GetReason();
  // Will optionally notify CIS disconnections.
  ASSERT(link_layer_remove_link(ll_.get(), connection_handle, reason));
  SendDisconnectionCompleteEvent(connection_handle, ErrorCode(reason));
}

Address LeController::generate_rpa(std::array<uint8_t, LeController::kIrkSize> irk) {
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
  rootcanal::crypto::Octet16 p = rootcanal::crypto::aes_128(irk, prand.data(), 3);

  /* set hash to be LSB of rpAddress */
  rpa.address[0] = p[0];
  rpa.address[1] = p[1];
  rpa.address[2] = p[2];
  INFO("RPA {}", rpa);
  return rpa;
}

bool LeController::irk_is_zero(std::array<uint8_t, LeController::kIrkSize> irk) {
  return std::all_of(irk.begin(), irk.end(), [](uint8_t b) { return b == 0; });
}

// Handle legacy advertising PDUs while in the Scanning state.
void LeController::ScanIncomingLeLegacyAdvertisingPdu(
        model::packets::LeLegacyAdvertisingPduView& pdu, uint8_t rssi) {
  if (!scanner_.IsEnabled()) {
    return;
  }

  auto advertising_type = pdu.GetAdvertisingType();
  std::vector<uint8_t> advertising_data = pdu.GetAdvertisingData();

  AddressWithType advertising_address{pdu.GetSourceAddress(),
                                      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};

  AddressWithType target_address{pdu.GetDestinationAddress(),
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
    case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY:
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
      case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY:
        if (!IsLocalPublicOrRandomAddress(target_address) && !target_address.IsRpa()) {
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
  if (scanner_.filter_duplicates != bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(pdu.bytes())) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(pdu.bytes());
    }
  }

  // Legacy scanning, directed advertising.
  if (LegacyAdvertising() && should_send_advertising_report &&
      should_send_directed_advertising_report &&
      IsLeEventUnmasked(SubeventCode::LE_DIRECTED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeDirectedAdvertisingResponse response;
    response.event_type_ = bluetooth::hci::DirectAdvertisingEventType::ADV_DIRECT_IND;
    response.address_type_ = static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
            resolved_advertising_address.GetAddressType());
    response.address_ = resolved_advertising_address.GetAddress();
    response.direct_address_type_ = bluetooth::hci::DirectAddressType::RANDOM_DEVICE_ADDRESS;
    response.direct_address_ = target_address.GetAddress();
    response.rssi_ = rssi;

    send_event_(bluetooth::hci::LeDirectedAdvertisingReportBuilder::Create({response}));
  }

  // Legacy scanning, un-directed advertising.
  if (LegacyAdvertising() && should_send_advertising_report &&
      !should_send_directed_advertising_report &&
      IsLeEventUnmasked(SubeventCode::LE_ADVERTISING_REPORT)) {
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
        response.event_type_ = bluetooth::hci::AdvertisingEventType::ADV_DIRECT_IND;
        break;
      case model::packets::LegacyAdvertisingType::ADV_SCAN_IND:
        response.event_type_ = bluetooth::hci::AdvertisingEventType::ADV_SCAN_IND;
        break;
      case model::packets::LegacyAdvertisingType::ADV_NONCONN_IND:
        response.event_type_ = bluetooth::hci::AdvertisingEventType::ADV_NONCONN_IND;
        break;
    }

    send_event_(bluetooth::hci::LeAdvertisingReportBuilder::Create({response}));
  }

  // Extended scanning.
  if (ExtendedAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::LE_EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponse response;
    response.connectable_ = connectable_advertising;
    response.scannable_ = scannable_advertising;
    response.directed_ = directed_advertising;
    response.scan_response_ = false;
    response.legacy_ = true;
    response.data_status_ = bluetooth::hci::DataStatus::COMPLETE;
    response.address_type_ = static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
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
              bluetooth::hci::DirectAdvertisingAddressType(target_address.GetAddressType());
      response.direct_address_ = target_address.GetAddress();
    } else {
      response.direct_address_type_ =
              bluetooth::hci::DirectAdvertisingAddressType::NO_ADDRESS_PROVIDED;
      response.direct_address_ = Address::kEmpty;
    }
    response.advertising_data_ = advertising_data;

    send_event_(bluetooth::hci::LeExtendedAdvertisingReportBuilder::Create({response}));
  }

  // Did the user enable Active scanning ?
  bool active_scanning = (scanner_.le_1m_phy.enabled &&
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

    AddressWithType public_address{address_, AddressType::PUBLIC_DEVICE_ADDRESS};
    AddressWithType random_address{random_address_, AddressType::RANDOM_DEVICE_ADDRESS};
    std::optional<AddressWithType> resolvable_scanning_address =
            GenerateResolvablePrivateAddress(resolved_advertising_address, IrkSelection::Local);

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
    scanner_.primary_scan_response_phy = model::packets::PhyType::LE_1M;
    scanner_.secondary_scan_response_phy = model::packets::PhyType::NO_PACKETS;
    scanner_.pending_scan_request = advertising_address;
    scanner_.pending_scan_request_timeout = std::chrono::steady_clock::now() + kScanRequestTimeout;

    INFO(id_,
         "Sending LE Scan request to advertising address {} with scanning "
         "address {}",
         advertising_address, scanning_address);

    // The advertiser’s device address (AdvA field) in the scan request PDU
    // shall be the same as the advertiser’s device address (AdvA field)
    // received in the advertising PDU to which the scanner is responding.
    SendLeLinkLayerPacket(model::packets::LeScanBuilder::Create(
            scanning_address.GetAddress(), advertising_address.GetAddress(),
            static_cast<model::packets::AddressType>(scanning_address.GetAddressType()),
            static_cast<model::packets::AddressType>(advertising_address.GetAddressType())));
  }
}

void LeController::ConnectIncomingLeLegacyAdvertisingPdu(
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

  AddressWithType advertising_address{pdu.GetSourceAddress(),
                                      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};

  AddressWithType target_address{pdu.GetDestinationAddress(),
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
    case bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST_WITH_PEER_ADDRESS:
      if (!LeFilterAcceptListContainsDevice(resolved_advertising_address)) {
        DEBUG(id_,
              "Legacy advertising ignored by initiator because the "
              "advertising address {} is not in the filter accept list",
              resolved_advertising_address);
        return;
      }
      break;
    case bluetooth::hci::InitiatorFilterPolicy::USE_DECISION_PDUS:
    case bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST_WITH_DECISION_PDUS:
      DEBUG(id_,
            "Legacy advertising ignored by initiated because the "
            "initiator filter policy is unsupported");
      return;
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
        (initiator_.own_address_type == OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS ||
         initiator_.own_address_type == OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS)) {
      DEBUG(id_,
            "Directed legacy advertising ignored by initiator because the "
            "target address {} is static or public and the initiator is "
            "configured to use resolvable addresses",
            target_address);
      return;
    }
  }

  AddressWithType public_address{address_, AddressType::PUBLIC_DEVICE_ADDRESS};
  AddressWithType random_address{random_address_, AddressType::RANDOM_DEVICE_ADDRESS};
  std::optional<AddressWithType> resolvable_initiating_address =
          GenerateResolvablePrivateAddress(resolved_advertising_address, IrkSelection::Local);

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
      initiating_address = resolvable_initiating_address.value_or(public_address);
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
      // The random address is checked in Le_Create_Connection or
      // Le_Extended_Create_Connection.
      ASSERT(random_address_ != Address::kEmpty);
      initiating_address = resolvable_initiating_address.value_or(random_address);
      break;
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
          static_cast<model::packets::AddressType>(initiating_address.GetAddressType()),
          static_cast<model::packets::AddressType>(advertising_address.GetAddressType()),
          // The connection is created with the highest allowed
          // value for the connection interval and the latency.
          initiator_.le_1m_phy.connection_interval_max, initiator_.le_1m_phy.max_latency,
          initiator_.le_1m_phy.supervision_timeout));
}

void LeController::IncomingLeLegacyAdvertisingPdu(model::packets::LinkLayerPacketView incoming,
                                                  uint8_t rssi) {
  auto pdu = model::packets::LeLegacyAdvertisingPduView::Create(incoming);
  ASSERT(pdu.IsValid());

  ScanIncomingLeLegacyAdvertisingPdu(pdu, rssi);
  ConnectIncomingLeLegacyAdvertisingPdu(pdu);
}

// Handle legacy advertising PDUs while in the Scanning state.
void LeController::ScanIncomingLeExtendedAdvertisingPdu(
        model::packets::LeExtendedAdvertisingPduView& pdu, uint8_t rssi) {
  if (!scanner_.IsEnabled()) {
    return;
  }
  if (!ExtendedAdvertising()) {
    DEBUG(id_, "Extended advertising ignored because the scanner is legacy");
    return;
  }

  std::vector<uint8_t> advertising_data = pdu.GetAdvertisingData();
  AddressWithType advertising_address{pdu.GetSourceAddress(),
                                      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};

  AddressWithType target_address{pdu.GetDestinationAddress(),
                                 static_cast<AddressType>(pdu.GetTargetAddressType())};

  bool scannable_advertising = pdu.GetScannable();
  bool connectable_advertising = pdu.GetConnectable();
  bool directed_advertising = pdu.GetDirected();
  auto primary_phy = pdu.GetPrimaryPhy();
  auto secondary_phy = pdu.GetSecondaryPhy();

  // Check originating primary PHY, compare against active scanning PHYs.
  if ((primary_phy == model::packets::PhyType::LE_1M && !scanner_.le_1m_phy.enabled) ||
      (primary_phy == model::packets::PhyType::LE_CODED_S8 && !scanner_.le_coded_phy.enabled)) {
    DEBUG(id_,
          "Extended adverising ignored because the scanner is not scanning on "
          "the primary phy type {}",
          model::packets::PhyTypeText(primary_phy));
    return;
  }

  // Check originating sceondary PHY, compare against local
  // supported features. The primary PHY is validated by the command
  // LE Set Extended Scan Parameters.
  if ((secondary_phy == model::packets::PhyType::LE_2M &&
       !properties_.SupportsLLFeature(bluetooth::hci::LLFeaturesBits::LE_2M_PHY)) ||
      (secondary_phy == model::packets::PhyType::LE_CODED_S8 &&
       !properties_.SupportsLLFeature(bluetooth::hci::LLFeaturesBits::LE_CODED_PHY)) ||
      (secondary_phy == model::packets::PhyType::LE_CODED_S2 &&
       !properties_.SupportsLLFeature(bluetooth::hci::LLFeaturesBits::LE_CODED_PHY))) {
    DEBUG(id_,
          "Extended adverising ignored because the scanner does not support "
          "the secondary phy type {}",
          model::packets::PhyTypeText(secondary_phy));
    return;
  }

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
          bluetooth::hci::AddressTypeText(resolved_advertising_address.GetAddressType()));
  }

  // Vol 6, Part B § 4.3.3 Scanner filter policy
  switch (scanner_.scan_filter_policy) {
    case bluetooth::hci::LeScanningFilterPolicy::ACCEPT_ALL:
    case bluetooth::hci::LeScanningFilterPolicy::CHECK_INITIATORS_IDENTITY:
      break;
    case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_ONLY:
    case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY:
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
      case bluetooth::hci::LeScanningFilterPolicy::FILTER_ACCEPT_LIST_AND_INITIATORS_IDENTITY:
        if (!IsLocalPublicOrRandomAddress(target_address) && !target_address.IsRpa()) {
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
  if (scanner_.filter_duplicates != bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(pdu.bytes())) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(pdu.bytes());
    }
  }

  if (should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::LE_EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponse response;
    response.connectable_ = connectable_advertising;
    response.scannable_ = scannable_advertising;
    response.directed_ = directed_advertising;
    response.scan_response_ = false;
    response.legacy_ = false;
    response.data_status_ = bluetooth::hci::DataStatus::COMPLETE;
    response.address_type_ = static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
            resolved_advertising_address.GetAddressType());
    response.address_ = resolved_advertising_address.GetAddress();
    response.primary_phy_ = static_cast<bluetooth::hci::PrimaryPhyType>(primary_phy);
    response.secondary_phy_ = static_cast<bluetooth::hci::SecondaryPhyType>(secondary_phy);
    response.advertising_sid_ = pdu.GetSid();
    response.tx_power_ = pdu.GetTxPower();
    response.rssi_ = rssi;
    response.periodic_advertising_interval_ = pdu.GetPeriodicAdvertisingInterval();
    if (directed_advertising) {
      response.direct_address_type_ =
              bluetooth::hci::DirectAdvertisingAddressType(target_address.GetAddressType());
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
      response.advertising_data_ = std::vector(advertising_data.begin() + offset,
                                               advertising_data.begin() + offset + fragment_size);
      offset += fragment_size;
      send_event_(bluetooth::hci::LeExtendedAdvertisingReportBuilder::Create({response}));
    } while (offset < advertising_data.size());
  }

  // Did the user enable Active scanning ?
  bool active_scanning = (scanner_.le_1m_phy.enabled &&
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

    AddressWithType public_address{address_, AddressType::PUBLIC_DEVICE_ADDRESS};
    AddressWithType random_address{random_address_, AddressType::RANDOM_DEVICE_ADDRESS};
    std::optional<AddressWithType> resolvable_address =
            GenerateResolvablePrivateAddress(resolved_advertising_address, IrkSelection::Local);

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
    scanner_.primary_scan_response_phy = primary_phy;
    scanner_.secondary_scan_response_phy = secondary_phy;
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
            static_cast<model::packets::AddressType>(scanning_address.GetAddressType()),
            static_cast<model::packets::AddressType>(advertising_address.GetAddressType())));
  }
}

void LeController::ConnectIncomingLeExtendedAdvertisingPdu(
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
    DEBUG(id_,
          "Extended advertising ignored because an LE Connect request is already "
          "pending");
    return;
  }

  AddressWithType advertising_address{pdu.GetSourceAddress(),
                                      static_cast<AddressType>(pdu.GetAdvertisingAddressType())};

  AddressWithType target_address{pdu.GetDestinationAddress(),
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
    case bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST_WITH_PEER_ADDRESS:
      if (!LeFilterAcceptListContainsDevice(resolved_advertising_address)) {
        DEBUG(id_,
              "Extended advertising ignored by initiator because the "
              "advertising address {} is not in the filter accept list",
              resolved_advertising_address);
        return;
      }
      break;
    case bluetooth::hci::InitiatorFilterPolicy::USE_DECISION_PDUS:
    case bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST_WITH_DECISION_PDUS:
      DEBUG(id_,
            "Extended advertising ignored by initiator because the "
            "initiator filter policy is not supported");
      return;
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
        (initiator_.own_address_type == OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS ||
         initiator_.own_address_type == OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS)) {
      DEBUG(id_,
            "Directed extended advertising ignored by initiator because the "
            "target address {} is static or public and the initiator is "
            "configured to use resolvable addresses",
            target_address);
      return;
    }
  }

  AddressWithType public_address{address_, AddressType::PUBLIC_DEVICE_ADDRESS};
  AddressWithType random_address{random_address_, AddressType::RANDOM_DEVICE_ADDRESS};
  std::optional<AddressWithType> resolvable_initiating_address =
          GenerateResolvablePrivateAddress(resolved_advertising_address, IrkSelection::Local);

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
      initiating_address = resolvable_initiating_address.value_or(public_address);
      break;
    case bluetooth::hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS:
      // The random address is checked in Le_Create_Connection or
      // Le_Extended_Create_Connection.
      ASSERT(random_address_ != Address::kEmpty);
      initiating_address = resolvable_initiating_address.value_or(random_address);
      break;
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
          static_cast<model::packets::AddressType>(initiating_address.GetAddressType()),
          static_cast<model::packets::AddressType>(advertising_address.GetAddressType()),
          // The connection is created with the highest allowed value
          // for the connection interval and the latency.
          initiator_.le_1m_phy.connection_interval_max, initiator_.le_1m_phy.max_latency,
          initiator_.le_1m_phy.supervision_timeout));
}

void LeController::IncomingLeExtendedAdvertisingPdu(model::packets::LinkLayerPacketView incoming,
                                                    uint8_t rssi) {
  auto pdu = model::packets::LeExtendedAdvertisingPduView::Create(incoming);
  ASSERT(pdu.IsValid());

  ScanIncomingLeExtendedAdvertisingPdu(pdu, rssi);
  ConnectIncomingLeExtendedAdvertisingPdu(pdu);
}

void LeController::IncomingLePeriodicAdvertisingPdu(model::packets::LinkLayerPacketView incoming,
                                                    uint8_t rssi) {
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

  AddressWithType advertiser_address{pdu.GetSourceAddress(),
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
      advertiser_address_type =
              bluetooth::hci::AdvertiserAddressType::PUBLIC_DEVICE_OR_IDENTITY_ADDRESS;
      break;
    case AddressType::RANDOM_DEVICE_ADDRESS:
    case AddressType::RANDOM_IDENTITY_ADDRESS:
      advertiser_address_type =
              bluetooth::hci::AdvertiserAddressType::RANDOM_DEVICE_OR_IDENTITY_ADDRESS;
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
                              advertiser_address_type, resolved_advertiser_address.GetAddress(),
                              advertising_sid)
                    : synchronizing_->advertiser_address_type == advertiser_address_type &&
                              synchronizing_->advertiser_address ==
                                      resolved_advertiser_address.GetAddress() &&
                              synchronizing_->advertising_sid == advertising_sid;
  }

  // If the periodic advertising event matches the synchronizing state,
  // create the synchronized train and report to the Host.
  if (matches_synchronizing) {
    INFO(id_, "Established Sync with advertiser {}[{}] - SID 0x{:x}", advertiser_address,
         bluetooth::hci::AdvertiserAddressTypeText(advertiser_address_type), advertising_sid);
    // Use the first unused Sync_Handle.
    // Note: sync handles are allocated from a different number space
    // compared to connection handles.
    uint16_t sync_handle = 0;
    for (; synchronized_.count(sync_handle) != 0; sync_handle++) {
    }

    // Notify of the new Synchronized train.
    if (IsLeEventUnmasked(SubeventCode::LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V1)) {
      send_event_(bluetooth::hci::LePeriodicAdvertisingSyncEstablishedV1Builder::Create(
              ErrorCode::SUCCESS, sync_handle, advertising_sid,
              resolved_advertiser_address.GetAddressType(),
              resolved_advertiser_address.GetAddress(), bluetooth::hci::SecondaryPhyType::LE_1M,
              pdu.GetAdvertisingInterval(), bluetooth::hci::ClockAccuracy::PPM_500));
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
                     .timeout = std::chrono::steady_clock::now() + synchronizing_->sync_timeout,
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
    if (IsLeEventUnmasked(SubeventCode::LE_PERIODIC_ADVERTISING_REPORT_V1)) {
      // Each extended advertising report can only pass 229 bytes of
      // advertising data (255 - 8 = size of report fields).
      std::vector<uint8_t> advertising_data = pdu.GetAdvertisingData();
      const size_t max_fragment_size = 247;
      size_t offset = 0;
      do {
        size_t remaining_size = advertising_data.size() - offset;
        size_t fragment_size = std::min(max_fragment_size, remaining_size);

        bluetooth::hci::DataStatus data_status = remaining_size <= max_fragment_size
                                                         ? bluetooth::hci::DataStatus::COMPLETE
                                                         : bluetooth::hci::DataStatus::CONTINUING;
        std::vector<uint8_t> fragment_data(advertising_data.begin() + offset,
                                           advertising_data.begin() + offset + fragment_size);
        offset += fragment_size;
        send_event_(bluetooth::hci::LePeriodicAdvertisingReportV1Builder::Create(
                sync.sync_handle, pdu.GetTxPower(), rssi,
                bluetooth::hci::CteType::NO_CONSTANT_TONE_EXTENSION, data_status, fragment_data));
      } while (offset < advertising_data.size());
    }

    // Refresh the timeout for the sync disconnection.
    sync.timeout = std::chrono::steady_clock::now() + sync.sync_timeout;
  }
}

void LeController::IncomingLlcpPacket(model::packets::LinkLayerPacketView incoming) {
  Address source = incoming.GetSourceAddress();
  Address destination = incoming.GetDestinationAddress();
  auto request = model::packets::LlcpView::Create(incoming);
  ASSERT(request.IsValid());
  auto payload = request.GetPayload();
  auto packet = std::vector(payload.begin(), payload.end());
  auto acl_connection_handle = connections_.GetLeAclConnectionHandle(destination, source);

  if (!acl_connection_handle.has_value()) {
    INFO(id_, "Dropping LLCP packet since connection does not exist");
    return;
  }

  ASSERT(link_layer_ingest_llcp(ll_.get(), *acl_connection_handle, packet.data(), packet.size()));
}

void LeController::IncomingLeConnectedIsochronousPdu(LinkLayerPacketView incoming) {
  auto pdu = model::packets::LeConnectedIsochronousPduView::Create(incoming);
  ASSERT(pdu.IsValid());
  auto data = pdu.GetData();
  auto packet = std::vector(data.begin(), data.end());
  uint8_t cig_id = pdu.GetCigId();
  uint8_t cis_id = pdu.GetCisId();
  uint16_t cis_connection_handle = 0;
  uint16_t iso_sdu_length = packet.size();

  if (!link_layer_get_cis_connection_handle(ll_.get(), cig_id, cis_id, &cis_connection_handle)) {
    INFO(id_, "Dropping CIS pdu received on disconnected CIS cig_id={}, cis_id={}", cig_id, cis_id);
    return;
  }

  // Fragment the ISO SDU if larger than the maximum payload size (4095).
  constexpr size_t kMaxPayloadSize = 4095 - 4;  // remove sequence_number and
                                                // iso_sdu_length
  size_t remaining_size = packet.size();
  size_t offset = 0;
  auto packet_boundary_flag = remaining_size <= kMaxPayloadSize
                                      ? bluetooth::hci::IsoPacketBoundaryFlag::COMPLETE_SDU
                                      : bluetooth::hci::IsoPacketBoundaryFlag::FIRST_FRAGMENT;

  do {
    size_t fragment_size = std::min(kMaxPayloadSize, remaining_size);
    std::vector<uint8_t> fragment(packet.data() + offset, packet.data() + offset + fragment_size);

    send_iso_(bluetooth::hci::IsoWithoutTimestampBuilder::Create(
            cis_connection_handle, packet_boundary_flag, pdu.GetSequenceNumber(), iso_sdu_length,
            bluetooth::hci::IsoPacketStatusFlag::VALID, std::move(fragment)));

    remaining_size -= fragment_size;
    offset += fragment_size;
    packet_boundary_flag = remaining_size <= kMaxPayloadSize
                                   ? bluetooth::hci::IsoPacketBoundaryFlag::LAST_FRAGMENT
                                   : bluetooth::hci::IsoPacketBoundaryFlag::CONTINUATION_FRAGMENT;
  } while (remaining_size > 0);
}

void LeController::HandleAcl(bluetooth::hci::AclView acl) {
  uint16_t connection_handle = acl.GetHandle();
  auto pb_flag = acl.GetPacketBoundaryFlag();
  auto bc_flag = acl.GetBroadcastFlag();

  // TODO: Support Broadcast_Flag value of BR/EDR broadcast.
  if (bc_flag != bluetooth::hci::BroadcastFlag::POINT_TO_POINT) {
    FATAL("Received ACL HCI packet with Broadcast_flag set to unsupported value {}",
          static_cast<int>(bc_flag));
  }

  if (connections_.HasLeAclHandle(connection_handle)) {
    // LE-ACL connection.
    auto& connection = connections_.GetLeAclConnection(connection_handle);
    auto acl_payload = acl.GetPayload();
    auto acl_packet = model::packets::AclBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress(),
            static_cast<uint8_t>(pb_flag), static_cast<uint8_t>(bc_flag),
            std::vector(acl_payload.begin(), acl_payload.end()));
    SendLeLinkLayerPacket(std::move(acl_packet));

  } else {
    // ACL HCI packets received with an unknown or invalid Connection Handle
    // are silently dropped.
    DEBUG("Received ACL HCI packet with invalid ACL connection handle 0x{:x}", connection_handle);
  }

  // Send immediate acknowledgment for the ACL packet.
  // We don't really have a transmission queue in the controller.
  ScheduleTask(kNoDelayMs, [this, connection_handle]() {
    send_event_(bluetooth::hci::NumberOfCompletedPacketsBuilder::Create(
            {bluetooth::hci::CompletedPackets(connection_handle, 1)}));
  });
}

void LeController::HandleIso(bluetooth::hci::IsoView iso) {
  uint16_t cis_connection_handle = iso.GetConnectionHandle();
  auto pb_flag = iso.GetPbFlag();
  auto ts_flag = iso.GetTsFlag();
  auto iso_data_load = iso.GetPayload();

  ScheduleTask(kNoDelayMs, [this, cis_connection_handle]() {
    send_event_(bluetooth::hci::NumberOfCompletedPacketsBuilder::Create(
            {bluetooth::hci::CompletedPackets(cis_connection_handle, 1)}));
  });

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
      (pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::CONTINUATION_FRAGMENT ||
       pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::LAST_FRAGMENT)) {
    FATAL(id_,
          "Received ISO HCI packet with TS_Flag set, but no ISO Header is "
          "expected");
  }

  uint8_t cig_id = 0;
  uint8_t cis_id = 0;
  uint16_t acl_connection_handle = -1;
  uint16_t packet_sequence_number = 0;
  uint16_t max_sdu_length = 0;

  if (!link_layer_get_cis_information(ll_.get(), cis_connection_handle, &acl_connection_handle,
                                      &cig_id, &cis_id, &max_sdu_length)) {
    INFO(id_, "Ignoring CIS pdu received on disconnected CIS handle={}", cis_connection_handle);
    return;
  }

  if (!connections_.HasLeAclHandle(acl_connection_handle)) {
    ERROR(id_, "Invalid LE-ACL connection handle returned from ISO manager");
    return;
  }

  if (pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::FIRST_FRAGMENT ||
      pb_flag == bluetooth::hci::IsoPacketBoundaryFlag::COMPLETE_SDU) {
    iso_sdu_.clear();
  }

  switch (ts_flag) {
    case bluetooth::hci::TimeStampFlag::PRESENT: {
      auto iso_with_timestamp = bluetooth::hci::IsoWithTimestampView::Create(iso);
      ASSERT(iso_with_timestamp.IsValid());
      auto iso_payload = iso_with_timestamp.GetPayload();
      iso_sdu_.insert(iso_sdu_.end(), iso_payload.begin(), iso_payload.end());
      packet_sequence_number = iso_with_timestamp.GetPacketSequenceNumber();
      break;
    }
    default:
    case bluetooth::hci::TimeStampFlag::NOT_PRESENT: {
      auto iso_without_timestamp = bluetooth::hci::IsoWithoutTimestampView::Create(iso);
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
      WARNING(id_,
              "attempted to send an SDU of length {} that exceeds the configure "
              "Max_SDU_Length ({})",
              iso_sdu_.size(), max_sdu_length);
      return;
    }

    auto const& connection = connections_.GetLeAclConnection(acl_connection_handle);
    SendLeLinkLayerPacket(model::packets::LeConnectedIsochronousPduBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress(), cig_id, cis_id,
            packet_sequence_number, std::move(iso_sdu_)));
  }
}

uint16_t LeController::HandleLeConnection(AddressWithType address, AddressWithType resolved_address,
                                          AddressWithType own_address, bluetooth::hci::Role role,
                                          uint16_t connection_interval, uint16_t connection_latency,
                                          uint16_t supervision_timeout,
                                          bool send_le_channel_selection_algorithm_event) {
  // Note: the HCI_LE_Connection_Complete event is not sent if the
  // HCI_LE_Enhanced_Connection_Complete event (see Section 7.7.65.10) is
  // unmasked.

  INFO(id_, "Creating LE connection with peer {}|{} and local address {}", address,
       resolved_address, own_address);

  uint16_t handle = connections_.CreateLeConnection(
          address, resolved_address, own_address, role,
          LeAclConnectionParameters{.conn_interval = connection_interval,
                                    .conn_subrate_factor = 1,
                                    .conn_peripheral_latency = connection_latency,
                                    .conn_supervision_timeout = supervision_timeout},
          default_subrate_parameters_);

  if (IsLeEventUnmasked(SubeventCode::LE_ENHANCED_CONNECTION_COMPLETE_V1)) {
    AddressWithType peer_resolved_address = resolved_address;
    Address peer_resolvable_private_address;
    Address connection_address = address.GetAddress();
    AddressType peer_address_type = address.GetAddressType();
    if (peer_resolved_address != AddressWithType()) {
      peer_resolvable_private_address = address.GetAddress();
      peer_address_type = peer_resolved_address.GetAddressType();
      connection_address = peer_resolved_address.GetAddress();
    }
    Address local_resolved_address = own_address.GetAddress();
    if (local_resolved_address == GetAddress() || local_resolved_address == random_address_) {
      local_resolved_address = Address::kEmpty;
    }

    send_event_(bluetooth::hci::LeEnhancedConnectionCompleteV1Builder::Create(
            ErrorCode::SUCCESS, handle, role, peer_address_type, connection_address,
            local_resolved_address, peer_resolvable_private_address, connection_interval,
            connection_latency, supervision_timeout,
            static_cast<bluetooth::hci::ClockAccuracy>(0x00)));
  } else if (IsLeEventUnmasked(SubeventCode::LE_CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::LeConnectionCompleteBuilder::Create(
            ErrorCode::SUCCESS, handle, role, address.GetAddressType(), address.GetAddress(),
            connection_interval, connection_latency, supervision_timeout,
            static_cast<bluetooth::hci::ClockAccuracy>(0x00)));
  }

  // Update the link layer with the new link.
  ASSERT(link_layer_add_link(ll_.get(), handle,
                             reinterpret_cast<const uint8_t (*)[6]>(address.GetAddress().data()),
                             static_cast<uint8_t>(role)));

  // Note: the HCI_LE_Connection_Complete event is immediately followed by
  // an HCI_LE_Channel_Selection_Algorithm event if the connection is created
  // using the LE_Extended_Create_Connection command (see Section 7.7.8.66).
  if (send_le_channel_selection_algorithm_event &&
      IsLeEventUnmasked(SubeventCode::LE_CHANNEL_SELECTION_ALGORITHM)) {
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
bool LeController::ProcessIncomingLegacyConnectRequest(
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
        PeerDeviceAddress(legacy_advertiser_.peer_address, legacy_advertiser_.peer_address_type)) {
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

  (void)HandleLeConnection(
          initiating_address,
          resolved_initiating_address != initiating_address ? resolved_initiating_address
                                                            : AddressWithType{},
          advertising_address, bluetooth::hci::Role::PERIPHERAL, connect_ind.GetConnInterval(),
          connect_ind.GetConnPeripheralLatency(), connect_ind.GetConnSupervisionTimeout(), false);

  SendLeLinkLayerPacket(model::packets::LeConnectCompleteBuilder::Create(
          advertising_address.GetAddress(), initiating_address.GetAddress(),
          static_cast<model::packets::AddressType>(initiating_address.GetAddressType()),
          static_cast<model::packets::AddressType>(advertising_address.GetAddressType()),
          connect_ind.GetConnInterval(), connect_ind.GetConnPeripheralLatency(),
          connect_ind.GetConnSupervisionTimeout()));

  legacy_advertiser_.Disable();
  return true;
}

// Handle CONNECT_IND PDUs for the selected extended advertiser.
bool LeController::ProcessIncomingExtendedConnectRequest(
        ExtendedAdvertiser& advertiser, model::packets::LeConnectView const& connect_ind) {
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
          advertiser.advertising_handle, advertising_address, advertiser.GetAdvertisingAddress());
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
        PeerDeviceAddress(advertiser.peer_address, advertiser.peer_address_type)) {
      DEBUG(id_,
            "LE Connect request ignored by extended advertiser {} because the "
            "initiating address {} does not match the target address {}[{}]",
            advertiser.advertising_handle, resolved_initiating_address, advertiser.peer_address,
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

  advertiser.Disable();

  uint16_t connection_handle = HandleLeConnection(
          initiating_address,
          resolved_initiating_address != initiating_address ? resolved_initiating_address
                                                            : AddressWithType{},
          advertising_address, bluetooth::hci::Role::PERIPHERAL, connect_ind.GetConnInterval(),
          connect_ind.GetConnPeripheralLatency(), connect_ind.GetConnSupervisionTimeout(), false);

  SendLeLinkLayerPacket(model::packets::LeConnectCompleteBuilder::Create(
          advertising_address.GetAddress(), initiating_address.GetAddress(),
          static_cast<model::packets::AddressType>(initiating_address.GetAddressType()),
          static_cast<model::packets::AddressType>(advertising_address.GetAddressType()),
          connect_ind.GetConnInterval(), connect_ind.GetConnPeripheralLatency(),
          connect_ind.GetConnSupervisionTimeout()));

  // If the advertising set is connectable and a connection gets created, an
  // HCI_LE_Connection_Complete or HCI_LE_Enhanced_Connection_Complete
  // event shall be generated followed by an HCI_LE_Advertising_Set_Terminated
  // event with the Status parameter set to 0x00. The Controller should not send
  // any other events in between these two events

  if (IsLeEventUnmasked(SubeventCode::LE_ADVERTISING_SET_TERMINATED)) {
    send_event_(bluetooth::hci::LeAdvertisingSetTerminatedBuilder::Create(
            ErrorCode::SUCCESS, advertiser.advertising_handle, connection_handle,
            advertiser.num_completed_extended_advertising_events));
  }

  return true;
}

void LeController::IncomingLeConnectPacket(model::packets::LinkLayerPacketView incoming) {
  model::packets::LeConnectView connect = model::packets::LeConnectView::Create(incoming);
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

void LeController::IncomingLeConnectCompletePacket(model::packets::LinkLayerPacketView incoming) {
  auto complete = model::packets::LeConnectCompleteView::Create(incoming);
  ASSERT(complete.IsValid());

  AddressWithType initiating_address{
          incoming.GetDestinationAddress(),
          static_cast<bluetooth::hci::AddressType>(complete.GetInitiatingAddressType())};
  AddressWithType advertising_address{
          incoming.GetSourceAddress(),
          static_cast<bluetooth::hci::AddressType>(complete.GetAdvertisingAddressType())};

  if (initiator_.pending_connect_request != advertising_address &&
      initiator_.initiating_address != initiating_address.GetAddress()) {
    INFO(id_, "Ignoring unexpected LE Connect complete response {} -> {}", advertising_address,
         initiating_address);
    return;
  }

  INFO(id_, "Received LE Connect complete response with advertising address {}",
       advertising_address);

  AddressWithType resolved_advertising_address =
          advertising_address.IsRpa()
                  ? ResolvePrivateAddress(advertising_address).value_or(AddressWithType{})
                  : AddressWithType{};

  HandleLeConnection(advertising_address, resolved_advertising_address,
                     AddressWithType(incoming.GetDestinationAddress(),
                                     static_cast<bluetooth::hci::AddressType>(
                                             complete.GetInitiatingAddressType())),
                     bluetooth::hci::Role::CENTRAL, complete.GetConnInterval(),
                     complete.GetConnPeripheralLatency(), complete.GetConnSupervisionTimeout(),
                     ExtendedAdvertising());

  initiator_.pending_connect_request = {};
  initiator_.Disable();
}

void LeController::IncomingLeConnectionParameterRequest(
        LeAclConnection& connection, model::packets::LinkLayerPacketView incoming) {
  auto request = model::packets::LeConnectionParameterRequestView::Create(incoming);
  ASSERT(request.IsValid());

  if (IsLeEventUnmasked(SubeventCode::LE_REMOTE_CONNECTION_PARAMETER_REQUEST)) {
    send_event_(bluetooth::hci::LeRemoteConnectionParameterRequestBuilder::Create(
            connection.handle, request.GetIntervalMin(), request.GetIntervalMax(),
            request.GetLatency(), request.GetTimeout()));
  } else {
    // If the request is being indicated to the Host and the event to the Host
    // is masked, then the Link Layer shall issue an LL_REJECT_EXT_IND PDU with
    // the ErrorCode set to Unsupported Remote Feature (0x1A).
    SendLeLinkLayerPacket(model::packets::LeConnectionParameterUpdateBuilder::Create(
            request.GetDestinationAddress(), request.GetSourceAddress(),
            static_cast<uint8_t>(ErrorCode::UNSUPPORTED_REMOTE_OR_LMP_FEATURE), 0, 0, 0));
  }
}

void LeController::IncomingLeConnectionParameterUpdate(
        LeAclConnection& connection, model::packets::LinkLayerPacketView incoming) {
  auto update = model::packets::LeConnectionParameterUpdateView::Create(incoming);
  ASSERT(update.IsValid());
  ErrorCode status = static_cast<ErrorCode>(update.GetStatus());

  if (status == ErrorCode::SUCCESS) {
    // Update local connection parameters on success.
    // If this command completes successfully and the connection interval has changed, then the
    // subrating factor shall be set to 1 and the continuation number to 0.
    connection.parameters = LeAclConnectionParameters{
            .conn_interval = update.GetInterval(),
            .conn_subrate_factor = 1,
            .conn_continuation_number = 0,
            .conn_peripheral_latency = update.GetLatency(),
            .conn_supervision_timeout = update.GetTimeout(),
    };
  }

  if (IsLeEventUnmasked(SubeventCode::LE_CONNECTION_UPDATE_COMPLETE)) {
    send_event_(bluetooth::hci::LeConnectionUpdateCompleteBuilder::Create(
            status, connection.handle, update.GetInterval(), update.GetLatency(),
            update.GetTimeout()));
  }
}

void LeController::IncomingLeEncryptConnection(LeAclConnection& connection,
                                               model::packets::LinkLayerPacketView incoming) {
  INFO(id_, "IncomingLeEncryptConnection");

  auto le_encrypt = model::packets::LeEncryptConnectionView::Create(incoming);
  ASSERT(le_encrypt.IsValid());

  // TODO: Save keys to check

  if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
    send_event_(bluetooth::hci::LeLongTermKeyRequestBuilder::Create(
            connection.handle, le_encrypt.GetRand(), le_encrypt.GetEdiv()));
  }
}

void LeController::IncomingLeEncryptConnectionResponse(
        LeAclConnection& connection, model::packets::LinkLayerPacketView incoming) {
  INFO(id_, "IncomingLeEncryptConnectionResponse");
  // TODO: Check keys

  ErrorCode status = ErrorCode::SUCCESS;
  auto response = model::packets::LeEncryptConnectionResponseView::Create(incoming);
  ASSERT(response.IsValid());

  bool success = true;
  // Zero LTK is a rejection
  if (response.GetLtk() == std::array<uint8_t, 16>{0}) {
    status = ErrorCode::AUTHENTICATION_FAILURE;
    success = false;
  }

  if (connection.IsEncrypted()) {
    if (IsEventUnmasked(EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE)) {
      send_event_(bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(status,
                                                                              connection.handle));
    }
  } else if (success) {
    connection.Encrypt();
    if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
      send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
              status, connection.handle, bluetooth::hci::EncryptionEnabled::ON));
    }
  } else {
    if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
      send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
              status, connection.handle, bluetooth::hci::EncryptionEnabled::OFF));
    }
  }
}

void LeController::IncomingLeReadRemoteFeatures(LeAclConnection& /*connection*/,
                                                model::packets::LinkLayerPacketView incoming) {
  ErrorCode status = ErrorCode::SUCCESS;
  SendLeLinkLayerPacket(model::packets::LeReadRemoteFeaturesResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(), GetLeSupportedFeatures(),
          static_cast<uint8_t>(status)));
}

void LeController::IncomingLeReadRemoteFeaturesResponse(
        LeAclConnection& connection, model::packets::LinkLayerPacketView incoming) {
  auto response = model::packets::LeReadRemoteFeaturesResponseView::Create(incoming);
  ASSERT(response.IsValid());
  ErrorCode status = static_cast<ErrorCode>(response.GetStatus());

  if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
    send_event_(bluetooth::hci::LeReadRemoteFeaturesPage0CompleteBuilder::Create(
            status, connection.handle, response.GetFeatures()));
  }
}

void LeController::ProcessIncomingLegacyScanRequest(AddressWithType scanning_address,
                                                    AddressWithType resolved_scanning_address,
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
    DEBUG(id_,
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
        DEBUG(id_,
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
                  static_cast<model::packets::AddressType>(advertising_address.GetAddressType()),
                  legacy_advertiser_.scan_response_data),
          properties_.le_advertising_physical_channel_tx_power);
}

void LeController::ProcessIncomingExtendedScanRequest(ExtendedAdvertiser const& advertiser,
                                                      AddressWithType scanning_address,
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
          advertiser.advertising_handle, advertising_address, advertiser.GetAdvertisingAddress());
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
  if (advertiser.IsDirected() && advertiser.target_address != resolved_scanning_address) {
    DEBUG(id_,
          "LE Scan request ignored by extended advertiser {} because the "
          "scanning address {} does not match the target address {}",
          advertiser.advertising_handle, resolved_scanning_address, advertiser.GetTargetAddress());
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
                  static_cast<model::packets::AddressType>(advertising_address.GetAddressType()),
                  advertiser.scan_response_data),
          advertiser.advertising_tx_power);
}

void LeController::IncomingLeScanPacket(model::packets::LinkLayerPacketView incoming) {
  auto scan_request = model::packets::LeScanView::Create(incoming);
  ASSERT(scan_request.IsValid());

  AddressWithType scanning_address{scan_request.GetSourceAddress(),
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
    ProcessIncomingExtendedScanRequest(advertiser, scanning_address, resolved_scanning_address,
                                       advertising_address);
  }
}

void LeController::IncomingLeScanResponsePacket(model::packets::LinkLayerPacketView incoming,
                                                uint8_t rssi) {
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

  INFO(id_, "Accepting LE Scan response from advertising address {}", resolved_advertising_address);

  scanner_.pending_scan_request = {};

  bool should_send_advertising_report = true;
  if (scanner_.filter_duplicates != bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(incoming.bytes())) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(incoming.bytes());
    }
  }

  if (LegacyAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::LE_ADVERTISING_REPORT)) {
    bluetooth::hci::LeAdvertisingResponse response;
    response.event_type_ = bluetooth::hci::AdvertisingEventType::SCAN_RESPONSE;
    response.address_ = resolved_advertising_address.GetAddress();
    response.address_type_ = resolved_advertising_address.GetAddressType();
    response.advertising_data_ = scan_response.GetScanResponseData();
    response.rssi_ = rssi;
    send_event_(bluetooth::hci::LeAdvertisingReportBuilder::Create({response}));
  }

  if (ExtendedAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::LE_EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponse response;
    response.address_ = resolved_advertising_address.GetAddress();
    response.address_type_ = static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
            resolved_advertising_address.GetAddressType());
    response.connectable_ = scanner_.connectable_scan_response;
    response.scannable_ = true;
    response.legacy_ = !scanner_.extended_scan_response;
    response.scan_response_ = true;
    response.primary_phy_ =
            static_cast<bluetooth::hci::PrimaryPhyType>(scanner_.primary_scan_response_phy);
    response.secondary_phy_ =
            static_cast<bluetooth::hci::SecondaryPhyType>(scanner_.secondary_scan_response_phy);
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
      response.advertising_data_ = std::vector(advertising_data.begin() + offset,
                                               advertising_data.begin() + offset + fragment_size);
      offset += fragment_size;
      send_event_(bluetooth::hci::LeExtendedAdvertisingReportBuilder::Create({response}));
    } while (offset < advertising_data.size());
  }
}

void LeController::LeScanning() {
  if (!scanner_.IsEnabled()) {
    return;
  }

  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

  // Extended Scanning Timeout

  // Generate HCI Connection Complete or Enhanced HCI Connection Complete
  // events with Advertising Timeout error code when the advertising
  // type is ADV_DIRECT_IND and the connection failed to be established.

  if (scanner_.timeout.has_value() && !scanner_.periodical_timeout.has_value() &&
      now >= scanner_.timeout.value()) {
    // At the end of a single scan (Duration non-zero but Period zero),
    // an HCI_LE_Scan_Timeout event shall be generated.
    INFO(id_, "Extended Scan Timeout");
    scanner_.scan_enable = false;
    scanner_.pending_scan_request = {};
    scanner_.history.clear();
    if (IsLeEventUnmasked(SubeventCode::LE_SCAN_TIMEOUT)) {
      send_event_(bluetooth::hci::LeScanTimeoutBuilder::Create());
    }
  }

  // End of duration with scan enabled
  if (scanner_.timeout.has_value() && scanner_.periodical_timeout.has_value() &&
      now >= scanner_.timeout.value()) {
    scanner_.timeout = {};
  }

  // End of period
  if (!scanner_.timeout.has_value() && scanner_.periodical_timeout.has_value() &&
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

void LeController::LeSynchronization() {
  std::vector<uint16_t> removed_sync_handles;
  for (auto& [_, sync] : synchronized_) {
    if (sync.timeout > std::chrono::steady_clock::now()) {
      INFO(id_, "Periodic advertising sync with handle 0x{:x} lost", sync.sync_handle);
      removed_sync_handles.push_back(sync.sync_handle);
    }
    if (IsLeEventUnmasked(SubeventCode::LE_PERIODIC_ADVERTISING_SYNC_LOST)) {
      send_event_(bluetooth::hci::LePeriodicAdvertisingSyncLostBuilder::Create(sync.sync_handle));
    }
  }

  for (auto sync_handle : removed_sync_handles) {
    synchronized_.erase(sync_handle);
  }
}

void LeController::Tick() {
  RunPendingTasks();
  LeAdvertising();
  LeScanning();
}

void LeController::Close() {
  DisconnectAll(ErrorCode::REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF);
}

void LeController::RegisterEventChannel(
        const std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>& send_event) {
  send_event_ = send_event;
}

void LeController::RegisterAclChannel(
        const std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)>& send_acl) {
  send_acl_ = send_acl;
}

void LeController::RegisterIsoChannel(
        const std::function<void(std::shared_ptr<bluetooth::hci::IsoBuilder>)>& send_iso) {
  send_iso_ = send_iso;
}

void LeController::RegisterRemoteChannel(
        const std::function<void(std::shared_ptr<model::packets::LinkLayerPacketBuilder>, Phy::Type,
                                 int8_t)>& send_to_remote) {
  send_to_remote_ = send_to_remote;
}

void LeController::ForwardToLl(bluetooth::hci::CommandView command) {
  auto packet = command.bytes().bytes();
  ASSERT(link_layer_ingest_hci(ll_.get(), packet.data(), packet.size()));
}

void LeController::SendDisconnectionCompleteEvent(uint16_t handle, ErrorCode reason) {
  if (IsEventUnmasked(EventCode::DISCONNECTION_COMPLETE)) {
    ScheduleTask(kNoDelayMs, [this, handle, reason]() {
      send_event_(bluetooth::hci::DisconnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle,
                                                                       reason));
    });
  }
}

ErrorCode LeController::Disconnect(uint16_t handle, ErrorCode host_reason,
                                   ErrorCode controller_reason) {
  if (connections_.HasLeAclHandle(handle)) {
    auto connection = connections_.GetLeAclConnection(handle);
    INFO(id_, "Disconnecting LE-ACL connection with {}", connection.address);

    SendLeLinkLayerPacket(model::packets::DisconnectBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress(),
            static_cast<uint8_t>(host_reason)));

    connections_.Disconnect(handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
    SendDisconnectionCompleteEvent(handle, controller_reason);

    ASSERT(link_layer_remove_link(ll_.get(), handle, static_cast<uint8_t>(controller_reason)));
    return ErrorCode::SUCCESS;
  }

  return ErrorCode::UNKNOWN_CONNECTION;
}

ErrorCode LeController::ReadRemoteVersionInformation(uint16_t connection_handle) {
  if (connections_.HasLeAclHandle(connection_handle)) {
    auto const& connection = connections_.GetLeAclConnection(connection_handle);
    SendLeLinkLayerPacket(model::packets::ReadRemoteVersionInformationBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress()));
    return ErrorCode::SUCCESS;
  }

  return ErrorCode::UNKNOWN_CONNECTION;
}

ErrorCode LeController::LeConnectionUpdate(uint16_t handle, uint16_t interval_min,
                                           uint16_t interval_max, uint16_t latency,
                                           uint16_t supervision_timeout) {
  if (!connections_.HasLeAclHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetLeAclConnection(handle);

  if (connection.role == bluetooth::hci::Role::CENTRAL) {
    // As Central, it is allowed to directly send
    // LL_CONNECTION_PARAM_UPDATE_IND to update the parameters.
    SendLeLinkLayerPacket(LeConnectionParameterUpdateBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress(),
            static_cast<uint8_t>(ErrorCode::SUCCESS), interval_max, latency, supervision_timeout));

    if (IsLeEventUnmasked(SubeventCode::LE_CONNECTION_UPDATE_COMPLETE)) {
      // TODO: should be delayed after the command status.
      send_event_(bluetooth::hci::LeConnectionUpdateCompleteBuilder::Create(
              ErrorCode::SUCCESS, handle, interval_max, latency, supervision_timeout));
    }
  } else {
    // Send LL_CONNECTION_PARAM_REQ and wait for LL_CONNECTION_PARAM_RSP
    // in return.
    SendLeLinkLayerPacket(LeConnectionParameterRequestBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress(), interval_min,
            interval_max, latency, supervision_timeout));
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LeController::LeRemoteConnectionParameterRequestReply(
        uint16_t connection_handle, uint16_t interval_min, uint16_t interval_max,
        uint16_t supervision_timeout, uint16_t latency, uint16_t minimum_ce_length,
        uint16_t maximum_ce_length) {
  if (!connections_.HasLeAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetLeAclConnection(connection_handle);

  if (interval_min < 6 || interval_max > 0xC80 || interval_min > interval_max ||
      interval_max < interval_min || latency > 0x1F3 || supervision_timeout < 0xA ||
      supervision_timeout > 0xC80 ||
      // The Supervision_Timeout in milliseconds (*10) shall be larger than (1 +
      // Connection_Latency) * Connection_Interval_Max (* 5/4) * 2
      supervision_timeout <= ((((1 + latency) * interval_max * 10) / 4) / 10)) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  if (minimum_ce_length > maximum_ce_length) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Update local connection parameters.
  // If this command completes successfully and the connection interval has changed, then the
  // subrating factor shall be set to 1 and the continuation number to 0.
  connection.parameters = LeAclConnectionParameters{
          .conn_interval = interval_min,
          .conn_subrate_factor = 1,
          .conn_continuation_number = 0,
          .conn_peripheral_latency = latency,
          .conn_supervision_timeout = supervision_timeout,
  };

  SendLeLinkLayerPacket(LeConnectionParameterUpdateBuilder::Create(
          connection.own_address.GetAddress(), connection.address.GetAddress(),
          static_cast<uint8_t>(ErrorCode::SUCCESS), interval_min, latency, supervision_timeout));

  if (IsLeEventUnmasked(SubeventCode::LE_CONNECTION_UPDATE_COMPLETE)) {
    // TODO: should be delayed after the command status.
    send_event_(bluetooth::hci::LeConnectionUpdateCompleteBuilder::Create(
            ErrorCode::SUCCESS, connection.handle, interval_min, latency, supervision_timeout));
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LeController::LeRemoteConnectionParameterRequestNegativeReply(
        uint16_t connection_handle, bluetooth::hci::ErrorCode reason) {
  if (!connections_.HasLeAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto const& connection = connections_.GetLeAclConnection(connection_handle);
  SendLeLinkLayerPacket(LeConnectionParameterUpdateBuilder::Create(
          connection.own_address.GetAddress(), connection.address.GetAddress(),
          static_cast<uint8_t>(reason), 0, 0, 0));

  return ErrorCode::SUCCESS;
}

bool LeController::HasLeAclConnection(uint16_t connection_handle) {
  return connections_.HasLeAclHandle(connection_handle);
}

void LeController::HandleLeEnableEncryption(uint16_t handle, std::array<uint8_t, 8> rand,
                                            uint16_t ediv, std::array<uint8_t, kLtkSize> ltk) {
  // TODO: Check keys
  // TODO: Block ACL traffic or at least guard against it
  if (!connections_.HasLeAclHandle(handle)) {
    return;
  }

  auto const& connection = connections_.GetLeAclConnection(handle);
  SendLeLinkLayerPacket(model::packets::LeEncryptConnectionBuilder::Create(
          connection.own_address.GetAddress(), connection.address.GetAddress(), rand, ediv, ltk));
}

ErrorCode LeController::LeEnableEncryption(uint16_t handle, std::array<uint8_t, 8> rand,
                                           uint16_t ediv, std::array<uint8_t, kLtkSize> ltk) {
  if (!connections_.HasLeAclHandle(handle)) {
    INFO(id_, "Unknown handle 0x{:04x}", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(kNoDelayMs, [this, handle, rand, ediv, ltk]() {
    HandleLeEnableEncryption(handle, rand, ediv, ltk);
  });
  return ErrorCode::SUCCESS;
}

ErrorCode LeController::LeLongTermKeyRequestReply(uint16_t handle,
                                                  std::array<uint8_t, kLtkSize> ltk) {
  if (!connections_.HasLeAclHandle(handle)) {
    INFO(id_, "Unknown handle {:04x}", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetLeAclConnection(handle);

  // TODO: Check keys
  if (connection.IsEncrypted()) {
    if (IsEventUnmasked(EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE)) {
      send_event_(bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(ErrorCode::SUCCESS,
                                                                              handle));
    }
  } else {
    connection.Encrypt();
    if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE_V2)) {
      send_event_(bluetooth::hci::EncryptionChangeV2Builder::Create(
              ErrorCode::SUCCESS, handle, bluetooth::hci::EncryptionEnabled::ON,
              0x10 /* key_size */));
    } else if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
      send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
              ErrorCode::SUCCESS, handle, bluetooth::hci::EncryptionEnabled::ON));
    }
  }
  SendLeLinkLayerPacket(model::packets::LeEncryptConnectionResponseBuilder::Create(
          connection.own_address.GetAddress(), connection.address.GetAddress(),
          std::array<uint8_t, 8>(), uint16_t(), ltk));

  return ErrorCode::SUCCESS;
}

ErrorCode LeController::LeLongTermKeyRequestNegativeReply(uint16_t handle) {
  if (!connections_.HasLeAclHandle(handle)) {
    INFO(id_, "Unknown handle {:04x}", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto const& connection = connections_.GetLeAclConnection(handle);
  SendLeLinkLayerPacket(model::packets::LeEncryptConnectionResponseBuilder::Create(
          connection.own_address.GetAddress(), connection.address.GetAddress(),
          std::array<uint8_t, 8>(), uint16_t(), std::array<uint8_t, 16>()));
  return ErrorCode::SUCCESS;
}

void LeController::DisconnectAll(ErrorCode reason) {
  for (auto connection_handle : connections_.GetLeAclHandles()) {
    auto const& connection = connections_.GetLeAclConnection(connection_handle);
    SendLeLinkLayerPacket(model::packets::DisconnectBuilder::Create(
            connection.own_address.GetAddress(), connection.address.GetAddress(),
            static_cast<uint8_t>(reason)));
  }
}

void LeController::Reset() {
  // Explicitly Disconnect all existing links on reset.
  // No Disconnection Complete event should be generated from the link
  // disconnections, as only the HCI Command Complete event is expected for the
  // HCI Reset command.
  DisconnectAll(ErrorCode::REMOTE_USER_TERMINATED_CONNECTION);

  // DisconnectAll does not close the local connection contexts.
  connections_.Reset([this](TaskId task_id) { CancelScheduledTask(task_id); });

  host_supported_features_ = 0;
  le_host_support_ = false;
  secure_simple_pairing_host_support_ = false;
  secure_connections_host_support_ = false;
  le_host_supported_features_ = 0;
  connected_isochronous_stream_host_support_ = false;
  connection_subrating_host_support_ = false;
  random_address_ = Address::kEmpty;
  event_mask_ = 0x00001fffffffffff;
  event_mask_page_2_ = 0x0;
  le_event_mask_ = 0x01f;
  le_suggested_max_tx_octets_ = 0x001b;
  le_suggested_max_tx_time_ = 0x0148;
  resolvable_private_address_timeout_ = std::chrono::seconds(0x0384);
  le_periodic_advertiser_list_.clear();
  le_filter_accept_list_.clear();
  le_resolving_list_.clear();
  le_resolving_list_enabled_ = false;
  legacy_advertising_in_use_ = false;
  extended_advertising_in_use_ = false;
  legacy_advertiser_ = LegacyAdvertiser{};
  extended_advertisers_.clear();
  scanner_ = Scanner{};
  apcf_scanner_ = ApcfScanner{};
  initiator_ = Initiator{};
  synchronizing_ = {};
  synchronized_ = {};
  default_tx_phys_ = properties_.LeSupportedPhys();
  default_rx_phys_ = properties_.LeSupportedPhys();
  default_subrate_parameters_ = LeAclSubrateParameters{};

  ll_.reset(link_layer_create(controller_ops_));
}

void LeController::CheckExpiringConnection(uint16_t handle) {
  if (!connections_.HasAclHandle(handle)) {
    return;
  }

  auto& connection = connections_.GetAclConnection(handle);

  if (connection.HasExpired()) {
    Disconnect(handle, ErrorCode::CONNECTION_TIMEOUT, ErrorCode::CONNECTION_TIMEOUT);
    return;
  }

  if (connection.IsNearExpiring()) {
    SendLeLinkLayerPacket(
            model::packets::PingRequestBuilder::Create(connection.own_address, connection.address));
    ScheduleTask(std::chrono::duration_cast<milliseconds>(connection.TimeUntilExpired()),
                 [this, handle] { CheckExpiringConnection(handle); });
    return;
  }

  ScheduleTask(std::chrono::duration_cast<milliseconds>(connection.TimeUntilNearExpiring()),
               [this, handle] { CheckExpiringConnection(handle); });
}

void LeController::IncomingPingRequest(model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::PingRequestView::Create(incoming);
  ASSERT(view.IsValid());
  SendLeLinkLayerPacket(model::packets::PingResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress()));
}

TaskId LeController::NextTaskId() {
  TaskId task_id = task_counter_++;
  while (task_id == kInvalidTaskId ||
         std::any_of(task_queue_.begin(), task_queue_.end(),
                     [=](Task const& task) { return task.task_id == task_id; })) {
    task_id = task_counter_++;
  }
  return task_id;
}

TaskId LeController::ScheduleTask(std::chrono::milliseconds delay, TaskCallback task_callback) {
  TaskId task_id = NextTaskId();
  task_queue_.emplace(std::chrono::steady_clock::now() + delay, std::move(task_callback), task_id);
  return task_id;
}

TaskId LeController::SchedulePeriodicTask(std::chrono::milliseconds delay,
                                          std::chrono::milliseconds period,
                                          TaskCallback task_callback) {
  TaskId task_id = NextTaskId();
  task_queue_.emplace(std::chrono::steady_clock::now() + delay, period, std::move(task_callback),
                      task_id);
  return task_id;
}

void LeController::CancelScheduledTask(TaskId task_id) {
  auto it = task_queue_.cbegin();
  for (; it != task_queue_.cend(); it++) {
    if (it->task_id == task_id) {
      task_queue_.erase(it);
      return;
    }
  }
}

void LeController::RunPendingTasks() {
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
