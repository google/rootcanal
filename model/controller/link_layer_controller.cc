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

#include "link_layer_controller.h"

#include <hci/hci_packets.h>
#ifdef ROOTCANAL_LMP
#include <lmp.h>
#endif /* ROOTCANAL_LMP */

#include "crypto/crypto.h"
#include "log.h"
#include "packet/raw_builder.h"

using namespace std::chrono;
using bluetooth::hci::Address;
using bluetooth::hci::AddressType;
using bluetooth::hci::AddressWithType;
using bluetooth::hci::DirectAdvertisingAddressType;
using bluetooth::hci::EventCode;
using bluetooth::hci::LLFeaturesBits;
using bluetooth::hci::SubeventCode;

using namespace model::packets;
using model::packets::PacketType;
using namespace std::literals;

using TaskId = rootcanal::LinkLayerController::TaskId;

// Temporay define, to be replaced when verbose log level is implemented.
#define LOG_VERB(...) LOG_INFO(__VA_ARGS__)

namespace rootcanal {

constexpr uint16_t kNumCommandPackets = 0x01;

constexpr milliseconds kNoDelayMs(0);

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
    AddressWithType address, IrkSelection irk) {
  if (!address.IsRpa()) {
    return address;
  }

  if (!le_resolving_list_enabled_) {
    return {};
  }

  for (auto const& entry : le_resolving_list_) {
    std::array<uint8_t, LinkLayerController::kIrkSize> const& used_irk =
        irk == IrkSelection::Local ? entry.local_irk : entry.peer_irk;

    if (address.IsRpaThatMatchesIrk(used_irk)) {
      return PeerIdentityAddress(entry.peer_identity_address,
                                 entry.peer_identity_address_type);
    }
  }

  return {};
}

std::optional<AddressWithType>
LinkLayerController::GenerateResolvablePrivateAddress(AddressWithType address,
                                                      IrkSelection irk) {
  if (!le_resolving_list_enabled_) {
    return {};
  }

  for (auto const& entry : le_resolving_list_) {
    if (address.GetAddress() == entry.peer_identity_address &&
        address.ToPeerAddressType() == entry.peer_identity_address_type) {
      std::array<uint8_t, LinkLayerController::kIrkSize> const& used_irk =
          irk == IrkSelection::Local ? entry.local_irk : entry.peer_irk;

      return AddressWithType{generate_rpa(used_irk),
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
    LOG_INFO("unknown connection identifier");
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
    LOG_INFO("advertising, scanning or initiating are currently active");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (random_address == Address::kEmpty) {
    LOG_INFO("the random address may not be set to 00:00:00:00:00:00");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  LOG_INFO("device random address configured to %s",
           random_address.ToString().c_str());
  random_address_ = random_address;
  return ErrorCode::SUCCESS;
}

// HCI LE Set Host Feature command (Vol 4, Part E § 7.8.45).
ErrorCode LinkLayerController::LeSetResolvablePrivateAddressTimeout(
    uint16_t rpa_timeout) {
  // Note: no documented status code for this case.
  if (rpa_timeout < 0x1 || rpa_timeout > 0x0e10) {
    LOG_INFO(
        "rpa_timeout (0x%04x) is outside the range of supported values "
        " 0x1 - 0x0e10",
        rpa_timeout);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  resolvable_private_address_timeout_ = seconds(rpa_timeout);
  return ErrorCode::SUCCESS;
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
    LOG_INFO(
        "device is currently advertising, scanning, or establishing an"
        " LE connection");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // When a Controller cannot add a device to the list because there is no space
  // available, it shall return the error code Memory Capacity Exceeded (0x07).
  if (le_resolving_list_.size() >= properties_.le_resolving_list_size) {
    LOG_INFO("resolving list is full");
    return ErrorCode::MEMORY_CAPACITY_EXCEEDED;
  }

  // If there is an existing entry in the resolving list with the same
  // Peer_Identity_Address and Peer_Identity_Address_Type, or with the same
  // Peer_IRK, the Controller should return the error code Invalid HCI Command
  // Parameters (0x12).
  for (auto const& entry : le_resolving_list_) {
    if ((entry.peer_identity_address_type == peer_identity_address_type &&
         entry.peer_identity_address == peer_identity_address) ||
        entry.peer_irk == peer_irk) {
      LOG_INFO("device is already present in the resolving list");
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }
  }

  le_resolving_list_.emplace_back(
      ResolvingListEntry{peer_identity_address_type, peer_identity_address,
                         peer_irk, local_irk, PrivacyMode::NETWORK});
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
    LOG_INFO(
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
  LOG_INFO("peer address not found in the resolving list");
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
    LOG_INFO(
        "device is currently advertising, scanning,"
        " or establishing an LE connection");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  le_resolving_list_.clear();
  return ErrorCode::SUCCESS;
}

// HCI command LE_Set_Address_Resolution_Enable (Vol 4, Part E § 7.8.44).
ErrorCode LinkLayerController::LeSetAddressResolutionEnable(bool enable) {
  // This command shall not be used when:
  //  • Advertising (other than periodic advertising) is enabled,
  //  • Scanning is enabled, or
  //  • an HCI_LE_Create_Connection, HCI_LE_Extended_Create_Connection, or
  //    HCI_LE_Periodic_Advertising_Create_Sync command is pending.
  if (ResolvingListBusy()) {
    LOG_INFO(
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
    LOG_INFO(
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
  LOG_INFO("peer address not found in the resolving list");
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
    LOG_INFO(
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
    LOG_INFO(
        "device is currently advertising, scanning,"
        " or establishing an LE connection using the filter accept list");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // When a Controller cannot add a device to the Filter Accept List
  // because there is no space available, it shall return the error code
  // Memory Capacity Exceeded (0x07).
  if (le_filter_accept_list_.size() >= properties_.le_filter_accept_list_size) {
    LOG_INFO("filter accept list is full");
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
    LOG_INFO(
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
  LOG_INFO("address not found in the filter accept list");
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
    LOG_INFO(
        "legacy advertising command rejected because extended advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // The Host shall not issue this command when scanning is enabled in the
  // Controller; if it is the Command Disallowed error code shall be used.
  if (scanner_.IsEnabled()) {
    LOG_INFO("scanning is currently enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // Note: no explicit error code stated for invalid interval and window
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (scan_interval < 0x4 || scan_interval > 0x4000 || scan_window < 0x4 ||
      scan_window > 0x4000) {
    LOG_INFO(
        "le_scan_interval (0x%04x) and/or"
        " le_scan_window (0x%04x) are outside the range"
        " of supported values (0x0004 - 0x4000)",
        scan_interval, scan_window);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The LE_Scan_Window parameter shall always be set to a value smaller
  // or equal to the value set for the LE_Scan_Interval parameter.
  if (scan_window > scan_interval) {
    LOG_INFO("le_scan_window (0x%04x) is larger than le_scan_interval (0x%04x)",
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
    LOG_INFO(
        "legacy advertising command rejected because extended advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (!enable) {
    scanner_.scan_enable = false;
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
    LOG_INFO(
        "own_address_type is Random_Device_Address or"
        " Resolvable_or_Random_Address but the Random_Address"
        " has not been initialized");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  scanner_.scan_enable = true;
  scanner_.history.clear();
  scanner_.timeout = {};
  scanner_.periodical_timeout = {};
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
    std::vector<bluetooth::hci::PhyScanParameters> scanning_phy_parameters) {
  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    LOG_INFO(
        "extended advertising command rejected because legacy advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command when scanning is enabled in the Controller,
  // the Controller shall return the error code Command Disallowed (0x0C).
  if (scanner_.IsEnabled()) {
    LOG_INFO("scanning is currently enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host specifies a PHY that is not supported by the Controller,
  // including a bit that is reserved for future use, it should return the
  // error code Unsupported Feature or Parameter Value (0x11).
  if ((scanning_phys & 0xfa) != 0) {
    LOG_INFO(
        "scanning_phys (%02x) enables PHYs that are not supported by"
        " the controller",
        scanning_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // TODO(c++20) std::popcount
  if (__builtin_popcount(scanning_phys) !=
      int(scanning_phy_parameters.size())) {
    LOG_INFO(
        "scanning_phy_parameters (%zu)"
        " does not match scanning_phys (%02x)",
        scanning_phy_parameters.size(), scanning_phys);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Note: no explicit error code stated for empty scanning_phys
  // but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on HCI Extended LE Create Connecton command.
  if (scanning_phys == 0) {
    LOG_INFO("scanning_phys is empty");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  for (auto const& parameter : scanning_phy_parameters) {
    //  If the requested scan cannot be supported by the implementation,
    // the Controller shall return the error code
    // Invalid HCI Command Parameters (0x12).
    if (parameter.le_scan_interval_ < 0x4 || parameter.le_scan_window_ < 0x4) {
      LOG_INFO(
          "le_scan_interval (0x%04x) and/or"
          " le_scan_window (0x%04x) are outside the range"
          " of supported values (0x0004 - 0xffff)",
          parameter.le_scan_interval_, parameter.le_scan_window_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    if (parameter.le_scan_window_ > parameter.le_scan_interval_) {
      LOG_INFO(
          "le_scan_window (0x%04x) is larger than le_scan_interval (0x%04x)",
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
    LOG_INFO(
        "extended advertising command rejected because legacy advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (!enable) {
    scanner_.scan_enable = false;
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
    LOG_INFO(
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
    LOG_INFO("the period is greater than or equal to the duration");
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
    LOG_INFO(
        "own_address_type is Random_Device_Address or"
        " Resolvable_or_Random_Address but the Random_Address"
        " has not been initialized");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  scanner_.scan_enable = true;
  scanner_.history.clear();
  scanner_.timeout = {};
  scanner_.periodical_timeout = {};
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
    LOG_INFO(
        "legacy advertising command rejected because extended advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command when another HCI_LE_Create_Connection
  // command is pending in the Controller, the Controller shall return the
  // error code Command Disallowed (0x0C).
  if (initiator_.IsEnabled()) {
    LOG_INFO("initiator is currently enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // Note: no explicit error code stated for invalid interval and window
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (scan_interval < 0x4 || scan_interval > 0x4000 || scan_window < 0x4 ||
      scan_window > 0x4000) {
    LOG_INFO(
        "scan_interval (0x%04x) and/or "
        "scan_window (0x%04x) are outside the range"
        " of supported values (0x4 - 0x4000)",
        scan_interval, scan_window);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The LE_Scan_Window parameter shall be set to a value smaller or equal to
  // the value set for the LE_Scan_Interval parameter.
  if (scan_interval < scan_window) {
    LOG_INFO("scan_window (0x%04x) is larger than scan_interval (0x%04x)",
             scan_window, scan_interval);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Note: no explicit error code stated for invalid connection interval
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (connection_interval_min < 0x6 || connection_interval_min > 0x0c80 ||
      connection_interval_max < 0x6 || connection_interval_max > 0x0c80) {
    LOG_INFO(
        "connection_interval_min (0x%04x) and/or "
        "connection_interval_max (0x%04x) are outside the range"
        " of supported values (0x6 - 0x0c80)",
        connection_interval_min, connection_interval_max);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // The Connection_Interval_Min parameter shall not be greater than the
  // Connection_Interval_Max parameter.
  if (connection_interval_max < connection_interval_min) {
    LOG_INFO(
        "connection_interval_min (0x%04x) is larger than"
        " connection_interval_max (0x%04x)",
        connection_interval_min, connection_interval_max);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Note: no explicit error code stated for invalid max_latency
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (max_latency > 0x01f3) {
    LOG_INFO(
        "max_latency (0x%04x) is outside the range"
        " of supported values (0x0 - 0x01f3)",
        max_latency);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // Note: no explicit error code stated for invalid supervision timeout
  // values but assuming Unsupported Feature or Parameter Value (0x11)
  // error code based on similar advertising command.
  if (supervision_timeout < 0xa || supervision_timeout > 0x0c80) {
    LOG_INFO(
        "supervision_timeout (0x%04x) is outside the range"
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
    LOG_INFO(
        "supervision_timeout (%d ms) is smaller that the minimal supervision "
        "timeout allowed by connection_interval_max and max_latency (%u ms)",
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
    LOG_INFO(
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
    LOG_INFO(
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
    LOG_INFO("initiator is currently disabled");
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
    std::vector<bluetooth::hci::LeCreateConnPhyScanParameters>
        initiating_phy_parameters) {
  // Extended advertising commands are disallowed when legacy advertising
  // commands were used since the last reset.
  if (!SelectExtendedAdvertising()) {
    LOG_INFO(
        "extended advertising command rejected because legacy advertising"
        " is being used");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host issues this command when another
  // HCI_LE_Extended_Create_Connection command is pending in the Controller,
  // the Controller shall return the error code Command Disallowed (0x0C).
  if (initiator_.IsEnabled()) {
    LOG_INFO("initiator is currently enabled");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the Host specifies a PHY that is not supported by the Controller,
  // including a bit that is reserved for future use, the latter should return
  // the error code Unsupported Feature or Parameter Value (0x11).
  if ((initiating_phys & 0xf8) != 0) {
    LOG_INFO(
        "initiating_phys (%02x) enables PHYs that are not supported by"
        " the controller",
        initiating_phys);
    return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
  }

  // TODO(c++20) std::popcount
  if (__builtin_popcount(initiating_phys) !=
      int(initiating_phy_parameters.size())) {
    LOG_INFO(
        "initiating_phy_parameters (%zu)"
        " does not match initiating_phys (%02x)",
        initiating_phy_parameters.size(), initiating_phys);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // If the Initiating_PHYs parameter does not have at least one bit set for a
  // PHY allowed for scanning on the primary advertising physical channel, the
  // Controller shall return the error code
  // Invalid HCI Command Parameters (0x12).
  if (initiating_phys == 0) {
    LOG_INFO("initiating_phys is empty");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  for (auto const& parameter : initiating_phy_parameters) {
    // Note: no explicit error code stated for invalid interval and window
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.scan_interval_ < 0x4 || parameter.scan_interval_ > 0x4000 ||
        parameter.scan_window_ < 0x4 || parameter.scan_window_ > 0x4000) {
      LOG_INFO(
          "scan_interval (0x%04x) and/or "
          "scan_window (0x%04x) are outside the range"
          " of supported values (0x4 - 0x4000)",
          parameter.scan_interval_, parameter.scan_window_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // The LE_Scan_Window parameter shall be set to a value smaller or equal to
    // the value set for the LE_Scan_Interval parameter.
    if (parameter.scan_interval_ < parameter.scan_window_) {
      LOG_INFO("scan_window (0x%04x) is larger than scan_interval (0x%04x)",
               parameter.scan_window_, parameter.scan_interval_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    // Note: no explicit error code stated for invalid connection interval
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.conn_interval_min_ < 0x6 ||
        parameter.conn_interval_min_ > 0x0c80 ||
        parameter.conn_interval_max_ < 0x6 ||
        parameter.conn_interval_max_ > 0x0c80) {
      LOG_INFO(
          "connection_interval_min (0x%04x) and/or "
          "connection_interval_max (0x%04x) are outside the range"
          " of supported values (0x6 - 0x0c80)",
          parameter.conn_interval_min_, parameter.conn_interval_max_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // The Connection_Interval_Min parameter shall not be greater than the
    // Connection_Interval_Max parameter.
    if (parameter.conn_interval_max_ < parameter.conn_interval_min_) {
      LOG_INFO(
          "connection_interval_min (0x%04x) is larger than"
          " connection_interval_max (0x%04x)",
          parameter.conn_interval_min_, parameter.conn_interval_max_);
      return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
    }

    // Note: no explicit error code stated for invalid max_latency
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.conn_latency_ > 0x01f3) {
      LOG_INFO(
          "max_latency (0x%04x) is outside the range"
          " of supported values (0x0 - 0x01f3)",
          parameter.conn_latency_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // Note: no explicit error code stated for invalid supervision timeout
    // values but assuming Unsupported Feature or Parameter Value (0x11)
    // error code based on similar advertising command.
    if (parameter.supervision_timeout_ < 0xa ||
        parameter.supervision_timeout_ > 0x0c80) {
      LOG_INFO(
          "supervision_timeout (0x%04x) is outside the range"
          " of supported values (0xa - 0x0c80)",
          parameter.supervision_timeout_);
      return ErrorCode::UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE;
    }

    // The Supervision_Timeout in milliseconds shall be larger than
    // (1 + Max_Latency) * Connection_Interval_Max * 2, where
    // Connection_Interval_Max is given in milliseconds.
    milliseconds min_supervision_timeout = duration_cast<milliseconds>(
        (1 + parameter.conn_latency_) *
        slots(2 * parameter.conn_interval_max_) * 2);
    if (parameter.supervision_timeout_ * 10ms < min_supervision_timeout) {
      LOG_INFO(
          "supervision_timeout (%d ms) is smaller that the minimal supervision "
          "timeout allowed by connection_interval_max and max_latency (%u ms)",
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
    LOG_INFO(
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
    LOG_INFO(
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
            initiating_phy_parameters[offset].conn_interval_min_,
        .connection_interval_max =
            initiating_phy_parameters[offset].conn_interval_max_,
        .max_latency = initiating_phy_parameters[offset].conn_latency_,
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
            initiating_phy_parameters[offset].conn_interval_min_,
        .connection_interval_max =
            initiating_phy_parameters[offset].conn_interval_max_,
        .max_latency = initiating_phy_parameters[offset].conn_latency_,
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
            initiating_phy_parameters[offset].conn_interval_min_,
        .connection_interval_max =
            initiating_phy_parameters[offset].conn_interval_max_,
        .max_latency = initiating_phy_parameters[offset].conn_latency_,
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
    std::vector<uint8_t> const& extended_inquiry_response) {
  ASSERT(extended_inquiry_response.size() <= extended_inquiry_response_.size());
  extended_inquiry_response_.fill(0);
  std::copy(extended_inquiry_response.begin(), extended_inquiry_response.end(),
            extended_inquiry_response_.begin());
}

#ifdef ROOTCANAL_LMP
LinkLayerController::LinkLayerController(const Address& address,
                                         const ControllerProperties& properties)
    : address_(address),
      properties_(properties),
      lm_(nullptr, link_manager_destroy) {
  ops_ = {
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

      .extended_features =
          [](void* user, uint8_t features_page) {
            auto controller = static_cast<LinkLayerController*>(user);
            return controller->GetLmpFeatures(features_page);
          },

      .send_hci_event =
          [](void* user, const uint8_t* data, uintptr_t len) {
            auto controller = static_cast<LinkLayerController*>(user);

            auto event_code = static_cast<EventCode>(data[0]);
            auto payload = std::make_unique<bluetooth::packet::RawBuilder>(
                std::vector(data + 2, data + len));

            controller->send_event_(bluetooth::hci::EventBuilder::Create(
                event_code, std::move(payload)));
          },

      .send_lmp_packet =
          [](void* user, const uint8_t(*to)[6], const uint8_t* data,
             uintptr_t len) {
            auto controller = static_cast<LinkLayerController*>(user);

            auto payload = std::make_unique<bluetooth::packet::RawBuilder>(
                std::vector(data, data + len));

            Address source = controller->GetAddress();
            Address dest(*to);

            controller->SendLinkLayerPacket(model::packets::LmpBuilder::Create(
                source, dest, std::move(payload)));
          }};

  lm_.reset(link_manager_create(ops_));
}
#else
LinkLayerController::LinkLayerController(const Address& address,
                                         const ControllerProperties& properties)
    : address_(address), properties_(properties) {}
#endif

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
      LOG_INFO("Dropping unhandled command 0x%04x",
               static_cast<uint16_t>(opcode));
      return ErrorCode::UNKNOWN_HCI_COMMAND;
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SendCommandToRemoteByAddress(
    OpCode opcode, bluetooth::packet::PacketView<true> args,
    const Address& own_address, const Address& peer_address) {
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
      uint8_t page_number =
          (args.begin() + 2).extract<uint8_t>();  // skip the handle
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
      LOG_INFO("Dropping unhandled command 0x%04x",
               static_cast<uint16_t>(opcode));
      return ErrorCode::UNKNOWN_HCI_COMMAND;
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SendCommandToRemoteByHandle(
    OpCode opcode, bluetooth::packet::PacketView<true> args, uint16_t handle) {
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

  ScheduleTask(kNoDelayMs, [this, handle]() {
    std::vector<bluetooth::hci::CompletedPackets> completed_packets;
    bluetooth::hci::CompletedPackets cp;
    cp.connection_handle_ = handle;
    cp.host_num_of_completed_packets_ = kNumCommandPackets;
    completed_packets.push_back(cp);
    send_event_(bluetooth::hci::NumberOfCompletedPacketsBuilder::Create(
        completed_packets));
  });

  auto acl_payload = acl_packet.GetPayload();

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  std::vector<uint8_t> payload_bytes(acl_payload.begin(), acl_payload.end());

  uint16_t first_two_bytes =
      static_cast<uint16_t>(acl_packet.GetHandle()) +
      (static_cast<uint16_t>(acl_packet.GetPacketBoundaryFlag()) << 12) +
      (static_cast<uint16_t>(acl_packet.GetBroadcastFlag()) << 14);
  raw_builder_ptr->AddOctets2(first_two_bytes);
  raw_builder_ptr->AddOctets2(static_cast<uint16_t>(payload_bytes.size()));
  raw_builder_ptr->AddOctets(payload_bytes);

  auto acl = model::packets::AclBuilder::Create(my_address.GetAddress(),
                                                destination.GetAddress(),
                                                std::move(raw_builder_ptr));

  switch (phy) {
    case Phy::Type::BR_EDR:
      SendLinkLayerPacket(std::move(acl));
      break;
    case Phy::Type::LOW_ENERGY:
      SendLeLinkLayerPacket(std::move(acl));
      break;
  }
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
      source, destination,
      std::make_unique<bluetooth::packet::RawBuilder>(sco_data_bytes)));
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
    LOG_INFO("%s | Dropping packet not addressed to me %s->%s (type 0x%x)",
             address_.ToString().c_str(), source_address.ToString().c_str(),
             destination_address.ToString().c_str(),
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
    case model::packets::PacketType::DISCONNECT:
      IncomingDisconnectPacket(incoming);
      break;
#ifdef ROOTCANAL_LMP
    case model::packets::PacketType::LMP:
      IncomingLmpPacket(incoming);
      break;
#else
    case model::packets::PacketType::ENCRYPT_CONNECTION:
      IncomingEncryptConnection(incoming);
      break;
    case model::packets::PacketType::ENCRYPT_CONNECTION_RESPONSE:
      IncomingEncryptConnectionResponse(incoming);
      break;
    case model::packets::PacketType::IO_CAPABILITY_REQUEST:
      IncomingIoCapabilityRequestPacket(incoming);
      break;
    case model::packets::PacketType::IO_CAPABILITY_RESPONSE:
      IncomingIoCapabilityResponsePacket(incoming);
      break;
    case model::packets::PacketType::IO_CAPABILITY_NEGATIVE_RESPONSE:
      IncomingIoCapabilityNegativeResponsePacket(incoming);
      break;
    case PacketType::KEYPRESS_NOTIFICATION:
      IncomingKeypressNotificationPacket(incoming);
      break;
    case (model::packets::PacketType::PASSKEY):
      IncomingPasskeyPacket(incoming);
      break;
    case (model::packets::PacketType::PASSKEY_FAILED):
      IncomingPasskeyFailedPacket(incoming);
      break;
    case (model::packets::PacketType::PIN_REQUEST):
      IncomingPinRequestPacket(incoming);
      break;
    case (model::packets::PacketType::PIN_RESPONSE):
      IncomingPinResponsePacket(incoming);
      break;
#endif /* ROOTCANAL_LMP */
    case model::packets::PacketType::INQUIRY:
      if (inquiry_scan_enable_) {
        IncomingInquiryPacket(incoming, rssi);
      }
      break;
    case model::packets::PacketType::INQUIRY_RESPONSE:
      IncomingInquiryResponsePacket(incoming);
      break;
    case PacketType::ISO:
      IncomingIsoPacket(incoming);
      break;
    case PacketType::ISO_CONNECTION_REQUEST:
      IncomingIsoConnectionRequestPacket(incoming);
      break;
    case PacketType::ISO_CONNECTION_RESPONSE:
      IncomingIsoConnectionResponsePacket(incoming);
      break;
    case model::packets::PacketType::LE_LEGACY_ADVERTISING_PDU:
      IncomingLeLegacyAdvertisingPdu(incoming, rssi);
      return;
    case model::packets::PacketType::LE_EXTENDED_ADVERTISING_PDU:
      IncomingLeExtendedAdvertisingPdu(incoming, rssi);
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
    case (model::packets::PacketType::RSSI_WRAPPER):
      LOG_ERROR("Dropping double-wrapped RSSI packet");
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
    default:
      LOG_WARN("Dropping unhandled packet of type %s",
               model::packets::PacketTypeText(incoming.GetType()).c_str());
  }
}

void LinkLayerController::IncomingAclPacket(
    model::packets::LinkLayerPacketView incoming, int8_t rssi) {
  auto acl = model::packets::AclView::Create(incoming);
  ASSERT(acl.IsValid());
  auto payload = acl.GetPayload();
  std::shared_ptr<std::vector<uint8_t>> payload_bytes =
      std::make_shared<std::vector<uint8_t>>(payload.begin(), payload.end());

  LOG_INFO("Acl Packet [%d] %s -> %s", static_cast<int>(payload_bytes->size()),
           incoming.GetSourceAddress().ToString().c_str(),
           incoming.GetDestinationAddress().ToString().c_str());

  bluetooth::hci::PacketView<bluetooth::hci::kLittleEndian> raw_packet(
      payload_bytes);
  auto acl_view = bluetooth::hci::AclView::Create(raw_packet);
  ASSERT(acl_view.IsValid());

  uint16_t local_handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());

  if (local_handle == kReservedHandle) {
      LOG_INFO("Dropping packet since connection does not exist");
      return;
  }

  // Update the RSSI for the local ACL connection.
  connections_.SetRssi(local_handle, rssi);

  std::vector<uint8_t> payload_data(acl_view.GetPayload().begin(),
                                    acl_view.GetPayload().end());
  uint16_t acl_buffer_size = properties_.acl_data_packet_length;
  int num_packets =
      (payload_data.size() + acl_buffer_size - 1) / acl_buffer_size;

  auto pb_flag_controller_to_host = acl_view.GetPacketBoundaryFlag();
  if (pb_flag_controller_to_host ==
      bluetooth::hci::PacketBoundaryFlag::FIRST_NON_AUTOMATICALLY_FLUSHABLE) {
    pb_flag_controller_to_host =
        bluetooth::hci::PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
  }
  for (int i = 0; i < num_packets; i++) {
    size_t start_index = acl_buffer_size * i;
    size_t end_index =
        std::min(start_index + acl_buffer_size, payload_data.size());
    std::vector<uint8_t> fragment(payload_data.begin() + start_index,
                                  payload_data.begin() + end_index);
    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>(fragment);
    auto acl_packet = bluetooth::hci::AclBuilder::Create(
        local_handle, pb_flag_controller_to_host, acl_view.GetBroadcastFlag(),
        std::move(raw_builder_ptr));
    pb_flag_controller_to_host =
        bluetooth::hci::PacketBoundaryFlag::CONTINUING_FRAGMENT;

    send_acl_(std::move(acl_packet));
  }
}

void LinkLayerController::IncomingScoPacket(
    model::packets::LinkLayerPacketView incoming) {
  Address source = incoming.GetSourceAddress();
  uint16_t sco_handle = connections_.GetScoHandle(source);
  if (!connections_.HasScoHandle(sco_handle)) {
    LOG_INFO("Spurious SCO packet from %s", source.ToString().c_str());
    return;
  }

  auto sco = model::packets::ScoView::Create(incoming);
  ASSERT(sco.IsValid());
  auto sco_data = sco.GetPayload();
  std::vector<uint8_t> sco_data_bytes(sco_data.begin(), sco_data.end());

  LOG_INFO("Sco Packet [%d] %s -> %s", static_cast<int>(sco_data_bytes.size()),
           incoming.GetSourceAddress().ToString().c_str(),
           incoming.GetDestinationAddress().ToString().c_str());

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
    LOG_INFO("Discarding response from a disconnected device %s",
             source.ToString().c_str());
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
    LOG_INFO("Discarding response from a disconnected device %s",
             source.ToString().c_str());
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
    LOG_INFO("Discarding response from a disconnected device %s",
             source.ToString().c_str());
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
    LOG_INFO("Discarding response from a disconnected device %s",
             source.ToString().c_str());
    return;
  }
  if (IsEventUnmasked(EventCode::READ_CLOCK_OFFSET_COMPLETE)) {
    send_event_(bluetooth::hci::ReadClockOffsetCompleteBuilder::Create(
        ErrorCode::SUCCESS, handle, view.GetOffset()));
  }
}

void LinkLayerController::IncomingDisconnectPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("Disconnect Packet");
  auto disconnect = model::packets::DisconnectView::Create(incoming);
  ASSERT(disconnect.IsValid());

  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    LOG_INFO("Discarding disconnect from a disconnected device %s",
             peer.ToString().c_str());
    return;
  }
#ifdef ROOTCANAL_LMP
  auto is_br_edr = connections_.GetPhyType(handle) == Phy::Type::BR_EDR;
#endif
  ASSERT_LOG(
      connections_.Disconnect(
          handle, [this](TaskId task_id) { CancelScheduledTask(task_id); }),
      "GetHandle() returned invalid handle %hx", handle);

  uint8_t reason = disconnect.GetReason();
  SendDisconnectionCompleteEvent(handle, ErrorCode(reason));
#ifdef ROOTCANAL_LMP
  if (is_br_edr) {
    ASSERT(link_manager_remove_link(
        lm_.get(), reinterpret_cast<uint8_t(*)[6]>(peer.data())));
  }
#endif
}

#ifndef ROOTCANAL_LMP
void LinkLayerController::IncomingEncryptConnection(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("IncomingEncryptConnection");

  // TODO: Check keys
  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    LOG_INFO("Unknown connection @%s", peer.ToString().c_str());
    return;
  }
  if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
    send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
        ErrorCode::SUCCESS, handle, bluetooth::hci::EncryptionEnabled::ON));
  }

  uint16_t count = security_manager_.ReadKey(peer);
  if (count == 0) {
    LOG_ERROR("NO KEY HERE for %s", peer.ToString().c_str());
    return;
  }
  auto array = security_manager_.GetKey(peer);
  std::vector<uint8_t> key_vec{array.begin(), array.end()};
  SendLinkLayerPacket(model::packets::EncryptConnectionResponseBuilder::Create(
      GetAddress(), peer, key_vec));
}

void LinkLayerController::IncomingEncryptConnectionResponse(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("IncomingEncryptConnectionResponse");
  // TODO: Check keys
  uint16_t handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  if (handle == kReservedHandle) {
    LOG_INFO("Unknown connection @%s",
             incoming.GetSourceAddress().ToString().c_str());
    return;
  }
  if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
    send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
        ErrorCode::SUCCESS, handle, bluetooth::hci::EncryptionEnabled::ON));
  }
}
#endif /* !ROOTCANAL_LMP */

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
      LOG_WARN("Unhandled Incoming Inquiry of type %d",
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

      send_event_(bluetooth::hci::ExtendedInquiryResultRawBuilder::Create(
          inquiry_response.GetSourceAddress(),
          static_cast<bluetooth::hci::PageScanRepetitionMode>(
              inquiry_response.GetPageScanRepetitionMode()),
          inquiry_response.GetClassOfDevice(),
          inquiry_response.GetClockOffset(), inquiry_response.GetRssi(),
          extended_inquiry_response_));
    } break;
    default:
      LOG_WARN("Unhandled Incoming Inquiry Response of type %d",
               static_cast<int>(basic_inquiry_response.GetInquiryType()));
  }
}

#ifndef ROOTCANAL_LMP
void LinkLayerController::IncomingIoCapabilityRequestPacket(
    model::packets::LinkLayerPacketView incoming) {
  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandle(AddressWithType(
      peer, bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS));
  if (handle == kReservedHandle) {
    LOG_INFO("Device not connected %s", peer.ToString().c_str());
    return;
  }

  if (!secure_simple_pairing_host_support_) {
    LOG_WARN("Trying PIN pairing for %s",
             incoming.GetDestinationAddress().ToString().c_str());
    SendLinkLayerPacket(
        model::packets::IoCapabilityNegativeResponseBuilder::Create(
            incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
            static_cast<uint8_t>(
                ErrorCode::UNSUPPORTED_REMOTE_OR_LMP_FEATURE)));
    if (!security_manager_.AuthenticationInProgress()) {
      security_manager_.AuthenticationRequest(incoming.GetSourceAddress(),
                                              handle, false);
    }
    security_manager_.SetPinRequested(peer);
    if (IsEventUnmasked(EventCode::PIN_CODE_REQUEST)) {
      send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(
          incoming.GetSourceAddress()));
    }
    return;
  }

  auto request = model::packets::IoCapabilityRequestView::Create(incoming);
  ASSERT(request.IsValid());

  uint8_t io_capability = request.GetIoCapability();
  uint8_t oob_data_present = request.GetOobDataPresent();
  uint8_t authentication_requirements = request.GetAuthenticationRequirements();

  if (IsEventUnmasked(EventCode::IO_CAPABILITY_RESPONSE)) {
    send_event_(bluetooth::hci::IoCapabilityResponseBuilder::Create(
        peer, static_cast<bluetooth::hci::IoCapability>(io_capability),
        static_cast<bluetooth::hci::OobDataPresent>(oob_data_present),
        static_cast<bluetooth::hci::AuthenticationRequirements>(
            authentication_requirements)));
  }

  bool pairing_started = security_manager_.AuthenticationInProgress();
  if (!pairing_started) {
    security_manager_.AuthenticationRequest(peer, handle, false);
    StartSimplePairing(peer);
  }

  security_manager_.SetPeerIoCapability(peer, io_capability, oob_data_present,
                                        authentication_requirements);
  if (pairing_started) {
    PairingType pairing_type = security_manager_.GetSimplePairingType();
    if (pairing_type != PairingType::INVALID) {
      ScheduleTask(kNoDelayMs, [this, peer, pairing_type]() {
        AuthenticateRemoteStage1(peer, pairing_type);
      });
    } else {
      LOG_INFO("Security Manager returned INVALID");
    }
  }
}

void LinkLayerController::IncomingIoCapabilityResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto response = model::packets::IoCapabilityResponseView::Create(incoming);
  ASSERT(response.IsValid());
  if (!secure_simple_pairing_host_support_) {
    LOG_WARN("Only simple pairing mode is implemented");
    SendLinkLayerPacket(
        model::packets::IoCapabilityNegativeResponseBuilder::Create(
            incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
            static_cast<uint8_t>(
                ErrorCode::UNSUPPORTED_REMOTE_OR_LMP_FEATURE)));
    return;
  }

  Address peer = incoming.GetSourceAddress();
  uint8_t io_capability = response.GetIoCapability();
  uint8_t oob_data_present = response.GetOobDataPresent();
  uint8_t authentication_requirements =
      response.GetAuthenticationRequirements();

  security_manager_.SetPeerIoCapability(peer, io_capability, oob_data_present,
                                        authentication_requirements);

  if (IsEventUnmasked(EventCode::IO_CAPABILITY_RESPONSE)) {
    send_event_(bluetooth::hci::IoCapabilityResponseBuilder::Create(
        peer, static_cast<bluetooth::hci::IoCapability>(io_capability),
        static_cast<bluetooth::hci::OobDataPresent>(oob_data_present),
        static_cast<bluetooth::hci::AuthenticationRequirements>(
            authentication_requirements)));
  }

  PairingType pairing_type = security_manager_.GetSimplePairingType();
  if (pairing_type != PairingType::INVALID) {
    ScheduleTask(kNoDelayMs, [this, peer, pairing_type]() {
      AuthenticateRemoteStage1(peer, pairing_type);
    });
  } else {
    LOG_INFO("Security Manager returned INVALID");
  }
}

void LinkLayerController::IncomingIoCapabilityNegativeResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  Address peer = incoming.GetSourceAddress();

  ASSERT(security_manager_.GetAuthenticationAddress() == peer);

  security_manager_.InvalidateIoCapabilities();
  LOG_INFO("%s doesn't support SSP, try PIN",
           incoming.GetSourceAddress().ToString().c_str());
  security_manager_.SetPinRequested(peer);
  if (IsEventUnmasked(EventCode::PIN_CODE_REQUEST)) {
    send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(
        incoming.GetSourceAddress()));
  }
}
#endif /* !ROOTCANAL_LMP */

void LinkLayerController::IncomingIsoPacket(LinkLayerPacketView incoming) {
  auto iso = IsoDataPacketView::Create(incoming);
  ASSERT(iso.IsValid());

  uint16_t cis_handle = iso.GetHandle();
  if (!connections_.HasCisHandle(cis_handle)) {
    LOG_INFO("Dropping ISO packet to unknown handle 0x%hx", cis_handle);
    return;
  }
  if (!connections_.HasConnectedCis(cis_handle)) {
    LOG_INFO("Dropping ISO packet to a disconnected handle 0x%hx", cis_handle);
    return;
  }

  auto sc = iso.GetSc();
  switch (sc) {
    case StartContinuation::START: {
      auto iso_start = IsoStartView::Create(iso);
      ASSERT(iso_start.IsValid());
      if (iso.GetCmplt() == Complete::COMPLETE) {
        send_iso_(bluetooth::hci::IsoWithoutTimestampBuilder::Create(
            cis_handle, bluetooth::hci::IsoPacketBoundaryFlag::COMPLETE_SDU,
            0 /* seq num */, bluetooth::hci::IsoPacketStatusFlag::VALID,
            std::make_unique<bluetooth::packet::RawBuilder>(
                std::vector<uint8_t>(iso_start.GetPayload().begin(),
                                     iso_start.GetPayload().end()))));
      } else {
        send_iso_(bluetooth::hci::IsoWithoutTimestampBuilder::Create(
            cis_handle, bluetooth::hci::IsoPacketBoundaryFlag::FIRST_FRAGMENT,
            0 /* seq num */, bluetooth::hci::IsoPacketStatusFlag::VALID,
            std::make_unique<bluetooth::packet::RawBuilder>(
                std::vector<uint8_t>(iso_start.GetPayload().begin(),
                                     iso_start.GetPayload().end()))));
      }
    } break;
    case StartContinuation::CONTINUATION: {
      auto continuation = IsoContinuationView::Create(iso);
      ASSERT(continuation.IsValid());
      if (iso.GetCmplt() == Complete::COMPLETE) {
        send_iso_(bluetooth::hci::IsoWithoutTimestampBuilder::Create(
            cis_handle, bluetooth::hci::IsoPacketBoundaryFlag::LAST_FRAGMENT,
            0 /* seq num */, bluetooth::hci::IsoPacketStatusFlag::VALID,
            std::make_unique<bluetooth::packet::RawBuilder>(
                std::vector<uint8_t>(continuation.GetPayload().begin(),
                                     continuation.GetPayload().end()))));
      } else {
        send_iso_(bluetooth::hci::IsoWithoutTimestampBuilder::Create(
            cis_handle,
            bluetooth::hci::IsoPacketBoundaryFlag::CONTINUATION_FRAGMENT,
            0 /* seq num */, bluetooth::hci::IsoPacketStatusFlag::VALID,
            std::make_unique<bluetooth::packet::RawBuilder>(
                std::vector<uint8_t>(continuation.GetPayload().begin(),
                                     continuation.GetPayload().end()))));
      }
    } break;
  }
}

void LinkLayerController::HandleIso(bluetooth::hci::IsoView iso) {
  auto cis_handle = iso.GetConnectionHandle();
  if (!connections_.HasCisHandle(cis_handle)) {
    LOG_INFO("Dropping ISO packet to unknown handle 0x%hx", cis_handle);
    return;
  }
  if (!connections_.HasConnectedCis(cis_handle)) {
    LOG_INFO("Dropping ISO packet to disconnected handle 0x%hx", cis_handle);
    return;
  }

  auto acl_handle = connections_.GetAclHandleForCisHandle(cis_handle);
  uint16_t remote_handle =
      connections_.GetRemoteCisHandleForCisHandle(cis_handle);
  model::packets::StartContinuation start_flag =
      model::packets::StartContinuation::START;
  model::packets::Complete complete_flag = model::packets::Complete::COMPLETE;
  switch (iso.GetPbFlag()) {
    case bluetooth::hci::IsoPacketBoundaryFlag::COMPLETE_SDU:
      start_flag = model::packets::StartContinuation::START;
      complete_flag = model::packets::Complete::COMPLETE;
      break;
    case bluetooth::hci::IsoPacketBoundaryFlag::CONTINUATION_FRAGMENT:
      start_flag = model::packets::StartContinuation::CONTINUATION;
      complete_flag = model::packets::Complete::INCOMPLETE;
      break;
    case bluetooth::hci::IsoPacketBoundaryFlag::FIRST_FRAGMENT:
      start_flag = model::packets::StartContinuation::START;
      complete_flag = model::packets::Complete::INCOMPLETE;
      break;
    case bluetooth::hci::IsoPacketBoundaryFlag::LAST_FRAGMENT:
      start_flag = model::packets::StartContinuation::CONTINUATION;
      complete_flag = model::packets::Complete::INCOMPLETE;
      break;
  }
  if (start_flag == model::packets::StartContinuation::START) {
    if (iso.GetTsFlag() == bluetooth::hci::TimeStampFlag::PRESENT) {
      auto timestamped = bluetooth::hci::IsoWithTimestampView::Create(iso);
      ASSERT(timestamped.IsValid());
      uint32_t timestamp = timestamped.GetTimeStamp();
      std::unique_ptr<bluetooth::packet::RawBuilder> payload =
          std::make_unique<bluetooth::packet::RawBuilder>();
      for (const auto it : timestamped.GetPayload()) {
        payload->AddOctets1(it);
      }

      SendLeLinkLayerPacket(model::packets::IsoStartBuilder::Create(
          connections_.GetOwnAddress(acl_handle).GetAddress(),
          connections_.GetAddress(acl_handle).GetAddress(), remote_handle,
          complete_flag, timestamp, std::move(payload)));
    } else {
      auto pkt = bluetooth::hci::IsoWithoutTimestampView::Create(iso);
      ASSERT(pkt.IsValid());

      auto payload =
          std::make_unique<bluetooth::packet::RawBuilder>(std::vector<uint8_t>(
              pkt.GetPayload().begin(), pkt.GetPayload().end()));

      SendLeLinkLayerPacket(model::packets::IsoStartBuilder::Create(
          connections_.GetOwnAddress(acl_handle).GetAddress(),
          connections_.GetAddress(acl_handle).GetAddress(), remote_handle,
          complete_flag, 0, std::move(payload)));
    }
  } else {
    auto pkt = bluetooth::hci::IsoWithoutTimestampView::Create(iso);
    ASSERT(pkt.IsValid());
    std::unique_ptr<bluetooth::packet::RawBuilder> payload =
        std::make_unique<bluetooth::packet::RawBuilder>(std::vector<uint8_t>(
            pkt.GetPayload().begin(), pkt.GetPayload().end()));
    SendLeLinkLayerPacket(model::packets::IsoContinuationBuilder::Create(
        connections_.GetOwnAddress(acl_handle).GetAddress(),
        connections_.GetAddress(acl_handle).GetAddress(), remote_handle,
        complete_flag, std::move(payload)));
  }
}

void LinkLayerController::IncomingIsoConnectionRequestPacket(
    LinkLayerPacketView incoming) {
  auto req = IsoConnectionRequestView::Create(incoming);
  ASSERT(req.IsValid());
  std::vector<bluetooth::hci::CisParametersConfig> stream_configs;
  bluetooth::hci::CisParametersConfig stream_config;

  stream_config.max_sdu_m_to_s_ = req.GetMaxSduMToS();
  stream_config.max_sdu_s_to_m_ = req.GetMaxSduSToM();

  stream_configs.push_back(stream_config);

  uint8_t group_id = req.GetCigId();

  /* CIG should be created by the local host before use */
  bluetooth::hci::CreateCisConfig config;
  config.cis_connection_handle_ = req.GetRequesterCisHandle();

  config.acl_connection_handle_ =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  connections_.CreatePendingCis(config);
  connections_.SetRemoteCisHandle(config.cis_connection_handle_,
                                  req.GetRequesterCisHandle());
  if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
    send_event_(bluetooth::hci::LeCisRequestBuilder::Create(
        config.acl_connection_handle_, config.cis_connection_handle_, group_id,
        req.GetId()));
  }
}

void LinkLayerController::IncomingIsoConnectionResponsePacket(
    LinkLayerPacketView incoming) {
  auto response = IsoConnectionResponseView::Create(incoming);
  ASSERT(response.IsValid());

  bluetooth::hci::CreateCisConfig config;
  config.acl_connection_handle_ = response.GetRequesterAclHandle();
  config.cis_connection_handle_ = response.GetRequesterCisHandle();
  if (!connections_.HasPendingCisConnection(config.cis_connection_handle_)) {
    LOG_INFO("Ignoring connection response with unknown CIS handle 0x%04hx",
             config.cis_connection_handle_);
    return;
  }
  ErrorCode status = static_cast<ErrorCode>(response.GetStatus());
  if (status != ErrorCode::SUCCESS) {
    if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
      send_event_(bluetooth::hci::LeCisEstablishedBuilder::Create(
          status, config.cis_connection_handle_, 0, 0, 0, 0,
          bluetooth::hci::SecondaryPhyType::NO_PACKETS,
          bluetooth::hci::SecondaryPhyType::NO_PACKETS, 0, 0, 0, 0, 0, 0, 0,
          0));
    }
    return;
  }
  connections_.SetRemoteCisHandle(config.cis_connection_handle_,
                                  response.GetResponderCisHandle());
  connections_.ConnectCis(config.cis_connection_handle_);
  auto stream_parameters =
      connections_.GetStreamParameters(config.cis_connection_handle_);
  auto group_parameters =
      connections_.GetGroupParameters(stream_parameters.group_id);
  // TODO: Which of these are important enough to fake?
  uint32_t cig_sync_delay = 0x100;
  uint32_t cis_sync_delay = 0x200;
  uint32_t latency_m_to_s = group_parameters.max_transport_latency_m_to_s;
  uint32_t latency_s_to_m = group_parameters.max_transport_latency_s_to_m;
  uint8_t nse = 1;
  uint8_t bn_m_to_s = 0;
  uint8_t bn_s_to_m = 0;
  uint8_t ft_m_to_s = 0;
  uint8_t ft_s_to_m = 0;
  uint8_t max_pdu_m_to_s = 0x40;
  uint8_t max_pdu_s_to_m = 0x40;
  uint16_t iso_interval = 0x100;
  if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
    send_event_(bluetooth::hci::LeCisEstablishedBuilder::Create(
        status, config.cis_connection_handle_, cig_sync_delay, cis_sync_delay,
        latency_m_to_s, latency_s_to_m,
        bluetooth::hci::SecondaryPhyType::NO_PACKETS,
        bluetooth::hci::SecondaryPhyType::NO_PACKETS, nse, bn_m_to_s, bn_s_to_m,
        ft_m_to_s, ft_s_to_m, max_pdu_m_to_s, max_pdu_s_to_m, iso_interval));
  }
}

#ifndef ROOTCANAL_LMP
void LinkLayerController::IncomingKeypressNotificationPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto keypress = model::packets::KeypressNotificationView::Create(incoming);
  ASSERT(keypress.IsValid());
  auto notification_type = keypress.GetNotificationType();
  if (notification_type >
      model::packets::PasskeyNotificationType::ENTRY_COMPLETED) {
    LOG_WARN("Dropping unknown notification type %d",
             static_cast<int>(notification_type));
    return;
  }
  if (IsEventUnmasked(EventCode::KEYPRESS_NOTIFICATION)) {
    send_event_(bluetooth::hci::KeypressNotificationBuilder::Create(
        incoming.GetSourceAddress(),
        static_cast<bluetooth::hci::KeypressNotificationType>(
            notification_type)));
  }
}
#endif /* !ROOTCANAL_LMP */

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
  LOG_INFO("RPA %s", rpa.ToString().c_str());
  return rpa;
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
      ResolvePrivateAddress(advertising_address, IrkSelection::Peer)
          .value_or(advertising_address);

  std::optional<AddressWithType> resolved_target_address =
      ResolvePrivateAddress(target_address, IrkSelection::Peer);

  if (resolved_advertising_address != advertising_address) {
    LOG_VERB("Resolved the advertising address %s(%hhx) to %s(%hhx)",
             advertising_address.ToString().c_str(),
             advertising_address.GetAddressType(),
             resolved_advertising_address.ToString().c_str(),
             resolved_advertising_address.GetAddressType());
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
        LOG_VERB(
            "Legacy advertising ignored by scanner because the advertising "
            "address %s(%hhx) is not in the filter accept list",
            resolved_advertising_address.ToString().c_str(),
            resolved_advertising_address.GetAddressType());
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
        if (!IsLocalPublicOrRandomAddress(target_address) &&
            !(target_address.IsRpa() && resolved_target_address)) {
          LOG_VERB(
              "Legacy advertising ignored by scanner because the directed "
              "address %s(%hhx) does not match the current device or cannot be "
              "resolved",
              target_address.ToString().c_str(),
              target_address.GetAddressType());
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
          LOG_VERB(
              "Legacy advertising ignored by scanner because the directed "
              "address %s(%hhx) does not match the current device or is not a "
              "resovable private address",
              target_address.ToString().c_str(),
              target_address.GetAddressType());
          return;
        }
        should_send_directed_advertising_report =
            target_address.IsRpa() && !resolved_target_address;
        break;
    }
  }

  bool should_send_advertising_report = true;
  if (scanner_.filter_duplicates !=
      bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(pdu)) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(pdu);
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
    bluetooth::hci::LeAdvertisingResponseRaw response;
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

    send_event_(
        bluetooth::hci::LeAdvertisingReportRawBuilder::Create({response}));
  }

  // Extended scanning.
  if (ExtendedAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponseRaw response;
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

    send_event_(bluetooth::hci::LeExtendedAdvertisingReportRawBuilder::Create(
        {response}));
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
    LOG_VERB(
        "Not sending LE Scan request to advertising address %s(%hhx) because "
        "it is not scannable",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType());
  } else if (!active_scanning) {
    LOG_VERB(
        "Not sending LE Scan request to advertising address %s(%hhx) because "
        "the scanner is passive",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType());
  } else if (scanner_.pending_scan_request) {
    LOG_VERB(
        "Not sending LE Scan request to advertising address %s(%hhx) because "
        "an LE Scan request is already pending",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType());
  } else if (!should_send_advertising_report) {
    LOG_VERB(
        "Not sending LE Scan request to advertising address %s(%hhx) because "
        "the advertising message was filtered",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType());
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
    scanner_.pending_scan_request = advertising_address;

    LOG_INFO(
        "Sending LE Scan request to advertising address %s(%hhx) with scanning "
        "address %s(%hhx)",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType(),
        scanning_address.ToString().c_str(), scanning_address.GetAddressType());

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
    LOG_VERB(
        "Legacy advertising ignored by initiator because it is not "
        "connectable");
    return;
  }
  if (initiator_.pending_connect_request) {
    LOG_VERB(
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
      ResolvePrivateAddress(advertising_address, IrkSelection::Peer)
          .value_or(advertising_address);

  AddressWithType resolved_target_address =
      ResolvePrivateAddress(target_address, IrkSelection::Peer)
          .value_or(target_address);

  // Vol 6, Part B § 4.3.5 Initiator filter policy.
  switch (initiator_.initiator_filter_policy) {
    case bluetooth::hci::InitiatorFilterPolicy::USE_PEER_ADDRESS:
      if (resolved_advertising_address != initiator_.peer_address) {
        LOG_VERB(
            "Legacy advertising ignored by initiator because the "
            "advertising address %s does not match the peer address %s",
            resolved_advertising_address.ToString().c_str(),
            initiator_.peer_address.ToString().c_str());
        return;
      }
      break;
    case bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST:
      if (!LeFilterAcceptListContainsDevice(resolved_advertising_address)) {
        LOG_VERB(
            "Legacy advertising ignored by initiator because the "
            "advertising address %s is not in the filter accept list",
            resolved_advertising_address.ToString().c_str());
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
    if (!IsLocalPublicOrRandomAddress(resolved_target_address)) {
      LOG_VERB(
          "Directed legacy advertising ignored by initiator because the "
          "target address %s does not match the current device addresses",
          resolved_advertising_address.ToString().c_str());
      return;
    }
    if (resolved_target_address == target_address &&
        (initiator_.own_address_type ==
             OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS ||
         initiator_.own_address_type ==
             OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS)) {
      LOG_VERB(
          "Directed legacy advertising ignored by initiator because the "
          "target address %s is static or public and the initiator is "
          "configured to use resolvable addresses",
          resolved_advertising_address.ToString().c_str());
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
    LOG_WARN("CreatePendingLeConnection failed for connection to %s",
             advertising_address.ToString().c_str());
  }

  initiator_.pending_connect_request = advertising_address;

  LOG_INFO("Sending LE Connect request to %s with initiating address %s",
           resolved_advertising_address.ToString().c_str(),
           initiating_address.ToString().c_str());

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
    LOG_VERB("Extended advertising ignored because the scanner is legacy");
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
      ResolvePrivateAddress(advertising_address, IrkSelection::Peer)
          .value_or(advertising_address);

  std::optional<AddressWithType> resolved_target_address =
      ResolvePrivateAddress(target_address, IrkSelection::Peer);

  if (resolved_advertising_address != advertising_address) {
    LOG_VERB("Resolved the advertising address %s(%hhx) to %s(%hhx)",
             advertising_address.ToString().c_str(),
             advertising_address.GetAddressType(),
             resolved_advertising_address.ToString().c_str(),
             resolved_advertising_address.GetAddressType());
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
        LOG_VERB(
            "Extended advertising ignored by scanner because the advertising "
            "address %s(%hhx) is not in the filter accept list",
            resolved_advertising_address.ToString().c_str(),
            resolved_advertising_address.GetAddressType());
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
        if (!IsLocalPublicOrRandomAddress(target_address) &&
            !(target_address.IsRpa() && resolved_target_address)) {
          LOG_VERB(
              "Extended advertising ignored by scanner because the directed "
              "address %s(%hhx) does not match the current device or cannot be "
              "resolved",
              target_address.ToString().c_str(),
              target_address.GetAddressType());
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
          LOG_VERB(
              "Extended advertising ignored by scanner because the directed "
              "address %s(%hhx) does not match the current device or is not a "
              "resovable private address",
              target_address.ToString().c_str(),
              target_address.GetAddressType());
          return;
        }
        break;
    }
  }

  bool should_send_advertising_report = true;
  if (scanner_.filter_duplicates !=
      bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(pdu)) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(pdu);
    }
  }

  if (should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponseRaw response;
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
      send_event_(bluetooth::hci::LeExtendedAdvertisingReportRawBuilder::Create(
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
    LOG_VERB(
        "Not sending LE Scan request to advertising address %s(%hhx) because "
        "it is not scannable",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType());
  } else if (!active_scanning) {
    LOG_VERB(
        "Not sending LE Scan request to advertising address %s(%hhx) because "
        "the scanner is passive",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType());
  } else if (scanner_.pending_scan_request) {
    LOG_VERB(
        "Not sending LE Scan request to advertising address %s(%hhx) because "
        "an LE Scan request is already pending",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType());
  } else if (!should_send_advertising_report) {
    LOG_VERB(
        "Not sending LE Scan request to advertising address %s(%hhx) because "
        "the advertising message was filtered",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType());
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
    scanner_.pending_scan_request = advertising_address;

    LOG_INFO(
        "Sending LE Scan request to advertising address %s(%hhx) with scanning "
        "address %s(%hhx)",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType(),
        scanning_address.ToString().c_str(), scanning_address.GetAddressType());

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
    LOG_VERB("Extended advertising ignored because the initiator is legacy");
    return;
  }

  // Connection.
  // Note: only send CONNECT requests in response to connectable advertising
  // events (ADV_IND, ADV_DIRECT_IND).
  if (!pdu.GetConnectable()) {
    LOG_VERB(
        "Extended advertising ignored by initiator because it is not "
        "connectable");
    return;
  }
  if (initiator_.pending_connect_request) {
    LOG_VERB(
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
      ResolvePrivateAddress(advertising_address, IrkSelection::Peer)
          .value_or(advertising_address);

  AddressWithType resolved_target_address =
      ResolvePrivateAddress(target_address, IrkSelection::Peer)
          .value_or(target_address);

  // Vol 6, Part B § 4.3.5 Initiator filter policy.
  switch (initiator_.initiator_filter_policy) {
    case bluetooth::hci::InitiatorFilterPolicy::USE_PEER_ADDRESS:
      if (resolved_advertising_address != initiator_.peer_address) {
        LOG_VERB(
            "Extended advertising ignored by initiator because the "
            "advertising address %s does not match the peer address %s",
            resolved_advertising_address.ToString().c_str(),
            initiator_.peer_address.ToString().c_str());
        return;
      }
      break;
    case bluetooth::hci::InitiatorFilterPolicy::USE_FILTER_ACCEPT_LIST:
      if (!LeFilterAcceptListContainsDevice(resolved_advertising_address)) {
        LOG_VERB(
            "Extended advertising ignored by initiator because the "
            "advertising address %s is not in the filter accept list",
            resolved_advertising_address.ToString().c_str());
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
    if (!IsLocalPublicOrRandomAddress(resolved_target_address)) {
      LOG_VERB(
          "Directed extended advertising ignored by initiator because the "
          "target address %s does not match the current device addresses",
          resolved_advertising_address.ToString().c_str());
      return;
    }
    if (resolved_target_address == target_address &&
        (initiator_.own_address_type ==
             OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS ||
         initiator_.own_address_type ==
             OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS)) {
      LOG_VERB(
          "Directed extended advertising ignored by initiator because the "
          "target address %s is static or public and the initiator is "
          "configured to use resolvable addresses",
          resolved_advertising_address.ToString().c_str());
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
    LOG_WARN("CreatePendingLeConnection failed for connection to %s",
             advertising_address.ToString().c_str());
  }

  initiator_.pending_connect_request = advertising_address;

  LOG_INFO("Sending LE Connect request to %s with initiating address %s",
           resolved_advertising_address.ToString().c_str(),
           initiating_address.ToString().c_str());

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

void LinkLayerController::IncomingScoConnectionRequest(
    model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto request = model::packets::ScoConnectionRequestView::Create(incoming);
  ASSERT(request.IsValid());

  LOG_INFO("Received eSCO connection request from %s",
           address.ToString().c_str());

  // Automatically reject if connection request was already sent
  // from the current device.
  if (connections_.HasPendingScoConnection(address)) {
    LOG_INFO(
        "Rejecting eSCO connection request from %s, "
        "an eSCO connection already exist with this device",
        address.ToString().c_str());

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

  LOG_INFO("Received eSCO connection response with status 0x%02x from %s",
           static_cast<unsigned>(status),
           incoming.GetSourceAddress().ToString().c_str());

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

  LOG_INFO(
      "Received eSCO disconnection request with"
      " reason 0x%02x from %s",
      static_cast<unsigned>(reason),
      incoming.GetSourceAddress().ToString().c_str());

  if (handle != kReservedHandle) {
    connections_.Disconnect(
        handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
    SendDisconnectionCompleteEvent(handle, ErrorCode(reason));
  }
}

#ifdef ROOTCANAL_LMP
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
#endif /* ROOTCANAL_LMP */

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
    LOG_WARN("No pending connection for connection from %s",
             address.ToString().c_str());
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
      if (peer_resolved_address.GetAddressType() ==
          AddressType::PUBLIC_DEVICE_ADDRESS) {
        peer_address_type = AddressType::PUBLIC_IDENTITY_ADDRESS;
      } else if (peer_resolved_address.GetAddressType() ==
                 AddressType::RANDOM_DEVICE_ADDRESS) {
        peer_address_type = AddressType::RANDOM_IDENTITY_ADDRESS;
      } else {
        LOG_WARN("Unhandled resolved address type %s -> %s",
                 address.ToString().c_str(),
                 peer_resolved_address.ToString().c_str());
      }
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
    LOG_VERB(
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
    LOG_VERB(
        "LE Connect request ignored by legacy advertiser because the "
        "advertising address %s(%hhx) does not match %s(%hhx)",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType(),
        legacy_advertiser_.GetAdvertisingAddress().ToString().c_str(),
        legacy_advertiser_.GetAdvertisingAddress().GetAddressType());
    return false;
  }

  // When an advertiser receives a connection request that contains a resolvable
  // private address for the initiator’s address (InitA field) and address
  // resolution is enabled, the Link Layer shall resolve the private address.
  // The advertising filter policy shall then determine if the
  // advertiser establishes a connection.
  AddressWithType resolved_initiating_address =
      ResolvePrivateAddress(initiating_address, IrkSelection::Peer)
          .value_or(initiating_address);

  if (resolved_initiating_address != initiating_address) {
    LOG_VERB("Resolved the initiating address %s(%hhx) to %s(%hhx)",
             initiating_address.ToString().c_str(),
             initiating_address.GetAddressType(),
             resolved_initiating_address.ToString().c_str(),
             resolved_initiating_address.GetAddressType());
  }

  // When the Link Layer is [...] connectable directed advertising events the
  // advertising filter policy shall be ignored.
  if (legacy_advertiser_.IsDirected()) {
    if (legacy_advertiser_.GetTargetAddress() != resolved_initiating_address) {
      LOG_VERB(
          "LE Connect request ignored by legacy advertiser because the "
          "initiating address %s(%hhx) does not match the target address "
          "%s(%hhx)",
          resolved_initiating_address.ToString().c_str(),
          resolved_initiating_address.GetAddressType(),
          legacy_advertiser_.GetTargetAddress().ToString().c_str(),
          legacy_advertiser_.GetTargetAddress().GetAddressType());
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
          LOG_VERB(
              "LE Connect request ignored by legacy advertiser because the "
              "initiating address %s(%hhx) is not in the filter accept list",
              resolved_initiating_address.ToString().c_str(),
              resolved_initiating_address.GetAddressType());
          return false;
        }
        break;
    }
  }

  LOG_INFO(
      "Accepting LE Connect request to legacy advertiser from initiating "
      "address %s(%hhx)",
      resolved_initiating_address.ToString().c_str(),
      resolved_initiating_address.GetAddressType());

  if (!connections_.CreatePendingLeConnection(
          initiating_address,
          resolved_initiating_address != initiating_address
              ? resolved_initiating_address
              : AddressWithType{},
          advertising_address)) {
    LOG_WARN(
        "CreatePendingLeConnection failed for connection from %s (type %hhx)",
        initiating_address.GetAddress().ToString().c_str(),
        initiating_address.GetAddressType());
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
    LOG_VERB(
        "LE Connect request ignored by extended advertiser %d because it is "
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
    LOG_VERB(
        "LE Connect request ignored by extended advertiser %d because the "
        "advertising address %s(%hhx) does not match %s(%hhx)",
        advertiser.advertising_handle, advertising_address.ToString().c_str(),
        advertising_address.GetAddressType(),
        advertiser.GetAdvertisingAddress().ToString().c_str(),
        advertiser.GetAdvertisingAddress().GetAddressType());
    return false;
  }

  // When an advertiser receives a connection request that contains a resolvable
  // private address for the initiator’s address (InitA field) and address
  // resolution is enabled, the Link Layer shall resolve the private address.
  // The advertising filter policy shall then determine if the
  // advertiser establishes a connection.
  AddressWithType resolved_initiating_address =
      ResolvePrivateAddress(initiating_address, IrkSelection::Peer)
          .value_or(initiating_address);

  if (resolved_initiating_address != initiating_address) {
    LOG_VERB("Resolved the initiating address %s(%hhx) to %s(%hhx)",
             initiating_address.ToString().c_str(),
             initiating_address.GetAddressType(),
             resolved_initiating_address.ToString().c_str(),
             resolved_initiating_address.GetAddressType());
  }

  // When the Link Layer is [...] connectable directed advertising events the
  // advertising filter policy shall be ignored.
  if (advertiser.IsDirected()) {
    if (advertiser.GetTargetAddress() != resolved_initiating_address) {
      LOG_VERB(
          "LE Connect request ignored by extended advertiser %d because the "
          "initiating address %s(%hhx) does not match the target address "
          "%s(%hhx)",
          advertiser.advertising_handle,
          resolved_initiating_address.ToString().c_str(),
          resolved_initiating_address.GetAddressType(),
          advertiser.GetTargetAddress().ToString().c_str(),
          advertiser.GetTargetAddress().GetAddressType());
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
          LOG_VERB(
              "LE Connect request ignored by extended advertiser %d because "
              "the initiating address %s(%hhx) is not in the filter accept "
              "list",
              advertiser.advertising_handle,
              resolved_initiating_address.ToString().c_str(),
              resolved_initiating_address.GetAddressType());
          return false;
        }
        break;
    }
  }

  LOG_INFO(
      "Accepting LE Connect request to extended advertiser %d from initiating "
      "address %s(%hhx)",
      advertiser.advertising_handle,
      resolved_initiating_address.ToString().c_str(),
      resolved_initiating_address.GetAddressType());

  if (!connections_.CreatePendingLeConnection(
          initiating_address,
          resolved_initiating_address != initiating_address
              ? resolved_initiating_address
              : AddressWithType{},
          advertising_address)) {
    LOG_WARN(
        "CreatePendingLeConnection failed for connection from %s (type %hhx)",
        initiating_address.GetAddress().ToString().c_str(),
        initiating_address.GetAddressType());
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

  LOG_INFO(
      "Received LE Connect complete response with advertising address %s(%hhx)",
      advertising_address.ToString().c_str(),
      advertising_address.GetAddressType());

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
    LOG_INFO("@%s: Unknown connection @%s",
             incoming.GetDestinationAddress().ToString().c_str(),
             peer.ToString().c_str());
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
    LOG_INFO("@%s: Unknown connection @%s",
             incoming.GetDestinationAddress().ToString().c_str(),
             peer.ToString().c_str());
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
  LOG_INFO("IncomingLeEncryptConnection");

  Address peer = incoming.GetSourceAddress();
  uint16_t handle = connections_.GetHandleOnlyAddress(peer);
  if (handle == kReservedHandle) {
    LOG_INFO("@%s: Unknown connection @%s",
             incoming.GetDestinationAddress().ToString().c_str(),
             peer.ToString().c_str());
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
  LOG_INFO("IncomingLeEncryptConnectionResponse");
  // TODO: Check keys
  uint16_t handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  if (handle == kReservedHandle) {
    LOG_INFO("@%s: Unknown connection @%s",
             incoming.GetDestinationAddress().ToString().c_str(),
             incoming.GetSourceAddress().ToString().c_str());
    return;
  }
  ErrorCode status = ErrorCode::SUCCESS;
  auto response =
      model::packets::LeEncryptConnectionResponseView::Create(incoming);
  ASSERT(response.IsValid());

  // Zero LTK is a rejection
  if (response.GetLtk() == std::array<uint8_t, 16>{0}) {
    status = ErrorCode::AUTHENTICATION_FAILURE;
  }

  if (connections_.IsEncrypted(handle)) {
    if (IsEventUnmasked(EventCode::ENCRYPTION_KEY_REFRESH_COMPLETE)) {
      send_event_(bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(
          status, handle));
    }
  } else {
    connections_.Encrypt(handle);
    if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
      send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
          status, handle, bluetooth::hci::EncryptionEnabled::ON));
    }
  }
}

void LinkLayerController::IncomingLeReadRemoteFeatures(
    model::packets::LinkLayerPacketView incoming) {
  uint16_t handle =
      connections_.GetHandleOnlyAddress(incoming.GetSourceAddress());
  ErrorCode status = ErrorCode::SUCCESS;
  if (handle == kReservedHandle) {
    LOG_WARN("@%s: Unknown connection @%s",
             incoming.GetDestinationAddress().ToString().c_str(),
             incoming.GetSourceAddress().ToString().c_str());
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
    LOG_INFO("@%s: Unknown connection @%s",
             incoming.GetDestinationAddress().ToString().c_str(),
             incoming.GetSourceAddress().ToString().c_str());
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
    LOG_VERB(
        "LE Scan request ignored by legacy advertiser because it is not "
        "scannable");
    return;
  }

  if (advertising_address != legacy_advertiser_.advertising_address) {
    LOG_VERB(
        "LE Scan request ignored by legacy advertiser because the advertising "
        "address %s(%hhx) does not match %s(%hhx)",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType(),
        legacy_advertiser_.GetAdvertisingAddress().ToString().c_str(),
        legacy_advertiser_.GetAdvertisingAddress().GetAddressType());
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
        LOG_VERB(
            "LE Scan request ignored by legacy advertiser because the scanning "
            "address %s(%hhx) is not in the filter accept list",
            resolved_scanning_address.ToString().c_str(),
            resolved_scanning_address.GetAddressType());
        return;
      }
      break;
  }

  LOG_INFO(
      "Accepting LE Scan request to legacy advertiser from scanning address "
      "%s(%hhx)",
      resolved_scanning_address.ToString().c_str(),
      resolved_scanning_address.GetAddressType());

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
    LOG_VERB(
        "LE Scan request ignored by extended advertiser %d because it is not "
        "scannable",
        advertiser.advertising_handle);
    return;
  }

  if (advertising_address != advertiser.advertising_address) {
    LOG_VERB(
        "LE Scan request ignored by extended advertiser %d because the "
        "advertising address %s(%hhx) does not match %s(%hhx)",
        advertiser.advertising_handle, advertising_address.ToString().c_str(),
        advertising_address.GetAddressType(),
        advertiser.GetAdvertisingAddress().ToString().c_str(),
        advertiser.GetAdvertisingAddress().GetAddressType());
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
        LOG_VERB(
            "LE Scan request ignored by extended advertiser %d because the "
            "scanning address %s(%hhx) is not in the filter accept list",
            advertiser.advertising_handle,
            resolved_scanning_address.ToString().c_str(),
            resolved_scanning_address.GetAddressType());
        return;
      }
      break;
  }

  // Check if the scanner address is the target address in the case of
  // scannable directed event types.
  if (advertiser.IsDirected() &&
      advertiser.target_address != resolved_scanning_address) {
    LOG_VERB(
        "LE Scan request ignored by extended advertiser %d because the "
        "scanning address %s(%hhx) does not match the target address %s(%hhx)",
        advertiser.advertising_handle,
        resolved_scanning_address.ToString().c_str(),
        resolved_scanning_address.GetAddressType(),
        advertiser.GetTargetAddress().ToString().c_str(),
        advertiser.GetTargetAddress().GetAddressType());
    return;
  }

  LOG_INFO(
      "Accepting LE Scan request to extended advertiser %d from scanning "
      "address %s(%hhx)",
      advertiser.advertising_handle,
      resolved_scanning_address.ToString().c_str(),
      resolved_scanning_address.GetAddressType());

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
      ResolvePrivateAddress(scanning_address, IrkSelection::Peer)
          .value_or(scanning_address);

  if (resolved_scanning_address != scanning_address) {
    LOG_VERB("Resolved the scanning address %s(%hhx) to %s(%hhx)",
             scanning_address.ToString().c_str(),
             scanning_address.GetAddressType(),
             resolved_scanning_address.ToString().c_str(),
             resolved_scanning_address.GetAddressType());
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
    LOG_VERB(
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
    LOG_VERB(
        "LE Scan response ignored by scanner because the advertising address "
        "%s(%hhx) does not match the pending request %s(%hhx)",
        advertising_address.ToString().c_str(),
        advertising_address.GetAddressType(),
        scanner_.pending_scan_request.value().ToString().c_str(),
        scanner_.pending_scan_request.value().GetAddressType());
    return;
  }

  AddressWithType resolved_advertising_address =
      ResolvePrivateAddress(advertising_address, IrkSelection::Peer)
          .value_or(advertising_address);

  if (advertising_address != resolved_advertising_address) {
    LOG_VERB("Resolved the advertising address %s(%hhx) to %s(%hhx)",
             advertising_address.ToString().c_str(),
             advertising_address.GetAddressType(),
             resolved_advertising_address.ToString().c_str(),
             resolved_advertising_address.GetAddressType());
  }

  LOG_INFO("Accepting LE Scan response from advertising address %s(%hhx)",
           resolved_advertising_address.ToString().c_str(),
           resolved_advertising_address.GetAddressType());

  scanner_.pending_scan_request = {};

  bool should_send_advertising_report = true;
  if (scanner_.filter_duplicates !=
      bluetooth::hci::FilterDuplicates::DISABLED) {
    if (scanner_.IsPacketInHistory(incoming)) {
      should_send_advertising_report = false;
    } else {
      scanner_.AddPacketToHistory(incoming);
    }
  }

  if (LegacyAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::ADVERTISING_REPORT)) {
    bluetooth::hci::LeAdvertisingResponseRaw response;
    response.event_type_ = bluetooth::hci::AdvertisingEventType::SCAN_RESPONSE;
    response.address_ = resolved_advertising_address.GetAddress();
    response.address_type_ = resolved_advertising_address.GetAddressType();
    response.advertising_data_ = scan_response.GetScanResponseData();
    response.rssi_ = rssi;
    send_event_(
        bluetooth::hci::LeAdvertisingReportRawBuilder::Create({response}));
  }

  if (ExtendedAdvertising() && should_send_advertising_report &&
      IsLeEventUnmasked(SubeventCode::EXTENDED_ADVERTISING_REPORT)) {
    bluetooth::hci::LeExtendedAdvertisingResponseRaw response;
    response.address_ = resolved_advertising_address.GetAddress();
    response.address_type_ =
        static_cast<bluetooth::hci::DirectAdvertisingAddressType>(
            resolved_advertising_address.GetAddressType());
    response.connectable_ = scanner_.connectable_scan_response;
    response.scannable_ = true;
    response.legacy_ = true;
    response.scan_response_ = true;
    response.primary_phy_ = bluetooth::hci::PrimaryPhyType::LE_1M;
    response.advertising_sid_ = 0xFF;
    response.tx_power_ = 0x7F;
    response.advertising_data_ = scan_response.GetScanResponseData();
    response.rssi_ = rssi;
    send_event_(bluetooth::hci::LeExtendedAdvertisingReportRawBuilder::Create(
        {response}));
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
    LOG_INFO("Extended Scan Timeout");
    scanner_.scan_enable = false;
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
}

#ifndef ROOTCANAL_LMP
void LinkLayerController::IncomingPasskeyPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto passkey = model::packets::PasskeyView::Create(incoming);
  ASSERT(passkey.IsValid());
  SaveKeyAndAuthenticate('P', incoming.GetSourceAddress());
}

void LinkLayerController::IncomingPasskeyFailedPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto failed = model::packets::PasskeyFailedView::Create(incoming);
  ASSERT(failed.IsValid());
  auto current_peer = incoming.GetSourceAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(kNoDelayMs, [this, current_peer]() {
    if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
      send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
          ErrorCode::AUTHENTICATION_FAILURE, current_peer));
    }
  });
}

void LinkLayerController::IncomingPinRequestPacket(
    model::packets::LinkLayerPacketView incoming) {
  auto request = model::packets::PinRequestView::Create(incoming);
  ASSERT(request.IsValid());
  auto peer = incoming.GetSourceAddress();
  auto handle = connections_.GetHandle(AddressWithType(
      peer, bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS));
  if (handle == kReservedHandle) {
    LOG_INFO("Dropping %s request (no connection)", peer.ToString().c_str());
    auto wrong_pin = request.GetPinCode();
    wrong_pin[0] = wrong_pin[0]++;
    SendLinkLayerPacket(model::packets::PinResponseBuilder::Create(
        GetAddress(), peer, wrong_pin));
    return;
  }
  if (security_manager_.AuthenticationInProgress()) {
    auto current_peer = security_manager_.GetAuthenticationAddress();
    if (current_peer != peer) {
      LOG_INFO("Dropping %s request (%s in progress)", peer.ToString().c_str(),
               current_peer.ToString().c_str());
      auto wrong_pin = request.GetPinCode();
      wrong_pin[0] = wrong_pin[0]++;
      SendLinkLayerPacket(model::packets::PinResponseBuilder::Create(
          GetAddress(), peer, wrong_pin));
      return;
    }
  } else {
    LOG_INFO("Incoming authentication request %s", peer.ToString().c_str());
    security_manager_.AuthenticationRequest(peer, handle, false);
  }
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.SetRemotePin(peer, request.GetPinCode());
  if (security_manager_.GetPinRequested(peer)) {
    if (security_manager_.GetLocalPinResponseReceived(peer)) {
      SendLinkLayerPacket(model::packets::PinResponseBuilder::Create(
          GetAddress(), peer, request.GetPinCode()));
      if (security_manager_.PinCompare()) {
        LOG_INFO("Authenticating %s", peer.ToString().c_str());
        SaveKeyAndAuthenticate('L', peer);  // Legacy
      } else {
        security_manager_.AuthenticationRequestFinished();
        ScheduleTask(kNoDelayMs, [this, peer]() {
          if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
            send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
                ErrorCode::AUTHENTICATION_FAILURE, peer));
          }
        });
      }
    }
  } else {
    LOG_INFO("PIN pairing %s", GetAddress().ToString().c_str());
    ScheduleTask(kNoDelayMs, [this, peer]() {
      security_manager_.SetPinRequested(peer);
      if (IsEventUnmasked(EventCode::PIN_CODE_REQUEST)) {
        send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(peer));
      }
    });
  }
}

void LinkLayerController::IncomingPinResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto request = model::packets::PinResponseView::Create(incoming);
  ASSERT(request.IsValid());
  auto peer = incoming.GetSourceAddress();
  auto handle = connections_.GetHandle(AddressWithType(
      peer, bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS));
  if (handle == kReservedHandle) {
    LOG_INFO("Dropping %s request (no connection)", peer.ToString().c_str());
    return;
  }
  if (security_manager_.AuthenticationInProgress()) {
    auto current_peer = security_manager_.GetAuthenticationAddress();
    if (current_peer != peer) {
      LOG_INFO("Dropping %s request (%s in progress)", peer.ToString().c_str(),
               current_peer.ToString().c_str());
      return;
    }
  } else {
    LOG_INFO("Dropping response without authentication request %s",
             peer.ToString().c_str());
    return;
  }
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.SetRemotePin(peer, request.GetPinCode());
  if (security_manager_.GetPinRequested(peer)) {
    if (security_manager_.GetLocalPinResponseReceived(peer)) {
      SendLinkLayerPacket(model::packets::PinResponseBuilder::Create(
          GetAddress(), peer, request.GetPinCode()));
      if (security_manager_.PinCompare()) {
        LOG_INFO("Authenticating %s", peer.ToString().c_str());
        SaveKeyAndAuthenticate('L', peer);  // Legacy
      } else {
        security_manager_.AuthenticationRequestFinished();
        ScheduleTask(kNoDelayMs, [this, peer]() {
          if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
            send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
                ErrorCode::AUTHENTICATION_FAILURE, peer));
          }
        });
      }
    }
  } else {
    LOG_INFO("PIN pairing %s", GetAddress().ToString().c_str());
    ScheduleTask(kNoDelayMs, [this, peer]() {
      security_manager_.SetPinRequested(peer);
      if (IsEventUnmasked(EventCode::PIN_CODE_REQUEST)) {
        send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(peer));
      }
    });
  }
}
#endif /* !ROOTCANAL_LMP */

void LinkLayerController::IncomingPagePacket(
    model::packets::LinkLayerPacketView incoming) {
  auto page = model::packets::PageView::Create(incoming);
  ASSERT(page.IsValid());
  LOG_INFO("from %s", incoming.GetSourceAddress().ToString().c_str());

  if (!connections_.CreatePendingConnection(
          incoming.GetSourceAddress(),
          authentication_enable_ == AuthenticationEnable::REQUIRED)) {
    // Send a response to indicate that we're busy, or drop the packet?
    LOG_WARN("Failed to create a pending connection for %s",
             incoming.GetSourceAddress().ToString().c_str());
  }

  bluetooth::hci::Address source_address{};
  bluetooth::hci::Address::FromString(page.GetSourceAddress().ToString(),
                                      source_address);

  if (IsEventUnmasked(EventCode::CONNECTION_REQUEST)) {
    send_event_(bluetooth::hci::ConnectionRequestBuilder::Create(
        source_address, page.GetClassOfDevice(),
        bluetooth::hci::ConnectionRequestLinkType::ACL));
  }
}

void LinkLayerController::IncomingPageRejectPacket(
    model::packets::LinkLayerPacketView incoming) {
  LOG_INFO("%s", incoming.GetSourceAddress().ToString().c_str());
  auto reject = model::packets::PageRejectView::Create(incoming);
  ASSERT(reject.IsValid());
  LOG_INFO("Sending CreateConnectionComplete");
  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        static_cast<ErrorCode>(reject.GetReason()), 0x0eff,
        incoming.GetSourceAddress(), bluetooth::hci::LinkType::ACL,
        bluetooth::hci::Enable::DISABLED));
  }
}

void LinkLayerController::IncomingPageResponsePacket(
    model::packets::LinkLayerPacketView incoming) {
  Address peer = incoming.GetSourceAddress();
  LOG_INFO("%s", peer.ToString().c_str());
#ifndef ROOTCANAL_LMP
  bool awaiting_authentication = connections_.AuthenticatePendingConnection();
#endif /* !ROOTCANAL_LMP */
  uint16_t handle =
      connections_.CreateConnection(peer, incoming.GetDestinationAddress());
  if (handle == kReservedHandle) {
    LOG_WARN("No free handles");
    return;
  }
  CancelScheduledTask(page_timeout_task_id_);
#ifdef ROOTCANAL_LMP
  ASSERT(link_manager_add_link(
      lm_.get(), reinterpret_cast<const uint8_t(*)[6]>(peer.data())));
#endif /* ROOTCANAL_LMP */

  CheckExpiringConnection(handle);

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        ErrorCode::SUCCESS, handle, incoming.GetSourceAddress(),
        bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));
  }

#ifndef ROOTCANAL_LMP
  if (awaiting_authentication) {
    ScheduleTask(kNoDelayMs, [this, peer, handle]() {
      HandleAuthenticationRequest(peer, handle);
    });
  }
#endif /* !ROOTCANAL_LMP */
}

void LinkLayerController::Tick() {
  RunPendingTasks();
  if (inquiry_timer_task_id_ != kInvalidTaskId) {
    Inquiry();
  }
  LeAdvertising();
  LeScanning();
#ifdef ROOTCANAL_LMP
  link_manager_tick(lm_.get());
#endif /* ROOTCANAL_LMP */
}

void LinkLayerController::Close() {
  for (auto handle : connections_.GetAclHandles()) {
    Disconnect(handle, ErrorCode::CONNECTION_TIMEOUT,
               ErrorCode::CONNECTION_TIMEOUT);
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

#ifdef ROOTCANAL_LMP
void LinkLayerController::ForwardToLm(bluetooth::hci::CommandView command) {
  auto packet = std::vector(command.begin(), command.end());
  ASSERT(link_manager_ingest_hci(lm_.get(), packet.data(), packet.size()));
}
#else
void LinkLayerController::StartSimplePairing(const Address& address) {
  // IO Capability Exchange (See the Diagram in the Spec)
  if (IsEventUnmasked(EventCode::IO_CAPABILITY_REQUEST)) {
    send_event_(bluetooth::hci::IoCapabilityRequestBuilder::Create(address));
  }

  // Get a Key, then authenticate
  // PublicKeyExchange(address);
  // AuthenticateRemoteStage1(address);
  // AuthenticateRemoteStage2(address);
}

void LinkLayerController::AuthenticateRemoteStage1(const Address& peer,
                                                   PairingType pairing_type) {
  ASSERT(security_manager_.GetAuthenticationAddress() == peer);
  // TODO: Public key exchange first?
  switch (pairing_type) {
    case PairingType::AUTO_CONFIRMATION:
      if (IsEventUnmasked(EventCode::USER_CONFIRMATION_REQUEST)) {
        send_event_(bluetooth::hci::UserConfirmationRequestBuilder::Create(
            peer, 123456));
      }
      break;
    case PairingType::CONFIRM_Y_N:
      if (IsEventUnmasked(EventCode::USER_CONFIRMATION_REQUEST)) {
        send_event_(bluetooth::hci::UserConfirmationRequestBuilder::Create(
            peer, 123456));
      }
      break;
    case PairingType::DISPLAY_PIN:
      if (IsEventUnmasked(EventCode::USER_PASSKEY_NOTIFICATION)) {
        send_event_(bluetooth::hci::UserPasskeyNotificationBuilder::Create(
            peer, 123456));
      }
      break;
    case PairingType::DISPLAY_AND_CONFIRM:
      if (IsEventUnmasked(EventCode::USER_CONFIRMATION_REQUEST)) {
        send_event_(bluetooth::hci::UserConfirmationRequestBuilder::Create(
            peer, 123456));
      }
      break;
    case PairingType::INPUT_PIN:
      if (IsEventUnmasked(EventCode::USER_PASSKEY_REQUEST)) {
        send_event_(bluetooth::hci::UserPasskeyRequestBuilder::Create(peer));
      }
      break;
    case PairingType::OUT_OF_BAND:
      LOG_INFO("Oob data request for %s", peer.ToString().c_str());
      if (IsEventUnmasked(EventCode::REMOTE_OOB_DATA_REQUEST)) {
        send_event_(bluetooth::hci::RemoteOobDataRequestBuilder::Create(peer));
      }
      break;
    case PairingType::PEER_HAS_OUT_OF_BAND:
      LOG_INFO("Trusting that %s has OOB data", peer.ToString().c_str());
      SaveKeyAndAuthenticate('P', peer);
      break;
    default:
      LOG_ALWAYS_FATAL("Invalid PairingType %d",
                       static_cast<int>(pairing_type));
  }
}

void LinkLayerController::AuthenticateRemoteStage2(const Address& peer) {
  uint16_t handle = security_manager_.GetAuthenticationHandle();
  ASSERT(security_manager_.GetAuthenticationAddress() == peer);
  // Check key in security_manager_ ?
  if (security_manager_.IsInitiator()) {
    if (IsEventUnmasked(EventCode::AUTHENTICATION_COMPLETE)) {
      send_event_(bluetooth::hci::AuthenticationCompleteBuilder::Create(
          ErrorCode::SUCCESS, handle));
    }
  }
}

ErrorCode LinkLayerController::LinkKeyRequestReply(
    const Address& peer, const std::array<uint8_t, 16>& key) {
  security_manager_.WriteKey(peer, key);
  security_manager_.AuthenticationRequestFinished();

  ScheduleTask(kNoDelayMs, [this, peer]() { AuthenticateRemoteStage2(peer); });

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LinkKeyRequestNegativeReply(
    const Address& address) {
  security_manager_.DeleteKey(address);
  // Simple pairing to get a key
  uint16_t handle = connections_.GetHandleOnlyAddress(address);
  if (handle == kReservedHandle) {
    LOG_INFO("Device not connected %s", address.ToString().c_str());
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (secure_simple_pairing_host_support_) {
    if (!security_manager_.AuthenticationInProgress()) {
      security_manager_.AuthenticationRequest(address, handle, false);
    }

    ScheduleTask(kNoDelayMs,
                 [this, address]() { StartSimplePairing(address); });
  } else {
    LOG_INFO("PIN pairing %s", GetAddress().ToString().c_str());
    ScheduleTask(kNoDelayMs, [this, address]() {
      security_manager_.SetPinRequested(address);
      if (IsEventUnmasked(EventCode::PIN_CODE_REQUEST)) {
        send_event_(bluetooth::hci::PinCodeRequestBuilder::Create(address));
      }
    });
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::IoCapabilityRequestReply(
    const Address& peer, uint8_t io_capability, uint8_t oob_data_present_flag,
    uint8_t authentication_requirements) {
  security_manager_.SetLocalIoCapability(
      peer, io_capability, oob_data_present_flag, authentication_requirements);

  PairingType pairing_type = security_manager_.GetSimplePairingType();

  if (pairing_type != PairingType::INVALID) {
    ScheduleTask(kNoDelayMs, [this, peer, pairing_type]() {
      AuthenticateRemoteStage1(peer, pairing_type);
    });
    SendLinkLayerPacket(model::packets::IoCapabilityResponseBuilder::Create(
        GetAddress(), peer, io_capability, oob_data_present_flag,
        authentication_requirements));
  } else {
    LOG_INFO("Requesting remote capability");

    SendLinkLayerPacket(model::packets::IoCapabilityRequestBuilder::Create(
        GetAddress(), peer, io_capability, oob_data_present_flag,
        authentication_requirements));
  }

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::IoCapabilityRequestNegativeReply(
    const Address& peer, ErrorCode reason) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }

  security_manager_.InvalidateIoCapabilities();

  SendLinkLayerPacket(
      model::packets::IoCapabilityNegativeResponseBuilder::Create(
          GetAddress(), peer, static_cast<uint8_t>(reason)));

  return ErrorCode::SUCCESS;
}

void LinkLayerController::SaveKeyAndAuthenticate(uint8_t key_type,
                                                 const Address& peer) {
  std::array<uint8_t, 16> key_vec{'k',
                                  'e',
                                  'y',
                                  ' ',
                                  key_type,
                                  5,
                                  6,
                                  7,
                                  8,
                                  9,
                                  10,
                                  11,
                                  12,
                                  13,
                                  static_cast<uint8_t>(key_id_ >> 8u),
                                  static_cast<uint8_t>(key_id_)};
  key_id_ += 1;
  security_manager_.WriteKey(peer, key_vec);

  security_manager_.AuthenticationRequestFinished();

  if (key_type == 'L') {
    // Legacy
    ScheduleTask(kNoDelayMs, [this, peer, key_vec]() {
      if (IsEventUnmasked(EventCode::LINK_KEY_NOTIFICATION)) {
        send_event_(bluetooth::hci::LinkKeyNotificationBuilder::Create(
            peer, key_vec, bluetooth::hci::KeyType::AUTHENTICATED_P192));
      }
    });
  } else {
    ScheduleTask(kNoDelayMs, [this, peer]() {
      if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
        send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
            ErrorCode::SUCCESS, peer));
      }
    });

    ScheduleTask(kNoDelayMs, [this, peer, key_vec]() {
      if (IsEventUnmasked(EventCode::LINK_KEY_NOTIFICATION)) {
        send_event_(bluetooth::hci::LinkKeyNotificationBuilder::Create(
            peer, key_vec, bluetooth::hci::KeyType::AUTHENTICATED_P256));
      }
    });
  }

  ScheduleTask(kNoDelayMs, [this, peer]() { AuthenticateRemoteStage2(peer); });
}

ErrorCode LinkLayerController::PinCodeRequestReply(const Address& peer,
                                                   std::vector<uint8_t> pin) {
  LOG_INFO("%s", GetAddress().ToString().c_str());
  auto current_peer = security_manager_.GetAuthenticationAddress();
  if (peer != current_peer) {
    LOG_INFO("%s: %s != %s", GetAddress().ToString().c_str(),
             peer.ToString().c_str(), current_peer.ToString().c_str());
    security_manager_.AuthenticationRequestFinished();
    ScheduleTask(kNoDelayMs, [this, current_peer]() {
      if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
        send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
            ErrorCode::AUTHENTICATION_FAILURE, current_peer));
      }
    });
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  if (!security_manager_.GetPinRequested(peer)) {
    LOG_INFO("No Pin Requested for %s", peer.ToString().c_str());
    return ErrorCode::COMMAND_DISALLOWED;
  }
  security_manager_.SetLocalPin(peer, pin);
  if (security_manager_.GetRemotePinResponseReceived(peer)) {
    if (security_manager_.PinCompare()) {
      LOG_INFO("Authenticating %s", peer.ToString().c_str());
      SaveKeyAndAuthenticate('L', peer);  // Legacy
    } else {
      security_manager_.AuthenticationRequestFinished();
      ScheduleTask(kNoDelayMs, [this, peer]() {
        if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
          send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
              ErrorCode::AUTHENTICATION_FAILURE, peer));
        }
      });
    }
  } else {
    SendLinkLayerPacket(
        model::packets::PinRequestBuilder::Create(GetAddress(), peer, pin));
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::PinCodeRequestNegativeReply(
    const Address& peer) {
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(kNoDelayMs, [this, current_peer]() {
    if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
      send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
          ErrorCode::AUTHENTICATION_FAILURE, current_peer));
    }
  });
  if (peer != current_peer) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  if (!security_manager_.GetPinRequested(peer)) {
    LOG_INFO("No Pin Requested for %s", peer.ToString().c_str());
    return ErrorCode::COMMAND_DISALLOWED;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::UserConfirmationRequestReply(
    const Address& peer) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }
  SaveKeyAndAuthenticate('U', peer);
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::UserConfirmationRequestNegativeReply(
    const Address& peer) {
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(kNoDelayMs, [this, current_peer]() {
    if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
      send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
          ErrorCode::AUTHENTICATION_FAILURE, current_peer));
    }
  });
  if (peer != current_peer) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::UserPasskeyRequestReply(const Address& peer,
                                                       uint32_t numeric_value) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }
  SendLinkLayerPacket(model::packets::PasskeyBuilder::Create(GetAddress(), peer,
                                                             numeric_value));
  SaveKeyAndAuthenticate('P', peer);

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::UserPasskeyRequestNegativeReply(
    const Address& peer) {
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(kNoDelayMs, [this, current_peer]() {
    if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
      send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
          ErrorCode::AUTHENTICATION_FAILURE, current_peer));
    }
  });
  if (peer != current_peer) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::RemoteOobDataRequestReply(
    const Address& peer, const std::array<uint8_t, 16>& c,
    const std::array<uint8_t, 16>& r) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }
  LOG_INFO("TODO:Do something with the OOB data c=%d r=%d", c[0], r[0]);
  SaveKeyAndAuthenticate('o', peer);

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::RemoteOobDataRequestNegativeReply(
    const Address& peer) {
  auto current_peer = security_manager_.GetAuthenticationAddress();
  security_manager_.AuthenticationRequestFinished();
  ScheduleTask(kNoDelayMs, [this, current_peer]() {
    if (IsEventUnmasked(EventCode::SIMPLE_PAIRING_COMPLETE)) {
      send_event_(bluetooth::hci::SimplePairingCompleteBuilder::Create(
          ErrorCode::AUTHENTICATION_FAILURE, current_peer));
    }
  });
  if (peer != current_peer) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::RemoteOobExtendedDataRequestReply(
    const Address& peer, const std::array<uint8_t, 16>& c192,
    const std::array<uint8_t, 16>& r192, const std::array<uint8_t, 16>& c256,
    const std::array<uint8_t, 16>& r256) {
  if (security_manager_.GetAuthenticationAddress() != peer) {
    return ErrorCode::AUTHENTICATION_FAILURE;
  }
  LOG_INFO(
      "TODO:Do something with the OOB data c192=%d r192=%d c256=%d r256=%d",
      c192[0], r192[0], c256[0], r256[0]);
  SaveKeyAndAuthenticate('O', peer);

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::SendKeypressNotification(
    const Address& peer,
    bluetooth::hci::KeypressNotificationType notification_type) {
  if (notification_type >
      bluetooth::hci::KeypressNotificationType::ENTRY_COMPLETED) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  SendLinkLayerPacket(model::packets::KeypressNotificationBuilder::Create(
      GetAddress(), peer,
      static_cast<model::packets::PasskeyNotificationType>(notification_type)));
  return ErrorCode::SUCCESS;
}

void LinkLayerController::HandleAuthenticationRequest(const Address& address,
                                                      uint16_t handle) {
  security_manager_.AuthenticationRequest(address, handle, true);
  if (IsEventUnmasked(EventCode::LINK_KEY_REQUEST)) {
    send_event_(bluetooth::hci::LinkKeyRequestBuilder::Create(address));
  }
}

ErrorCode LinkLayerController::AuthenticationRequested(uint16_t handle) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Authentication Requested for unknown handle %04x", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  AddressWithType remote = connections_.GetAddress(handle);

  ScheduleTask(kNoDelayMs, [this, remote, handle]() {
    HandleAuthenticationRequest(remote.GetAddress(), handle);
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::HandleSetConnectionEncryption(
    const Address& peer, uint16_t handle, uint8_t encryption_enable) {
  // TODO: Block ACL traffic or at least guard against it

  if (connections_.IsEncrypted(handle) && encryption_enable) {
    if (IsEventUnmasked(EventCode::ENCRYPTION_CHANGE)) {
      send_event_(bluetooth::hci::EncryptionChangeBuilder::Create(
          ErrorCode::SUCCESS, handle,
          static_cast<bluetooth::hci::EncryptionEnabled>(encryption_enable)));
    }
    return;
  }

  uint16_t count = security_manager_.ReadKey(peer);
  if (count == 0) {
    LOG_ERROR("NO KEY HERE for %s", peer.ToString().c_str());
    return;
  }
  auto array = security_manager_.GetKey(peer);
  std::vector<uint8_t> key_vec{array.begin(), array.end()};
  SendLinkLayerPacket(model::packets::EncryptConnectionBuilder::Create(
      GetAddress(), peer, key_vec));
}

ErrorCode LinkLayerController::SetConnectionEncryption(
    uint16_t handle, uint8_t encryption_enable) {
  if (!connections_.HasHandle(handle)) {
    LOG_INFO("Set Connection Encryption for unknown handle %04x", handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (connections_.IsEncrypted(handle) && !encryption_enable) {
    return ErrorCode::ENCRYPTION_MODE_NOT_ACCEPTABLE;
  }
  AddressWithType remote = connections_.GetAddress(handle);

  if (security_manager_.ReadKey(remote.GetAddress()) == 0) {
    return ErrorCode::PIN_OR_KEY_MISSING;
  }

  ScheduleTask(kNoDelayMs, [this, remote, handle, encryption_enable]() {
    HandleSetConnectionEncryption(remote.GetAddress(), handle,
                                  encryption_enable);
  });
  return ErrorCode::SUCCESS;
}
#endif /* ROOTCANAL_LMP */

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
    LOG_INFO("Accepting connection request from %s",
             bd_addr.ToString().c_str());
    ScheduleTask(kNoDelayMs, [this, bd_addr, try_role_switch]() {
      LOG_INFO("Accepted connection from %s", bd_addr.ToString().c_str());
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
    ScheduleTask(kNoDelayMs, [this, status, sco_handle, bd_addr]() {
      send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
          ErrorCode(status), sco_handle, bd_addr, bluetooth::hci::LinkType::SCO,
          bluetooth::hci::Enable::DISABLED));
    });

    return ErrorCode::SUCCESS;
  }

  LOG_INFO("No pending connection for %s", bd_addr.ToString().c_str());
  return ErrorCode::UNKNOWN_CONNECTION;
}

void LinkLayerController::MakePeripheralConnection(const Address& addr,
                                                   bool try_role_switch) {
  LOG_INFO("Sending page response to %s", addr.ToString().c_str());
  SendLinkLayerPacket(model::packets::PageResponseBuilder::Create(
      GetAddress(), addr, try_role_switch));

  uint16_t handle = connections_.CreateConnection(addr, GetAddress());
  if (handle == kReservedHandle) {
    LOG_INFO("CreateConnection failed");
    return;
  }
#ifdef ROOTCANAL_LMP
  ASSERT(link_manager_add_link(
      lm_.get(), reinterpret_cast<const uint8_t(*)[6]>(addr.data())));
#endif /* ROOTCANAL_LMP */

  CheckExpiringConnection(handle);

  LOG_INFO("CreateConnection returned handle 0x%x", handle);
  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        ErrorCode::SUCCESS, handle, addr, bluetooth::hci::LinkType::ACL,
        bluetooth::hci::Enable::DISABLED));
  }
}

ErrorCode LinkLayerController::RejectConnectionRequest(const Address& addr,
                                                       uint8_t reason) {
  if (!connections_.HasPendingConnection(addr)) {
    LOG_INFO("No pending connection for %s", addr.ToString().c_str());
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(kNoDelayMs, [this, addr, reason]() {
    RejectPeripheralConnection(addr, reason);
  });

  return ErrorCode::SUCCESS;
}

void LinkLayerController::RejectPeripheralConnection(const Address& addr,
                                                     uint8_t reason) {
  LOG_INFO("Sending page reject to %s (reason 0x%02hhx)",
           addr.ToString().c_str(), reason);
  SendLinkLayerPacket(
      model::packets::PageRejectBuilder::Create(GetAddress(), addr, reason));

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
        static_cast<ErrorCode>(reason), 0xeff, addr,
        bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));
  }
}

ErrorCode LinkLayerController::CreateConnection(const Address& addr,
                                                uint16_t /* packet_type */,
                                                uint8_t /* page_scan_mode */,
                                                uint16_t /* clock_offset */,
                                                uint8_t allow_role_switch) {
  if (!connections_.CreatePendingConnection(
          addr, authentication_enable_ == AuthenticationEnable::REQUIRED)) {
    return ErrorCode::CONTROLLER_BUSY;
  }

  page_timeout_task_id_ = ScheduleTask(
      duration_cast<milliseconds>(page_timeout_ * microseconds(625)),
      [this, addr] {
        send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
            ErrorCode::PAGE_TIMEOUT, 0xeff, addr, bluetooth::hci::LinkType::ACL,
            bluetooth::hci::Enable::DISABLED));
      });

  SendLinkLayerPacket(model::packets::PageBuilder::Create(
      GetAddress(), addr, class_of_device_, allow_role_switch));

  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::CreateConnectionCancel(const Address& addr) {
  if (!connections_.CancelPendingConnection(addr)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  CancelScheduledTask(page_timeout_task_id_);
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
    LOG_INFO("Disconnecting eSCO connection with %s",
             remote.ToString().c_str());

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
    LOG_INFO("Disconnecting ACL connection with %s", remote.ToString().c_str());

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
    LOG_INFO("Disconnecting LE connection with %s", remote.ToString().c_str());

    SendLeLinkLayerPacket(model::packets::DisconnectBuilder::Create(
        connections_.GetOwnAddress(handle).GetAddress(), remote.GetAddress(),
        static_cast<uint8_t>(host_reason)));
  }

  connections_.Disconnect(
      handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
  SendDisconnectionCompleteEvent(handle, controller_reason);
#ifdef ROOTCANAL_LMP
  if (is_br_edr) {
    ASSERT(link_manager_remove_link(
        lm_.get(),
        reinterpret_cast<uint8_t(*)[6]>(remote.GetAddress().data())));
  }
#endif
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

ErrorCode LinkLayerController::SwitchRole(Address addr,
                                          bluetooth::hci::Role role) {
  auto handle = connections_.GetHandleOnlyAddress(addr);
  if (handle == rootcanal::kReservedHandle) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  connections_.SetAclRole(handle, role);
  ScheduleTask(kNoDelayMs, [this, addr, role]() {
    send_event_(bluetooth::hci::RoleChangeBuilder::Create(ErrorCode::SUCCESS,
                                                          addr, role));
  });
  return ErrorCode::SUCCESS;
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

void LinkLayerController::LeReadIsoTxSync(uint16_t /* handle */) {}

void LinkLayerController::LeSetCigParameters(
    uint8_t cig_id, uint32_t sdu_interval_m_to_s, uint32_t sdu_interval_s_to_m,
    bluetooth::hci::ClockAccuracy clock_accuracy,
    bluetooth::hci::Packing packing, bluetooth::hci::Enable framing,
    uint16_t max_transport_latency_m_to_s,
    uint16_t max_transport_latency_s_to_m,
    std::vector<bluetooth::hci::CisParametersConfig> cis_config) {
  if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
    send_event_(connections_.SetCigParameters(
        cig_id, sdu_interval_m_to_s, sdu_interval_s_to_m, clock_accuracy,
        packing, framing, max_transport_latency_m_to_s,
        max_transport_latency_s_to_m, cis_config));
  }
}

ErrorCode LinkLayerController::LeCreateCis(
    std::vector<bluetooth::hci::CreateCisConfig> cis_config) {
  if (connections_.HasPendingCis()) {
    return ErrorCode::COMMAND_DISALLOWED;
  }
  for (auto& config : cis_config) {
    if (!connections_.HasHandle(config.acl_connection_handle_)) {
      LOG_INFO("Unknown ACL handle %04x", config.acl_connection_handle_);
      return ErrorCode::UNKNOWN_CONNECTION;
    }
    if (!connections_.HasCisHandle(config.cis_connection_handle_)) {
      LOG_INFO("Unknown CIS handle %04x", config.cis_connection_handle_);
      return ErrorCode::UNKNOWN_CONNECTION;
    }
  }
  for (auto& config : cis_config) {
    connections_.CreatePendingCis(config);
    auto own_address =
        connections_.GetOwnAddress(config.acl_connection_handle_);
    auto peer_address = connections_.GetAddress(config.acl_connection_handle_);
    StreamParameters stream_parameters =
        connections_.GetStreamParameters(config.cis_connection_handle_);
    GroupParameters group_parameters =
        connections_.GetGroupParameters(stream_parameters.group_id);

    SendLeLinkLayerPacket(model::packets::IsoConnectionRequestBuilder::Create(
        own_address.GetAddress(), peer_address.GetAddress(),
        stream_parameters.group_id, group_parameters.sdu_interval_m_to_s,
        group_parameters.sdu_interval_s_to_m, group_parameters.interleaved,
        group_parameters.framed, group_parameters.max_transport_latency_m_to_s,
        group_parameters.max_transport_latency_s_to_m,
        stream_parameters.stream_id, stream_parameters.max_sdu_m_to_s,
        stream_parameters.max_sdu_s_to_m, config.cis_connection_handle_,
        config.acl_connection_handle_));
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeRemoveCig(uint8_t cig_id) {
  return connections_.RemoveCig(cig_id);
}

ErrorCode LinkLayerController::LeAcceptCisRequest(uint16_t cis_handle) {
  if (!connections_.HasPendingCisConnection(cis_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  auto acl_handle = connections_.GetPendingAclHandle(cis_handle);

  connections_.ConnectCis(cis_handle);

  SendLeLinkLayerPacket(model::packets::IsoConnectionResponseBuilder::Create(
      connections_.GetOwnAddress(acl_handle).GetAddress(),
      connections_.GetAddress(acl_handle).GetAddress(),
      static_cast<uint8_t>(ErrorCode::SUCCESS), cis_handle, acl_handle,
      connections_.GetRemoteCisHandleForCisHandle(cis_handle)));

  // Both sides have to send LeCisEstablished event

  uint32_t cig_sync_delay = 0x100;
  uint32_t cis_sync_delay = 0x200;
  uint32_t latency_m_to_s = 0x200;
  uint32_t latency_s_to_m = 0x200;
  uint8_t nse = 1;
  uint8_t bn_m_to_s = 0;
  uint8_t bn_s_to_m = 0;
  uint8_t ft_m_to_s = 0;
  uint8_t ft_s_to_m = 0;
  uint8_t max_pdu_m_to_s = 0x40;
  uint8_t max_pdu_s_to_m = 0x40;
  uint16_t iso_interval = 0x100;
  if (IsEventUnmasked(EventCode::LE_META_EVENT)) {
    send_event_(bluetooth::hci::LeCisEstablishedBuilder::Create(
        ErrorCode::SUCCESS, cis_handle, cig_sync_delay, cis_sync_delay,
        latency_m_to_s, latency_s_to_m,
        bluetooth::hci::SecondaryPhyType::NO_PACKETS,
        bluetooth::hci::SecondaryPhyType::NO_PACKETS, nse, bn_m_to_s, bn_s_to_m,
        ft_m_to_s, ft_s_to_m, max_pdu_m_to_s, max_pdu_s_to_m, iso_interval));
  }
  return ErrorCode::SUCCESS;
}

ErrorCode LinkLayerController::LeRejectCisRequest(uint16_t cis_handle,
                                                  ErrorCode reason) {
  if (!connections_.HasPendingCisConnection(cis_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  auto acl_handle = connections_.GetPendingAclHandle(cis_handle);

  SendLeLinkLayerPacket(model::packets::IsoConnectionResponseBuilder::Create(
      connections_.GetOwnAddress(acl_handle).GetAddress(),
      connections_.GetAddress(acl_handle).GetAddress(),
      static_cast<uint8_t>(reason), cis_handle, acl_handle, kReservedHandle));
  connections_.RejectCis(cis_handle);
  return ErrorCode::SUCCESS;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ErrorCode LinkLayerController::LeCreateBig(
    uint8_t /* big_handle */, uint8_t /* advertising_handle */,
    uint8_t /* num_bis */, uint32_t /* sdu_interval */, uint16_t /* max_sdu */,
    uint16_t /* max_transport_latency */, uint8_t /* rtn */,
    bluetooth::hci::SecondaryPhyType /* phy */,
    bluetooth::hci::Packing /* packing */, bluetooth::hci::Enable /* framing */,
    bluetooth::hci::Enable /* encryption */,
    std::array<uint8_t, 16> /* broadcast_code */) {
  return ErrorCode::SUCCESS;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ErrorCode LinkLayerController::LeTerminateBig(uint8_t /* big_handle */,
                                              ErrorCode /* reason */) {
  return ErrorCode::SUCCESS;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ErrorCode LinkLayerController::LeBigCreateSync(
    uint8_t /* big_handle */, uint16_t /* sync_handle */,
    bluetooth::hci::Enable /* encryption */,
    std::array<uint8_t, 16> /* broadcast_code */, uint8_t /* mse */,
    uint16_t /* big_sync_timeout */, std::vector<uint8_t> /* bis */) {
  return ErrorCode::SUCCESS;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
void LinkLayerController::LeBigTerminateSync(uint8_t /* big_handle */) {}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ErrorCode LinkLayerController::LeRequestPeerSca(uint16_t /* request_handle */) {
  return ErrorCode::SUCCESS;
}

void LinkLayerController::LeSetupIsoDataPath(
    uint16_t /* connection_handle */,
    bluetooth::hci::DataPathDirection /* data_path_direction */,
    uint8_t /* data_path_id */, uint64_t /* codec_id */,
    uint32_t /* controller_Delay */,
    std::vector<uint8_t> /* codec_configuration */) {}

void LinkLayerController::LeRemoveIsoDataPath(
    uint16_t /* connection_handle */,
    bluetooth::hci::RemoveDataPathDirection /* remove_data_path_direction */) {}

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
    LOG_INFO("Unknown handle %04x", handle);
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
    LOG_INFO("Unknown handle %04x", handle);
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
    LOG_INFO("Unknown handle %04x", handle);
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
  class_of_device_ = ClassOfDevice({0, 0, 0});
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
  le_filter_accept_list_.clear();
  le_resolving_list_.clear();
  le_resolving_list_enabled_ = false;
  legacy_advertising_in_use_ = false;
  extended_advertising_in_use_ = false;
  legacy_advertiser_ = LegacyAdvertiser{};
  extended_advertisers_.clear();
  scanner_ = Scanner{};
  initiator_ = Initiator{};
  last_inquiry_ = steady_clock::now();
  inquiry_mode_ = InquiryType::STANDARD;
  inquiry_lap_ = 0;
  inquiry_max_responses_ = 0;

  bluetooth::hci::Lap general_iac;
  general_iac.lap_ = 0x33;  // 0x9E8B33
  current_iac_lap_list_.clear();
  current_iac_lap_list_.emplace_back(general_iac);

  if (inquiry_timer_task_id_ != kInvalidTaskId) {
    CancelScheduledTask(inquiry_timer_task_id_);
    inquiry_timer_task_id_ = kInvalidTaskId;
  }

  if (page_timeout_task_id_ != kInvalidTaskId) {
    CancelScheduledTask(page_timeout_task_id_);
    page_timeout_task_id_ = kInvalidTaskId;
  }

#ifdef ROOTCANAL_LMP
  lm_.reset(link_manager_create(ops_));
#else
  security_manager_ = SecurityManager(10);
#endif
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

  LOG_INFO("Creating SCO connection with %s", bd_addr.ToString().c_str());

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

  LOG_INFO("Creating eSCO connection with %s", bd_addr.ToString().c_str());

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
  LOG_INFO("Accepting eSCO connection request from %s",
           bd_addr.ToString().c_str());

  if (!connections_.HasPendingScoConnection(bd_addr)) {
    LOG_INFO("No pending eSCO connection for %s", bd_addr.ToString().c_str());
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
  LOG_INFO("Rejecting eSCO connection request from %s",
           bd_addr.ToString().c_str());

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

  auto bytes = std::make_shared<std::vector<uint8_t>>();
  bluetooth::packet::BitInserter bit_inserter(*bytes);
  sco_builder->Serialize(bit_inserter);
  auto raw_view =
      bluetooth::hci::PacketView<bluetooth::hci::kLittleEndian>(bytes);
  auto sco_view = bluetooth::hci::ScoView::Create(raw_view);
  ASSERT(sco_view.IsValid());

  return SchedulePeriodicTask(0ms, 20ms, [this, address, sco_view]() {
    LOG_INFO("SCO sending...");
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
