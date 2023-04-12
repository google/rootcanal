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

#pragma once

#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <vector>

#include "hci/address.h"
#include "hci/hci_packets.h"
#include "include/phy.h"
#include "model/controller/acl_connection_handler.h"
#include "model/controller/controller_properties.h"
#include "model/controller/le_advertiser.h"
#include "packets/link_layer_packets.h"

#ifdef ROOTCANAL_LMP
extern "C" {
struct LinkManager;
}
#include "lmp.h"
#else
#include "security_manager.h"
#endif /* ROOTCANAL_LMP */

namespace rootcanal {

using ::bluetooth::hci::Address;
using ::bluetooth::hci::AddressType;
using ::bluetooth::hci::AuthenticationEnable;
using ::bluetooth::hci::ClassOfDevice;
using ::bluetooth::hci::ErrorCode;
using ::bluetooth::hci::FilterAcceptListAddressType;
using ::bluetooth::hci::OpCode;
using ::bluetooth::hci::PageScanRepetitionMode;

// Create an address with type Public Device Address or Random Device Address.
AddressWithType PeerDeviceAddress(Address address,
                                  PeerAddressType peer_address_type);
// Create an address with type Public Identity Address or Random Identity
// address.
AddressWithType PeerIdentityAddress(Address address,
                                    PeerAddressType peer_address_type);

class LinkLayerController {
 public:
  static constexpr size_t kIrkSize = 16;
  static constexpr size_t kLtkSize = 16;
  static constexpr size_t kLocalNameSize = 248;
  static constexpr size_t kExtendedInquiryResponseSize = 240;

  // Generate a resolvable private address using the specified IRK.
  static Address generate_rpa(
      std::array<uint8_t, LinkLayerController::kIrkSize> irk);

  LinkLayerController(const Address& address,
                      const ControllerProperties& properties);
  ~LinkLayerController();

  ErrorCode SendCommandToRemoteByAddress(
      OpCode opcode, bluetooth::packet::PacketView<true> args,
      const Address& own_address, const Address& peer_address);
  ErrorCode SendLeCommandToRemoteByAddress(OpCode opcode,
                                           const Address& own_address,
                                           const Address& peer_address);
  ErrorCode SendCommandToRemoteByHandle(
      OpCode opcode, bluetooth::packet::PacketView<true> args, uint16_t handle);
  ErrorCode SendScoToRemote(bluetooth::hci::ScoView sco_packet);
  ErrorCode SendAclToRemote(bluetooth::hci::AclView acl_packet);

#ifdef ROOTCANAL_LMP
  void ForwardToLm(bluetooth::hci::CommandView command);
#else
  void StartSimplePairing(const Address& address);
  void AuthenticateRemoteStage1(const Address& address,
                                PairingType pairing_type);
  void AuthenticateRemoteStage2(const Address& address);
  void SaveKeyAndAuthenticate(uint8_t key_type, const Address& peer);
  ErrorCode LinkKeyRequestReply(const Address& address,
                                const std::array<uint8_t, 16>& key);
  ErrorCode LinkKeyRequestNegativeReply(const Address& address);
  ErrorCode IoCapabilityRequestReply(const Address& peer, uint8_t io_capability,
                                     uint8_t oob_data_present_flag,
                                     uint8_t authentication_requirements);
  ErrorCode IoCapabilityRequestNegativeReply(const Address& peer,
                                             ErrorCode reason);
  ErrorCode PinCodeRequestReply(const Address& peer, std::vector<uint8_t> pin);
  ErrorCode PinCodeRequestNegativeReply(const Address& peer);
  ErrorCode UserConfirmationRequestReply(const Address& peer);
  ErrorCode UserConfirmationRequestNegativeReply(const Address& peer);
  ErrorCode UserPasskeyRequestReply(const Address& peer,
                                    uint32_t numeric_value);
  ErrorCode UserPasskeyRequestNegativeReply(const Address& peer);
  ErrorCode RemoteOobDataRequestReply(const Address& peer,
                                      const std::array<uint8_t, 16>& c,
                                      const std::array<uint8_t, 16>& r);
  ErrorCode RemoteOobDataRequestNegativeReply(const Address& peer);
  ErrorCode RemoteOobExtendedDataRequestReply(
      const Address& peer, const std::array<uint8_t, 16>& c_192,
      const std::array<uint8_t, 16>& r_192,
      const std::array<uint8_t, 16>& c_256,
      const std::array<uint8_t, 16>& r_256);
  ErrorCode SendKeypressNotification(
      const Address& peer,
      bluetooth::hci::KeypressNotificationType notification_type);
  void HandleSetConnectionEncryption(const Address& address, uint16_t handle,
                                     uint8_t encryption_enable);
  ErrorCode SetConnectionEncryption(uint16_t handle, uint8_t encryption_enable);
  void HandleAuthenticationRequest(const Address& address, uint16_t handle);
  ErrorCode AuthenticationRequested(uint16_t handle);
#endif /* ROOTCANAL_LMP */

  std::vector<bluetooth::hci::Lap> const& ReadCurrentIacLap() const;
  void WriteCurrentIacLap(std::vector<bluetooth::hci::Lap> iac_lap);

  ErrorCode AcceptConnectionRequest(const Address& addr, bool try_role_switch);
  void MakePeripheralConnection(const Address& addr, bool try_role_switch);
  ErrorCode RejectConnectionRequest(const Address& addr, uint8_t reason);
  void RejectPeripheralConnection(const Address& addr, uint8_t reason);
  ErrorCode CreateConnection(const Address& addr, uint16_t packet_type,
                             uint8_t page_scan_mode, uint16_t clock_offset,
                             uint8_t allow_role_switch);
  ErrorCode CreateConnectionCancel(const Address& addr);

  // Disconnect a link.
  // \p host_reason is taken from the Disconnect command, and sent over
  // to the remote as disconnect error. \p controller_reason is the code
  // used in the DisconnectionComplete event.
  ErrorCode Disconnect(uint16_t handle, ErrorCode host_reason,
                       ErrorCode controller_reason =
                           ErrorCode::CONNECTION_TERMINATED_BY_LOCAL_HOST);

  // Internal task scheduler.
  // This scheduler is driven by the tick function only,
  // hence the precision of the scheduler is within a tick period.
  class Task;
  using TaskId = uint32_t;
  using TaskCallback = std::function<void(void)>;
  static constexpr TaskId kInvalidTaskId = 0;

  /// Schedule a task to be executed \p delay ms in the future.
  TaskId ScheduleTask(std::chrono::milliseconds delay,
                      TaskCallback task_callback);

  /// Schedule a task to be executed every \p period ms starting
  /// \p delay ms in the future. Note that the task will be executed
  /// at most once per \ref Tick() invocation, hence the period
  /// cannot be lower than the \ref Tick() period.
  TaskId SchedulePeriodicTask(std::chrono::milliseconds delay,
                              std::chrono::milliseconds period,
                              TaskCallback task_callback);

  /// Cancel the selected task.
  void CancelScheduledTask(TaskId task_id);

  // Execute tasks that are pending at the current time.
  void RunPendingTasks();

 private:
  void SendDisconnectionCompleteEvent(uint16_t handle, ErrorCode reason);

 public:
  const Address& GetAddress() const;

  void IncomingPacket(model::packets::LinkLayerPacketView incoming,
                      int8_t rssi);

  void Tick();

  void Close();

  // Set the callbacks for sending packets to the HCI.
  void RegisterEventChannel(
      const std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>&
          send_event);

  void RegisterAclChannel(
      const std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)>&
          send_acl);

  void RegisterScoChannel(
      const std::function<void(std::shared_ptr<bluetooth::hci::ScoBuilder>)>&
          send_sco);

  void RegisterIsoChannel(
      const std::function<void(std::shared_ptr<bluetooth::hci::IsoBuilder>)>&
          send_iso);

  void RegisterRemoteChannel(
      const std::function<
          void(std::shared_ptr<model::packets::LinkLayerPacketBuilder>,
               Phy::Type, int8_t)>& send_to_remote);

  void Reset();

  void LeAdvertising();
  void LeScanning();

  void LeConnectionUpdateComplete(uint16_t handle, uint16_t interval_min,
                                  uint16_t interval_max, uint16_t latency,
                                  uint16_t supervision_timeout);
  ErrorCode LeConnectionUpdate(uint16_t handle, uint16_t interval_min,
                               uint16_t interval_max, uint16_t latency,
                               uint16_t supervision_timeout);
  ErrorCode LeRemoteConnectionParameterRequestReply(
      uint16_t connection_handle, uint16_t interval_min, uint16_t interval_max,
      uint16_t timeout, uint16_t latency, uint16_t minimum_ce_length,
      uint16_t maximum_ce_length);
  ErrorCode LeRemoteConnectionParameterRequestNegativeReply(
      uint16_t connection_handle, bluetooth::hci::ErrorCode reason);
  uint16_t HandleLeConnection(AddressWithType addr, AddressWithType own_addr,
                              bluetooth::hci::Role role,
                              uint16_t connection_interval,
                              uint16_t connection_latency,
                              uint16_t supervision_timeout,
                              bool send_le_channel_selection_algorithm_event);

  bool ResolvingListBusy();
  bool FilterAcceptListBusy();

  bool LeFilterAcceptListContainsDevice(
      FilterAcceptListAddressType address_type, Address address);
  bool LeFilterAcceptListContainsDevice(AddressWithType address);

  enum IrkSelection {
    Peer,  // Use Peer IRK for RPA resolution or generation.
    Local  // Use Local IRK for RPA resolution or generation.
  };

  // If the selected address is a Resolvable Private Address, then
  // resolve the address using the resolving list. If the address cannot
  // be resolved none is returned. If the address is not a Resolvable
  // Private Address, the original address is returned.
  std::optional<AddressWithType> ResolvePrivateAddress(AddressWithType address,
                                                       IrkSelection irk);

  // Generate a Resolvable Private for the selected peer.
  // If the address is not found in the resolving list none is returned.
  // `local` indicates whether to use the local (true) or peer (false) IRK when
  // generating the Resolvable Private Address.
  std::optional<AddressWithType> GenerateResolvablePrivateAddress(
      AddressWithType address, IrkSelection irk);

  // Check if the selected address matches one of the controller's device
  // addresses (public or random static).
  bool IsLocalPublicOrRandomAddress(AddressWithType address) {
    switch (address.GetAddressType()) {
      case AddressType::PUBLIC_DEVICE_ADDRESS:
        return address.GetAddress() == address_;
      case AddressType::RANDOM_DEVICE_ADDRESS:
        return address.GetAddress() == random_address_;
      default:
        return false;
    }
  }

  void LeReadIsoTxSync(uint16_t handle);
  void LeSetCigParameters(
      uint8_t cig_id, uint32_t sdu_interval_m_to_s,
      uint32_t sdu_interval_s_to_m,
      bluetooth::hci::ClockAccuracy clock_accuracy,
      bluetooth::hci::Packing packing, bluetooth::hci::Enable framing,
      uint16_t max_transport_latency_m_to_s,
      uint16_t max_transport_latency_s_to_m,
      std::vector<bluetooth::hci::CisParametersConfig> cis_config);
  bluetooth::hci::ErrorCode LeCreateCis(
      std::vector<bluetooth::hci::CreateCisConfig> cis_config);
  bluetooth::hci::ErrorCode LeRemoveCig(uint8_t cig_id);
  bluetooth::hci::ErrorCode LeAcceptCisRequest(uint16_t handle);
  bluetooth::hci::ErrorCode LeRejectCisRequest(
      uint16_t handle, bluetooth::hci::ErrorCode reason);
  bluetooth::hci::ErrorCode LeCreateBig(
      uint8_t big_handle, uint8_t advertising_handle, uint8_t num_bis,
      uint32_t sdu_interval, uint16_t max_sdu, uint16_t max_transport_latency,
      uint8_t rtn, bluetooth::hci::SecondaryPhyType phy,
      bluetooth::hci::Packing packing, bluetooth::hci::Enable framing,
      bluetooth::hci::Enable encryption,
      std::array<uint8_t, 16> broadcast_code);
  bluetooth::hci::ErrorCode LeTerminateBig(uint8_t big_handle,
                                           bluetooth::hci::ErrorCode reason);
  bluetooth::hci::ErrorCode LeBigCreateSync(
      uint8_t big_handle, uint16_t sync_handle,
      bluetooth::hci::Enable encryption, std::array<uint8_t, 16> broadcast_code,
      uint8_t mse, uint16_t big_syunc_timeout, std::vector<uint8_t> bis);
  void LeBigTerminateSync(uint8_t big_handle);
  bluetooth::hci::ErrorCode LeRequestPeerSca(uint16_t request_handle);
  void LeSetupIsoDataPath(uint16_t connection_handle,
                          bluetooth::hci::DataPathDirection data_path_direction,
                          uint8_t data_path_id, uint64_t codec_id,
                          uint32_t controller_Delay,
                          std::vector<uint8_t> codec_configuration);
  void LeRemoveIsoDataPath(
      uint16_t connection_handle,
      bluetooth::hci::RemoveDataPathDirection remove_data_path_direction);

  void HandleLeEnableEncryption(uint16_t handle, std::array<uint8_t, 8> rand,
                                uint16_t ediv,
                                std::array<uint8_t, kLtkSize> ltk);

  ErrorCode LeEnableEncryption(uint16_t handle, std::array<uint8_t, 8> rand,
                               uint16_t ediv,
                               std::array<uint8_t, kLtkSize> ltk);

  ErrorCode LeLongTermKeyRequestReply(uint16_t handle,
                                      std::array<uint8_t, kLtkSize> ltk);

  ErrorCode LeLongTermKeyRequestNegativeReply(uint16_t handle);

  uint8_t LeReadNumberOfSupportedAdvertisingSets();

  // Classic
  void StartInquiry(std::chrono::milliseconds timeout);
  void InquiryCancel();
  void InquiryTimeout();
  void SetInquiryMode(uint8_t mode);
  void SetInquiryLAP(uint64_t lap);
  void SetInquiryMaxResponses(uint8_t max);
  void Inquiry();

  bool GetInquiryScanEnable() const { return inquiry_scan_enable_; }
  void SetInquiryScanEnable(bool enable);

  bool GetPageScanEnable() const { return page_scan_enable_; }
  void SetPageScanEnable(bool enable);

  uint16_t GetPageTimeout() const { return page_timeout_; }
  void SetPageTimeout(uint16_t page_timeout);

  ErrorCode ChangeConnectionPacketType(uint16_t handle, uint16_t types);
  ErrorCode ChangeConnectionLinkKey(uint16_t handle);
  ErrorCode CentralLinkKey(uint8_t key_flag);
  ErrorCode HoldMode(uint16_t handle, uint16_t hold_mode_max_interval,
                     uint16_t hold_mode_min_interval);
  ErrorCode SniffMode(uint16_t handle, uint16_t sniff_max_interval,
                      uint16_t sniff_min_interval, uint16_t sniff_attempt,
                      uint16_t sniff_timeout);
  ErrorCode ExitSniffMode(uint16_t handle);
  ErrorCode QosSetup(uint16_t handle, uint8_t service_type, uint32_t token_rate,
                     uint32_t peak_bandwidth, uint32_t latency,
                     uint32_t delay_variation);
  ErrorCode RoleDiscovery(uint16_t handle, bluetooth::hci::Role* role);
  ErrorCode SwitchRole(Address bd_addr, bluetooth::hci::Role role);
  ErrorCode ReadLinkPolicySettings(uint16_t handle, uint16_t* settings);
  ErrorCode WriteLinkPolicySettings(uint16_t handle, uint16_t settings);
  ErrorCode FlowSpecification(uint16_t handle, uint8_t flow_direction,
                              uint8_t service_type, uint32_t token_rate,
                              uint32_t token_bucket_size,
                              uint32_t peak_bandwidth, uint32_t access_latency);
  ErrorCode WriteLinkSupervisionTimeout(uint16_t handle, uint16_t timeout);
  ErrorCode WriteDefaultLinkPolicySettings(uint16_t settings);
  void CheckExpiringConnection(uint16_t handle);
  uint16_t ReadDefaultLinkPolicySettings() const;

  void ReadLocalOobData();
  void ReadLocalOobExtendedData();

  ErrorCode AddScoConnection(uint16_t connection_handle, uint16_t packet_type,
                             ScoDatapath datapath);
  ErrorCode SetupSynchronousConnection(
      uint16_t connection_handle, uint32_t transmit_bandwidth,
      uint32_t receive_bandwidth, uint16_t max_latency, uint16_t voice_setting,
      uint8_t retransmission_effort, uint16_t packet_types,
      ScoDatapath datapath);
  ErrorCode AcceptSynchronousConnection(
      Address bd_addr, uint32_t transmit_bandwidth, uint32_t receive_bandwidth,
      uint16_t max_latency, uint16_t voice_setting,
      uint8_t retransmission_effort, uint16_t packet_types);
  ErrorCode RejectSynchronousConnection(Address bd_addr, uint16_t reason);

  bool HasAclConnection();

  void HandleIso(bluetooth::hci::IsoView iso);

  // BR/EDR Commands

  // HCI Read Rssi command (Vol 4, Part E § 7.5.4).
  ErrorCode ReadRssi(uint16_t connection_handle, int8_t* rssi);

  // LE Commands

  // HCI LE Set Random Address command (Vol 4, Part E § 7.8.4).
  ErrorCode LeSetRandomAddress(Address random_address);

  // HCI LE Set Resolvable Private Address Timeout command
  // (Vol 4, Part E § 7.8.45).
  ErrorCode LeSetResolvablePrivateAddressTimeout(uint16_t rpa_timeout);

  // HCI LE Read Phy command (Vol 4, Part E § 7.8.47).
  ErrorCode LeReadPhy(uint16_t connection_handle,
                      bluetooth::hci::PhyType* tx_phy,
                      bluetooth::hci::PhyType* rx_phy);

  // HCI LE Set Default Phy command (Vol 4, Part E § 7.8.48).
  ErrorCode LeSetDefaultPhy(bool all_phys_no_transmit_preference,
                            bool all_phys_no_receive_preference,
                            uint8_t tx_phys, uint8_t rx_phys);

  // HCI LE Set Phy command (Vol 4, Part E § 7.8.49).
  ErrorCode LeSetPhy(uint16_t connection_handle,
                     bool all_phys_no_transmit_preference,
                     bool all_phys_no_receive_preference, uint8_t tx_phys,
                     uint8_t rx_phys, bluetooth::hci::PhyOptions phy_options);

  // HCI LE Set Host Feature command (Vol 4, Part E § 7.8.115).
  ErrorCode LeSetHostFeature(uint8_t bit_number, uint8_t bit_value);

  // LE Filter Accept List

  // HCI command LE_Clear_Filter_Accept_List (Vol 4, Part E § 7.8.15).
  ErrorCode LeClearFilterAcceptList();

  // HCI command LE_Add_Device_To_Filter_Accept_List (Vol 4, Part E § 7.8.16).
  ErrorCode LeAddDeviceToFilterAcceptList(
      FilterAcceptListAddressType address_type, Address address);

  // HCI command LE_Remove_Device_From_Filter_Accept_List (Vol 4, Part E
  // § 7.8.17).
  ErrorCode LeRemoveDeviceFromFilterAcceptList(
      FilterAcceptListAddressType address_type, Address address);

  // LE Address Resolving

  // HCI command LE_Add_Device_To_Resolving_List (Vol 4, Part E § 7.8.38).
  ErrorCode LeAddDeviceToResolvingList(
      PeerAddressType peer_identity_address_type, Address peer_identity_address,
      std::array<uint8_t, kIrkSize> peer_irk,
      std::array<uint8_t, kIrkSize> local_irk);

  // HCI command LE_Remove_Device_From_Resolving_List (Vol 4, Part E § 7.8.39).
  ErrorCode LeRemoveDeviceFromResolvingList(
      PeerAddressType peer_identity_address_type,
      Address peer_identity_address);

  // HCI command LE_Clear_Resolving_List (Vol 4, Part E § 7.8.40).
  ErrorCode LeClearResolvingList();

  // HCI command LE_Read_Peer_Resolvable_Address (Vol 4, Part E § 7.8.42).
  ErrorCode LeReadPeerResolvableAddress(
      PeerAddressType peer_identity_address_type, Address peer_identity_address,
      Address* peer_resolvable_address);

  // HCI command LE_Read_Local_Resolvable_Address (Vol 4, Part E § 7.8.43).
  ErrorCode LeReadLocalResolvableAddress(
      PeerAddressType peer_identity_address_type, Address peer_identity_address,
      Address* local_resolvable_address);

  // HCI command LE_Set_Address_Resolution_Enable (Vol 4, Part E § 7.8.44).
  ErrorCode LeSetAddressResolutionEnable(bool enable);

  // HCI command LE_Set_Privacy_Mode (Vol 4, Part E § 7.8.77).
  ErrorCode LeSetPrivacyMode(PeerAddressType peer_identity_address_type,
                             Address peer_identity_address,
                             bluetooth::hci::PrivacyMode privacy_mode);

  // Legacy Advertising

  // HCI command LE_Set_Advertising_Parameters (Vol 4, Part E § 7.8.5).
  ErrorCode LeSetAdvertisingParameters(
      uint16_t advertising_interval_min, uint16_t advertising_interval_max,
      bluetooth::hci::AdvertisingType advertising_type,
      bluetooth::hci::OwnAddressType own_address_type,
      bluetooth::hci::PeerAddressType peer_address_type, Address peer_address,
      uint8_t advertising_channel_map,
      bluetooth::hci::AdvertisingFilterPolicy advertising_filter_policy);

  // HCI command LE_Set_Advertising_Data (Vol 4, Part E § 7.8.7).
  ErrorCode LeSetAdvertisingData(const std::vector<uint8_t>& advertising_data);

  // HCI command LE_Set_Scan_Response_Data (Vol 4, Part E § 7.8.8).
  ErrorCode LeSetScanResponseData(
      const std::vector<uint8_t>& scan_response_data);

  // HCI command LE_Advertising_Enable (Vol 4, Part E § 7.8.9).
  ErrorCode LeSetAdvertisingEnable(bool advertising_enable);

  // Extended Advertising

  // HCI command LE_Set_Advertising_Set_Random_Address (Vol 4, Part E § 7.8.52).
  ErrorCode LeSetAdvertisingSetRandomAddress(uint8_t advertising_handle,
                                             Address random_address);

  // HCI command LE_Set_Advertising_Parameters (Vol 4, Part E § 7.8.53).
  ErrorCode LeSetExtendedAdvertisingParameters(
      uint8_t advertising_handle,
      AdvertisingEventProperties advertising_event_properties,
      uint16_t primary_advertising_interval_min,
      uint16_t primary_advertising_interval_max,
      uint8_t primary_advertising_channel_map,
      bluetooth::hci::OwnAddressType own_address_type,
      bluetooth::hci::PeerAddressType peer_address_type, Address peer_address,
      bluetooth::hci::AdvertisingFilterPolicy advertising_filter_policy,
      uint8_t advertising_tx_power,
      bluetooth::hci::PrimaryPhyType primary_advertising_phy,
      uint8_t secondary_max_skip,
      bluetooth::hci::SecondaryPhyType secondary_advertising_phy,
      uint8_t advertising_sid, bool scan_request_notification_enable);

  // HCI command LE_Set_Extended_Advertising_Data (Vol 4, Part E § 7.8.54).
  ErrorCode LeSetExtendedAdvertisingData(
      uint8_t advertising_handle, bluetooth::hci::Operation operation,
      bluetooth::hci::FragmentPreference fragment_preference,
      const std::vector<uint8_t>& advertising_data);

  // HCI command LE_Set_Extended_Scan_Response_Data (Vol 4, Part E § 7.8.55).
  ErrorCode LeSetExtendedScanResponseData(
      uint8_t advertising_handle, bluetooth::hci::Operation operation,
      bluetooth::hci::FragmentPreference fragment_preference,
      const std::vector<uint8_t>& scan_response_data);

  // HCI command LE_Set_Extended_Advertising_Enable (Vol 4, Part E § 7.8.56).
  ErrorCode LeSetExtendedAdvertisingEnable(
      bool enable, const std::vector<bluetooth::hci::EnabledSet>& sets);

  // HCI command LE_Remove_Advertising_Set (Vol 4, Part E § 7.8.59).
  ErrorCode LeRemoveAdvertisingSet(uint8_t advertising_handle);

  // HCI command LE_Clear_Advertising_Sets (Vol 4, Part E § 7.8.60).
  ErrorCode LeClearAdvertisingSets();

  // Legacy Scanning

  // HCI command LE_Set_Scan_Parameters (Vol 4, Part E § 7.8.10).
  ErrorCode LeSetScanParameters(
      bluetooth::hci::LeScanType scan_type, uint16_t scan_interval,
      uint16_t scan_window, bluetooth::hci::OwnAddressType own_address_type,
      bluetooth::hci::LeScanningFilterPolicy scanning_filter_policy);

  // HCI command LE_Set_Scan_Enable (Vol 4, Part E § 7.8.11).
  ErrorCode LeSetScanEnable(bool enable, bool filter_duplicates);

  // Extended Scanning

  // HCI command LE_Set_Extended_Scan_Parameters (Vol 4, Part E § 7.8.64).
  ErrorCode LeSetExtendedScanParameters(
      bluetooth::hci::OwnAddressType own_address_type,
      bluetooth::hci::LeScanningFilterPolicy scanning_filter_policy,
      uint8_t scanning_phys,
      std::vector<bluetooth::hci::PhyScanParameters> scanning_phy_parameters);

  // HCI command LE_Set_Extended_Scan_Enable (Vol 4, Part E § 7.8.65).
  ErrorCode LeSetExtendedScanEnable(
      bool enable, bluetooth::hci::FilterDuplicates filter_duplicates,
      uint16_t duration, uint16_t period);

  // Legacy Connection

  // HCI LE Create Connection command (Vol 4, Part E § 7.8.12).
  ErrorCode LeCreateConnection(
      uint16_t scan_interval, uint16_t scan_window,
      bluetooth::hci::InitiatorFilterPolicy initiator_filter_policy,
      AddressWithType peer_address,
      bluetooth::hci::OwnAddressType own_address_type,
      uint16_t connection_interval_min, uint16_t connection_interval_max,
      uint16_t max_latency, uint16_t supervision_timeout,
      uint16_t min_ce_length, uint16_t max_ce_length);

  // HCI LE Create Connection Cancel command (Vol 4, Part E § 7.8.12).
  ErrorCode LeCreateConnectionCancel();

  // Extended Connection

  // HCI LE Extended Create Connection command (Vol 4, Part E § 7.8.66).
  ErrorCode LeExtendedCreateConnection(
      bluetooth::hci::InitiatorFilterPolicy initiator_filter_policy,
      bluetooth::hci::OwnAddressType own_address_type,
      AddressWithType peer_address, uint8_t initiating_phys,
      std::vector<bluetooth::hci::LeCreateConnPhyScanParameters>
          initiating_phy_parameters);

 protected:
  void SendLinkLayerPacket(
      std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet,
      int8_t tx_power = 0);
  void SendLeLinkLayerPacket(
      std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet,
      int8_t tx_power = 0);

  void IncomingAclPacket(model::packets::LinkLayerPacketView incoming,
                         int8_t rssi);
  void IncomingScoPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingDisconnectPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingEncryptConnection(model::packets::LinkLayerPacketView incoming);
  void IncomingEncryptConnectionResponse(
      model::packets::LinkLayerPacketView incoming);
  void IncomingInquiryPacket(model::packets::LinkLayerPacketView incoming,
                             uint8_t rssi);
  void IncomingInquiryResponsePacket(
      model::packets::LinkLayerPacketView incoming);
#ifdef ROOTCANAL_LMP
  void IncomingLmpPacket(model::packets::LinkLayerPacketView incoming);
#else
  void IncomingIoCapabilityRequestPacket(
      model::packets::LinkLayerPacketView incoming);
  void IncomingIoCapabilityResponsePacket(
      model::packets::LinkLayerPacketView incoming);
  void IncomingIoCapabilityNegativeResponsePacket(
      model::packets::LinkLayerPacketView incoming);
  void IncomingKeypressNotificationPacket(
      model::packets::LinkLayerPacketView incoming);
  void IncomingPasskeyPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingPasskeyFailedPacket(
      model::packets::LinkLayerPacketView incoming);
  void IncomingPinRequestPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingPinResponsePacket(model::packets::LinkLayerPacketView incoming);
#endif /* ROOTCANAL_LMP */
  void IncomingIsoPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingIsoConnectionRequestPacket(
      model::packets::LinkLayerPacketView incoming);
  void IncomingIsoConnectionResponsePacket(
      model::packets::LinkLayerPacketView incoming);

  void ScanIncomingLeLegacyAdvertisingPdu(
      model::packets::LeLegacyAdvertisingPduView& pdu, uint8_t rssi);
  void ScanIncomingLeExtendedAdvertisingPdu(
      model::packets::LeExtendedAdvertisingPduView& pdu, uint8_t rssi);
  void ConnectIncomingLeLegacyAdvertisingPdu(
      model::packets::LeLegacyAdvertisingPduView& pdu);
  void ConnectIncomingLeExtendedAdvertisingPdu(
      model::packets::LeExtendedAdvertisingPduView& pdu);

  void IncomingLeLegacyAdvertisingPdu(
      model::packets::LinkLayerPacketView incoming, uint8_t rssi);
  void IncomingLeExtendedAdvertisingPdu(
      model::packets::LinkLayerPacketView incoming, uint8_t rssi);

  void IncomingLeConnectPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingLeConnectCompletePacket(
      model::packets::LinkLayerPacketView incoming);
  void IncomingLeConnectionParameterRequest(
      model::packets::LinkLayerPacketView incoming);
  void IncomingLeConnectionParameterUpdate(
      model::packets::LinkLayerPacketView incoming);
  void IncomingLeEncryptConnection(
      model::packets::LinkLayerPacketView incoming);
  void IncomingLeEncryptConnectionResponse(
      model::packets::LinkLayerPacketView incoming);
  void IncomingLeReadRemoteFeatures(
      model::packets::LinkLayerPacketView incoming);
  void IncomingLeReadRemoteFeaturesResponse(
      model::packets::LinkLayerPacketView incoming);

  void ProcessIncomingLegacyScanRequest(
      AddressWithType scanning_address,
      AddressWithType resolved_scanning_address,
      AddressWithType advertising_address);
  void ProcessIncomingExtendedScanRequest(
      ExtendedAdvertiser const& advertiser, AddressWithType scanning_address,
      AddressWithType resolved_scanning_address,
      AddressWithType advertising_address);

  bool ProcessIncomingLegacyConnectRequest(
      model::packets::LeConnectView const& connect_ind);
  bool ProcessIncomingExtendedConnectRequest(
      ExtendedAdvertiser& advertiser,
      model::packets::LeConnectView const& connect_ind);

  void IncomingLeScanPacket(model::packets::LinkLayerPacketView incoming);

  void IncomingLeScanResponsePacket(
      model::packets::LinkLayerPacketView incoming, uint8_t rssi);
  void IncomingPagePacket(model::packets::LinkLayerPacketView incoming);
  void IncomingPageRejectPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingPageResponsePacket(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteLmpFeatures(
      model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteLmpFeaturesResponse(
      model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteSupportedFeatures(
      model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteSupportedFeaturesResponse(
      model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteExtendedFeatures(
      model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteExtendedFeaturesResponse(
      model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteVersion(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteVersionResponse(
      model::packets::LinkLayerPacketView incoming);
  void IncomingReadClockOffset(model::packets::LinkLayerPacketView incoming);
  void IncomingReadClockOffsetResponse(
      model::packets::LinkLayerPacketView incoming);
  void IncomingRemoteNameRequest(model::packets::LinkLayerPacketView incoming);
  void IncomingRemoteNameRequestResponse(
      model::packets::LinkLayerPacketView incoming);

  void IncomingScoConnectionRequest(
      model::packets::LinkLayerPacketView incoming);
  void IncomingScoConnectionResponse(
      model::packets::LinkLayerPacketView incoming);
  void IncomingScoDisconnect(model::packets::LinkLayerPacketView incoming);

  void IncomingPingRequest(model::packets::LinkLayerPacketView incoming);
  void IncomingRoleSwitchRequest(model::packets::LinkLayerPacketView incoming);
  void IncomingRoleSwitchResponse(model::packets::LinkLayerPacketView incoming);

 public:
  bool IsEventUnmasked(bluetooth::hci::EventCode event) const;
  bool IsLeEventUnmasked(bluetooth::hci::SubeventCode subevent) const;

  // TODO
  // The Clock Offset should be specific to an ACL connection.
  // Returning a proper value is not that important.
  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  uint32_t GetClockOffset() const { return 0; }

  // TODO
  // The Page Scan Repetition Mode should be specific to an ACL connection or
  // a paging session.
  PageScanRepetitionMode GetPageScanRepetitionMode() const {
    return page_scan_repetition_mode_;
  }

  // TODO
  // The Encryption Key Size should be specific to an ACL connection.
  uint8_t GetEncryptionKeySize() const { return min_encryption_key_size_; }

  bool GetScoFlowControlEnable() const { return sco_flow_control_enable_; }

  AuthenticationEnable GetAuthenticationEnable() {
    return authentication_enable_;
  }

  std::array<uint8_t, kLocalNameSize> const& GetLocalName() {
    return local_name_;
  }

  uint64_t GetLeSupportedFeatures() const {
    return properties_.le_features | le_host_supported_features_;
  }

  uint16_t GetConnectionAcceptTimeout() const {
    return connection_accept_timeout_;
  }

  uint16_t GetVoiceSetting() const { return voice_setting_; }
  const ClassOfDevice& GetClassOfDevice() const { return class_of_device_; }

  uint8_t GetMaxLmpFeaturesPageNumber() {
    return properties_.lmp_features.size() - 1;
  }

  uint64_t GetLmpFeatures(uint8_t page_number = 0) {
    return page_number == 1 ? host_supported_features_
                            : properties_.lmp_features[page_number];
  }

  void SetLocalName(std::vector<uint8_t> const& local_name);
  void SetLocalName(std::array<uint8_t, kLocalNameSize> const& local_name);
  void SetExtendedInquiryResponse(
      std::vector<uint8_t> const& extended_inquiry_response);

  void SetClassOfDevice(ClassOfDevice class_of_device) {
    class_of_device_ = class_of_device;
  }

  void SetClassOfDevice(uint32_t class_of_device) {
    class_of_device_.cod[0] = class_of_device & UINT8_MAX;
    class_of_device_.cod[1] = (class_of_device >> 8) & UINT8_MAX;
    class_of_device_.cod[2] = (class_of_device >> 16) & UINT8_MAX;
  }

  void SetAuthenticationEnable(AuthenticationEnable enable) {
    authentication_enable_ = enable;
  }

  void SetScoFlowControlEnable(bool enable) {
    sco_flow_control_enable_ = enable;
  }
  void SetVoiceSetting(uint16_t voice_setting) {
    voice_setting_ = voice_setting;
  }
  void SetEventMask(uint64_t event_mask) { event_mask_ = event_mask; }

  void SetEventMaskPage2(uint64_t event_mask) {
    event_mask_page_2_ = event_mask;
  }
  void SetLeEventMask(uint64_t le_event_mask) {
    le_event_mask_ = le_event_mask;
  }

  void SetLeHostSupport(bool enable);
  void SetSecureSimplePairingSupport(bool enable);
  void SetSecureConnectionsSupport(bool enable);

  void SetConnectionAcceptTimeout(uint16_t timeout) {
    connection_accept_timeout_ = timeout;
  }

  bool LegacyAdvertising() const { return legacy_advertising_in_use_; }
  bool ExtendedAdvertising() const { return extended_advertising_in_use_; }

  bool SelectLegacyAdvertising() {
    if (extended_advertising_in_use_) {
      return false;
    }
    legacy_advertising_in_use_ = true;
    return true;
  }

  bool SelectExtendedAdvertising() {
    if (legacy_advertising_in_use_) {
      return false;
    }
    extended_advertising_in_use_ = true;
    return true;
  }

  uint16_t GetLeSuggestedMaxTxOctets() const {
    return le_suggested_max_tx_octets_;
  }
  uint16_t GetLeSuggestedMaxTxTime() const { return le_suggested_max_tx_time_; }

  void SetLeSuggestedMaxTxOctets(uint16_t max_tx_octets) {
    le_suggested_max_tx_octets_ = max_tx_octets;
  }
  void SetLeSuggestedMaxTxTime(uint16_t max_tx_time) {
    le_suggested_max_tx_time_ = max_tx_time;
  }

  TaskId StartScoStream(Address address);

 private:
  const Address& address_;
  const ControllerProperties& properties_;

  // Host Supported Features (Vol 2, Part C § 3.3 Feature Mask Definition).
  // Page 1 of the LMP feature mask.
  uint64_t host_supported_features_{0};
  bool le_host_support_{false};
  bool secure_simple_pairing_host_support_{false};
  bool secure_connections_host_support_{false};

  // Le Host Supported Features (Vol 4, Part E § 7.8.3).
  // Specifies the bits indicating Host support.
  uint64_t le_host_supported_features_{0};
  bool connected_isochronous_stream_host_support_{false};
  bool connection_subrating_host_support_{false};

  // LE Random Address (Vol 4, Part E § 7.8.4).
  Address random_address_{Address::kEmpty};

  // HCI configuration parameters.
  //
  // Provide the current HCI Configuration Parameters as defined in section
  // Vol 4, Part E § 6 of the core specification.

  // Scan Enable (Vol 4, Part E § 6.1).
  bool page_scan_enable_{false};
  bool inquiry_scan_enable_{false};

  // Inquiry Scan Interval and Window
  // (Vol 4, Part E § 6.2, 6.3).
  uint16_t inquiry_scan_interval_{0x1000};
  uint16_t inquiry_scan_window_{0x0012};

  // Page Timeout (Vol 4, Part E § 6.6).
  uint16_t page_timeout_{0x2000};

  // Connection Accept Timeout (Vol 4, Part E § 6.7).
  uint16_t connection_accept_timeout_{0x1FA0};

  // Page Scan Interval and Window
  // (Vol 4, Part E § 6.8, 6.9).
  uint16_t page_scan_interval_{0x0800};
  uint16_t page_scan_window_{0x0012};

  // Voice Setting (Vol 4, Part E § 6.12).
  uint16_t voice_setting_{0x0060};

  // Authentication Enable (Vol 4, Part E § 6.16).
  AuthenticationEnable authentication_enable_{
      AuthenticationEnable::NOT_REQUIRED};

  // Default Link Policy Settings (Vol 4, Part E § 6.18).
  uint8_t default_link_policy_settings_{0x0000};

  // Synchronous Flow Control Enable (Vol 4, Part E § 6.22).
  bool sco_flow_control_enable_{false};

  // Local Name (Vol 4, Part E § 6.23).
  std::array<uint8_t, kLocalNameSize> local_name_{};

  // Extended Inquiry Response (Vol 4, Part E § 6.24).
  std::array<uint8_t, kExtendedInquiryResponseSize>
      extended_inquiry_response_{};

  // Class of Device (Vol 4, Part E § 6.26).
  ClassOfDevice class_of_device_{{0, 0, 0}};

  // Other configuration parameters.

  // Current IAC LAP (Vol 4, Part E § 7.3.44).
  std::vector<bluetooth::hci::Lap> current_iac_lap_list_{};

  // Min Encryption Key Size (Vol 4, Part E § 7.3.102).
  uint8_t min_encryption_key_size_{16};

  // Event Mask (Vol 4, Part E § 7.3.1) and
  // Event Mask Page 2 (Vol 4, Part E § 7.3.69) and
  // LE Event Mask (Vol 4, Part E § 7.8.1).
  uint64_t event_mask_{0x00001fffffffffff};
  uint64_t event_mask_page_2_{0x0};
  uint64_t le_event_mask_{0x01f};

  // Suggested Default Data Length (Vol 4, Part E § 7.8.34).
  uint16_t le_suggested_max_tx_octets_{0x001b};
  uint16_t le_suggested_max_tx_time_{0x0148};

  // Resolvable Private Address Timeout (Vol 4, Part E § 7.8.45).
  std::chrono::seconds resolvable_private_address_timeout_{0x0384};

  // Page Scan Repetition Mode (Vol 2 Part B § 8.3.1 Page Scan substate).
  // The Page Scan Repetition Mode depends on the selected Page Scan Interval.
  PageScanRepetitionMode page_scan_repetition_mode_{PageScanRepetitionMode::R0};

  AclConnectionHandler connections_;

  // Callbacks to send packets back to the HCI.
  std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)> send_acl_;
  std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>
      send_event_;
  std::function<void(std::shared_ptr<bluetooth::hci::ScoBuilder>)> send_sco_;
  std::function<void(std::shared_ptr<bluetooth::hci::IsoBuilder>)> send_iso_;

  // Callback to send packets to remote devices.
  std::function<void(std::shared_ptr<model::packets::LinkLayerPacketBuilder>,
                     Phy::Type phy_type, int8_t tx_power)>
      send_to_remote_;

  uint32_t oob_id_{1};
  uint32_t key_id_{1};

  struct FilterAcceptListEntry {
    FilterAcceptListAddressType address_type;
    Address address;
  };

  std::vector<FilterAcceptListEntry> le_filter_accept_list_;

  struct ResolvingListEntry {
    PeerAddressType peer_identity_address_type;
    Address peer_identity_address;
    std::array<uint8_t, kIrkSize> peer_irk;
    std::array<uint8_t, kIrkSize> local_irk;
    bluetooth::hci::PrivacyMode privacy_mode;

    // Resolvable Private Address being used by the local device.
    // It is the last resolvable private address generated for
    // this identity address.
    std::optional<Address> local_resolvable_address;
    // Resolvable Private Address being used by the peer device.
    // It is the last resolvable private address received that resolved
    // to this identity address.
    std::optional<Address> peer_resolvable_address;
  };

  std::vector<ResolvingListEntry> le_resolving_list_;
  bool le_resolving_list_enabled_{false};

  // Flag set when any legacy advertising command has been received
  // since the last power-on-reset.
  // From Vol 4, Part E § 3.1.1 Legacy and extended advertising,
  // extended advertising are rejected when this bit is set.
  bool legacy_advertising_in_use_{false};

  // Flag set when any extended advertising command has been received
  // since the last power-on-reset.
  // From Vol 4, Part E § 3.1.1 Legacy and extended advertising,
  // legacy advertising are rejected when this bit is set.
  bool extended_advertising_in_use_{false};

  // Legacy advertising state.
  LegacyAdvertiser legacy_advertiser_{};

  // Extended advertising sets.
  std::unordered_map<uint8_t, ExtendedAdvertiser> extended_advertisers_{};

  struct Scanner {
    bool scan_enable;
    std::chrono::steady_clock::duration period;
    std::chrono::steady_clock::duration duration;
    bluetooth::hci::FilterDuplicates filter_duplicates;
    bluetooth::hci::OwnAddressType own_address_type;
    bluetooth::hci::LeScanningFilterPolicy scan_filter_policy;

    struct PhyParameters {
      bool enabled;
      bluetooth::hci::LeScanType scan_type;
      uint16_t scan_interval;
      uint16_t scan_window;
    };

    PhyParameters le_1m_phy;
    PhyParameters le_coded_phy;

    // Save information about the advertising PDU being scanned.
    bool connectable_scan_response;
    std::optional<AddressWithType> pending_scan_request{};

    // Time keeping
    std::optional<std::chrono::steady_clock::time_point> timeout;
    std::optional<std::chrono::steady_clock::time_point> periodical_timeout;

    // Packet History
    std::vector<model::packets::LinkLayerPacketView> history;

    bool IsEnabled() const { return scan_enable; }

    bool IsPacketInHistory(model::packets::LinkLayerPacketView packet) const {
      return std::any_of(
          history.begin(), history.end(),
          [packet](model::packets::LinkLayerPacketView const& a) {
            return a.size() == packet.size() &&
                   std::equal(a.begin(), a.end(), packet.begin());
          });
    }

    void AddPacketToHistory(model::packets::LinkLayerPacketView packet) {
      history.push_back(packet);
    }
  };

  // Legacy and extended scanning properties.
  // Legacy and extended scanning are disambiguated by the use
  // of legacy_advertising_in_use_ and extended_advertising_in_use_ flags.
  // Only one type of advertising may be used during a controller session.
  Scanner scanner_{};

  struct Initiator {
    bool connect_enable;
    bluetooth::hci::InitiatorFilterPolicy initiator_filter_policy;
    bluetooth::hci::AddressWithType peer_address{};
    bluetooth::hci::OwnAddressType own_address_type;

    struct PhyParameters {
      bool enabled;
      uint16_t scan_interval;
      uint16_t scan_window;
      uint16_t connection_interval_min;
      uint16_t connection_interval_max;
      uint16_t max_latency;
      uint16_t supervision_timeout;
      uint16_t min_ce_length;
      uint16_t max_ce_length;
    };

    PhyParameters le_1m_phy;
    PhyParameters le_2m_phy;
    PhyParameters le_coded_phy;

    // Save information about the ongoing connection.
    Address initiating_address{};  // TODO: AddressWithType
    std::optional<AddressWithType> pending_connect_request{};

    bool IsEnabled() const { return connect_enable; }
    void Disable() { connect_enable = false; }
  };

  // Legacy and extended initiating properties.
  // Legacy and extended initiating are disambiguated by the use
  // of legacy_advertising_in_use_ and extended_advertising_in_use_ flags.
  // Only one type of advertising may be used during a controller session.
  Initiator initiator_{};

  // Classic state
#ifdef ROOTCANAL_LMP
  std::unique_ptr<const LinkManager, void (*)(const LinkManager*)> lm_;
  struct LinkManagerOps ops_;
#else
  SecurityManager security_manager_{10};
#endif /* ROOTCANAL_LMP */

  TaskId page_timeout_task_id_ = kInvalidTaskId;

  std::chrono::steady_clock::time_point last_inquiry_;
  model::packets::InquiryType inquiry_mode_{
      model::packets::InquiryType::STANDARD};
  TaskId inquiry_timer_task_id_ = kInvalidTaskId;
  uint64_t inquiry_lap_{};
  uint8_t inquiry_max_responses_{};

 public:
  // Type of scheduled tasks.
  class Task {
   public:
    Task(std::chrono::steady_clock::time_point time,
         std::chrono::milliseconds period, TaskCallback callback,
         TaskId task_id)
        : time(time),
          periodic(true),
          period(period),
          callback(std::move(callback)),
          task_id(task_id) {}

    Task(std::chrono::steady_clock::time_point time, TaskCallback callback,
         TaskId task_id)
        : time(time),
          periodic(false),
          callback(std::move(callback)),
          task_id(task_id) {}

    // Operators needed to be in a collection
    bool operator<(const Task& another) const {
      return std::make_pair(time, task_id) <
             std::make_pair(another.time, another.task_id);
    }

    // These fields should no longer be public if the class ever becomes
    // public or gets more complex
    std::chrono::steady_clock::time_point time;
    const bool periodic;
    std::chrono::milliseconds period{};
    TaskCallback callback;
    TaskId task_id;
  };

 private:
  // List currently pending tasks.
  std::set<Task> task_queue_{};
  TaskId task_counter_{0};

  // Return the next valid unused task identifier.
  TaskId NextTaskId();
};

}  // namespace rootcanal
