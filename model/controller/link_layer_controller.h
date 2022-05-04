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

#include "hci/address.h"
#include "hci/hci_packets.h"
#include "include/phy.h"
#include "model/controller/acl_connection_handler.h"
#include "model/controller/le_advertiser.h"
#include "model/devices/device_properties.h"
#include "model/setup/async_manager.h"
#include "packets/link_layer_packets.h"

#ifdef ROOTCANAL_LMP
extern "C" {
struct LinkManager;
}
#else
#include "security_manager.h"
#endif /* ROOTCANAL_LMP */

namespace rootcanal {

using ::bluetooth::hci::Address;
using ::bluetooth::hci::ErrorCode;
using ::bluetooth::hci::OpCode;

class LinkLayerController {
 public:
  static constexpr size_t kIrkSize = 16;

  LinkLayerController(const DeviceProperties& properties);
  ErrorCode SendCommandToRemoteByAddress(
      OpCode opcode, bluetooth::packet::PacketView<true> args,
      const Address& remote);
  ErrorCode SendLeCommandToRemoteByAddress(OpCode opcode, const Address& remote,
                                           const Address& local);
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

  ErrorCode AcceptConnectionRequest(const Address& addr, bool try_role_switch);
  void MakePeripheralConnection(const Address& addr, bool try_role_switch);
  ErrorCode RejectConnectionRequest(const Address& addr, uint8_t reason);
  void RejectPeripheralConnection(const Address& addr, uint8_t reason);
  ErrorCode CreateConnection(const Address& addr, uint16_t packet_type,
                             uint8_t page_scan_mode, uint16_t clock_offset,
                             uint8_t allow_role_switch);
  ErrorCode CreateConnectionCancel(const Address& addr);
  ErrorCode Disconnect(uint16_t handle, uint8_t reason);

 private:
  void SendDisconnectionCompleteEvent(uint16_t handle, uint8_t reason);

  void IncomingPacketWithRssi(model::packets::LinkLayerPacketView incoming,
                              uint8_t rssi);

 public:
  void IncomingPacket(model::packets::LinkLayerPacketView incoming);

  void TimerTick();

  void Close();

  AsyncTaskId ScheduleTask(std::chrono::milliseconds delay_ms,
                           const TaskCallback& task);

  void CancelScheduledTask(AsyncTaskId task);

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
      const std::function<void(
          std::shared_ptr<model::packets::LinkLayerPacketBuilder>, Phy::Type)>&
          send_to_remote);

  // Set the callbacks for scheduling tasks.
  void RegisterTaskScheduler(
      std::function<AsyncTaskId(std::chrono::milliseconds, const TaskCallback&)>
          event_scheduler);

  void RegisterPeriodicTaskScheduler(
      std::function<AsyncTaskId(std::chrono::milliseconds,
                                std::chrono::milliseconds, const TaskCallback&)>
          periodic_event_scheduler);

  void RegisterTaskCancel(std::function<void(AsyncTaskId)> cancel);
  void Reset();

  void LeAdvertising();

  ErrorCode SetLeExtendedAddress(uint8_t handle, Address address);

  ErrorCode SetLeExtendedAdvertisingData(uint8_t handle,
                                         const std::vector<uint8_t>& data);

  ErrorCode SetLeExtendedScanResponseData(uint8_t handle,
                                          const std::vector<uint8_t>& data);

  ErrorCode SetLeExtendedAdvertisingParameters(
      uint8_t set, uint16_t interval_min, uint16_t interval_max,
      bluetooth::hci::LegacyAdvertisingProperties type,
      bluetooth::hci::OwnAddressType own_address_type,
      bluetooth::hci::PeerAddressType peer_address_type, Address peer,
      bluetooth::hci::AdvertisingFilterPolicy filter_policy, uint8_t tx_power);
  ErrorCode LeRemoveAdvertisingSet(uint8_t set);
  ErrorCode LeClearAdvertisingSets();
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
                              uint8_t role, uint16_t connection_interval,
                              uint16_t connection_latency,
                              uint16_t supervision_timeout,
                              bool send_le_channel_selection_algorithm_event);

  bool ListBusy(uint16_t ignore_mask);

  bool FilterAcceptListBusy();
  ErrorCode LeFilterAcceptListClear();
  ErrorCode LeFilterAcceptListAddDevice(Address addr, uint8_t addr_type);
  ErrorCode LeFilterAcceptListRemoveDevice(Address addr, uint8_t addr_type);
  bool LeFilterAcceptListContainsDevice(Address addr, uint8_t addr_type);
  bool LeFilterAcceptListFull();
  bool ResolvingListBusy();
  ErrorCode LeSetAddressResolutionEnable(bool enable);
  ErrorCode LeResolvingListClear();
  ErrorCode LeResolvingListAddDevice(Address addr, uint8_t addr_type,
                                     std::array<uint8_t, kIrkSize> peerIrk,
                                     std::array<uint8_t, kIrkSize> localIrk);
  ErrorCode LeResolvingListRemoveDevice(Address addr, uint8_t addr_type);
  bool LeResolvingListContainsDevice(Address addr, uint8_t addr_type);
  bool LeResolvingListFull();
  void LeSetPrivacyMode(uint8_t address_type, Address addr, uint8_t mode);

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
      bluetooth::hci::Enable encryption, std::vector<uint16_t> broadcast_code);
  bluetooth::hci::ErrorCode LeTerminateBig(uint8_t big_handle,
                                           bluetooth::hci::ErrorCode reason);
  bluetooth::hci::ErrorCode LeBigCreateSync(
      uint8_t big_handle, uint16_t sync_handle,
      bluetooth::hci::Enable encryption, std::vector<uint16_t> broadcast_code,
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
                                uint16_t ediv, std::array<uint8_t, 16> ltk);

  ErrorCode LeEnableEncryption(uint16_t handle, std::array<uint8_t, 8> rand,
                               uint16_t ediv, std::array<uint8_t, 16> ltk);

  ErrorCode LeLongTermKeyRequestReply(uint16_t handle,
                                      std::array<uint8_t, 16> ltk);

  ErrorCode LeLongTermKeyRequestNegativeReply(uint16_t handle);

  ErrorCode SetLeAdvertisingEnable(uint8_t le_advertising_enable);

  void LeDisableAdvertisingSets();

  uint8_t LeReadNumberOfSupportedAdvertisingSets();

  ErrorCode SetLeExtendedAdvertisingEnable(
      bluetooth::hci::Enable enable,
      const std::vector<bluetooth::hci::EnabledSet>& enabled_sets);

  bluetooth::hci::OpCode GetLeScanEnable() { return le_scan_enable_; }

  void SetLeScanEnable(bluetooth::hci::OpCode enabling_opcode) {
    le_scan_enable_ = enabling_opcode;
  }
  void SetLeScanType(uint8_t le_scan_type) { le_scan_type_ = le_scan_type; }
  void SetLeScanInterval(uint16_t le_scan_interval) {
    le_scan_interval_ = le_scan_interval;
  }
  void SetLeScanWindow(uint16_t le_scan_window) {
    le_scan_window_ = le_scan_window;
  }
  void SetLeScanFilterPolicy(uint8_t le_scan_filter_policy) {
    le_scan_filter_policy_ = le_scan_filter_policy;
  }
  void SetLeFilterDuplicates(uint8_t le_scan_filter_duplicates) {
    le_scan_filter_duplicates_ = le_scan_filter_duplicates;
  }
  void SetLeAddressType(bluetooth::hci::OwnAddressType le_address_type) {
    le_address_type_ = le_address_type;
  }
  ErrorCode SetLeConnect(bool le_connect, bool extended) {
    if (le_connect_ == le_connect) {
      return ErrorCode::COMMAND_DISALLOWED;
    }
    le_connect_ = le_connect;
    le_extended_connect_ = extended;
    le_pending_connect_ = false;
    return ErrorCode::SUCCESS;
  }
  void SetLeConnectionIntervalMin(uint16_t min) {
    le_connection_interval_min_ = min;
  }
  void SetLeConnectionIntervalMax(uint16_t max) {
    le_connection_interval_max_ = max;
  }
  void SetLeConnectionLatency(uint16_t latency) {
    le_connection_latency_ = latency;
  }
  void SetLeSupervisionTimeout(uint16_t timeout) {
    le_connection_supervision_timeout_ = timeout;
  }
  void SetLeMinimumCeLength(uint16_t min) {
    le_connection_minimum_ce_length_ = min;
  }
  void SetLeMaximumCeLength(uint16_t max) {
    le_connection_maximum_ce_length_ = max;
  }
  void SetLeInitiatorFilterPolicy(uint8_t le_initiator_filter_policy) {
    le_initiator_filter_policy_ = le_initiator_filter_policy;
  }
  void SetLePeerAddressType(uint8_t peer_address_type) {
    le_peer_address_type_ = peer_address_type;
  }
  void SetLePeerAddress(const Address& peer_address) {
    le_peer_address_ = peer_address;
  }

  // Classic
  void StartInquiry(std::chrono::milliseconds timeout);
  void InquiryCancel();
  void InquiryTimeout();
  void SetInquiryMode(uint8_t mode);
  void SetInquiryLAP(uint64_t lap);
  void SetInquiryMaxResponses(uint8_t max);
  void Inquiry();

  void SetInquiryScanEnable(bool enable);
  void SetPageScanEnable(bool enable);

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
  ErrorCode RoleDiscovery(uint16_t handle);
  ErrorCode SwitchRole(Address bd_addr, uint8_t role);
  ErrorCode WriteLinkPolicySettings(uint16_t handle, uint16_t settings);
  ErrorCode FlowSpecification(uint16_t handle, uint8_t flow_direction,
                              uint8_t service_type, uint32_t token_rate,
                              uint32_t token_bucket_size,
                              uint32_t peak_bandwidth, uint32_t access_latency);
  ErrorCode WriteLinkSupervisionTimeout(uint16_t handle, uint16_t timeout);
  ErrorCode WriteDefaultLinkPolicySettings(uint16_t settings);
  uint16_t ReadDefaultLinkPolicySettings();

  void ReadLocalOobData();
  void ReadLocalOobExtendedData();

  ErrorCode AddScoConnection(uint16_t connection_handle, uint16_t packet_type);
  ErrorCode SetupSynchronousConnection(
      uint16_t connection_handle, uint32_t transmit_bandwidth,
      uint32_t receive_bandwidth, uint16_t max_latency, uint16_t voice_setting,
      uint8_t retransmission_effort, uint16_t packet_types);
  ErrorCode AcceptSynchronousConnection(
      Address bd_addr, uint32_t transmit_bandwidth, uint32_t receive_bandwidth,
      uint16_t max_latency, uint16_t voice_setting,
      uint8_t retransmission_effort, uint16_t packet_types);
  ErrorCode RejectSynchronousConnection(Address bd_addr, uint16_t reason);

  bool HasAclConnection();

  void HandleIso(bluetooth::hci::IsoView iso);

 protected:
  void SendLeLinkLayerPacketWithRssi(
      Address source, Address dest, uint8_t rssi,
      std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet);
  void SendLeLinkLayerPacket(
      std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet);
  void SendLinkLayerPacket(
      std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet);
  void IncomingAclPacket(model::packets::LinkLayerPacketView packet);
  void IncomingScoPacket(model::packets::LinkLayerPacketView packet);
  void IncomingDisconnectPacket(model::packets::LinkLayerPacketView packet);
  void IncomingEncryptConnection(model::packets::LinkLayerPacketView packet);
  void IncomingEncryptConnectionResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingInquiryPacket(model::packets::LinkLayerPacketView packet,
                             uint8_t rssi);
  void IncomingInquiryResponsePacket(
      model::packets::LinkLayerPacketView packet);
#ifdef ROOTCANAL_LMP
  void IncomingLmpPacket(model::packets::LinkLayerPacketView packet);
#else
  void IncomingIoCapabilityRequestPacket(
      model::packets::LinkLayerPacketView packet);
  void IncomingIoCapabilityResponsePacket(
      model::packets::LinkLayerPacketView packet);
  void IncomingIoCapabilityNegativeResponsePacket(
      model::packets::LinkLayerPacketView packet);
  void IncomingKeypressNotificationPacket(
      model::packets::LinkLayerPacketView packet);
  void IncomingPasskeyPacket(model::packets::LinkLayerPacketView packet);
  void IncomingPasskeyFailedPacket(model::packets::LinkLayerPacketView packet);
  void IncomingPinRequestPacket(model::packets::LinkLayerPacketView packet);
  void IncomingPinResponsePacket(model::packets::LinkLayerPacketView packet);
#endif /* ROOTCANAL_LMP */
  void IncomingIsoPacket(model::packets::LinkLayerPacketView packet);
  void IncomingIsoConnectionRequestPacket(
      model::packets::LinkLayerPacketView packet);
  void IncomingIsoConnectionResponsePacket(
      model::packets::LinkLayerPacketView packet);
  void IncomingLeAdvertisementPacket(model::packets::LinkLayerPacketView packet,
                                     uint8_t rssi);
  void IncomingLeConnectPacket(model::packets::LinkLayerPacketView packet);
  void IncomingLeConnectCompletePacket(
      model::packets::LinkLayerPacketView packet);
  void IncomingLeConnectionParameterRequest(
      model::packets::LinkLayerPacketView packet);
  void IncomingLeConnectionParameterUpdate(
      model::packets::LinkLayerPacketView packet);
  void IncomingLeEncryptConnection(model::packets::LinkLayerPacketView packet);
  void IncomingLeEncryptConnectionResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingLeReadRemoteFeatures(model::packets::LinkLayerPacketView packet);
  void IncomingLeReadRemoteFeaturesResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingLeScanPacket(model::packets::LinkLayerPacketView packet);
  void IncomingLeScanResponsePacket(model::packets::LinkLayerPacketView packet,
                                    uint8_t rssi);
  void IncomingPagePacket(model::packets::LinkLayerPacketView packet);
  void IncomingPageRejectPacket(model::packets::LinkLayerPacketView packet);
  void IncomingPageResponsePacket(model::packets::LinkLayerPacketView packet);
  void IncomingReadRemoteLmpFeatures(
      model::packets::LinkLayerPacketView packet);
  void IncomingReadRemoteLmpFeaturesResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingReadRemoteSupportedFeatures(
      model::packets::LinkLayerPacketView packet);
  void IncomingReadRemoteSupportedFeaturesResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingReadRemoteExtendedFeatures(
      model::packets::LinkLayerPacketView packet);
  void IncomingReadRemoteExtendedFeaturesResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingReadRemoteVersion(model::packets::LinkLayerPacketView packet);
  void IncomingReadRemoteVersionResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingReadClockOffset(model::packets::LinkLayerPacketView packet);
  void IncomingReadClockOffsetResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingRemoteNameRequest(model::packets::LinkLayerPacketView packet);
  void IncomingRemoteNameRequestResponse(
      model::packets::LinkLayerPacketView packet);

  void IncomingScoConnectionRequest(model::packets::LinkLayerPacketView packet);
  void IncomingScoConnectionResponse(
      model::packets::LinkLayerPacketView packet);
  void IncomingScoDisconnect(model::packets::LinkLayerPacketView packet);

 private:
  const DeviceProperties& properties_;
  AclConnectionHandler connections_;

  // Callbacks to schedule tasks.
  std::function<AsyncTaskId(std::chrono::milliseconds, const TaskCallback&)>
      schedule_task_;
  std::function<AsyncTaskId(std::chrono::milliseconds,
                            std::chrono::milliseconds, const TaskCallback&)>
      schedule_periodic_task_;
  std::function<void(AsyncTaskId)> cancel_task_;

  // Callbacks to send packets back to the HCI.
  std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)> send_acl_;
  std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>
      send_event_;
  std::function<void(std::shared_ptr<bluetooth::hci::ScoBuilder>)> send_sco_;
  std::function<void(std::shared_ptr<bluetooth::hci::IsoBuilder>)> send_iso_;

  // Callback to send packets to remote devices.
  std::function<void(std::shared_ptr<model::packets::LinkLayerPacketBuilder>,
                     Phy::Type phy_type)>
      send_to_remote_;

  uint32_t oob_id_ = 1;
  uint32_t key_id_ = 1;

  // LE state
  std::vector<std::tuple<Address, uint8_t>> le_connect_list_;
  struct ResolvingListEntry {
    Address address;
    uint8_t address_type;
    std::array<uint8_t, kIrkSize> peer_irk;
    std::array<uint8_t, kIrkSize> local_irk;
  };
  std::vector<ResolvingListEntry> le_resolving_list_;
  bool le_resolving_list_enabled_{false};

  Address le_connecting_rpa_;

  std::array<LeAdvertiser, 7> advertisers_;

  bluetooth::hci::OpCode le_scan_enable_{bluetooth::hci::OpCode::NONE};
  uint8_t le_scan_type_{};
  uint16_t le_scan_interval_{};
  uint16_t le_scan_window_{};
  uint8_t le_scan_filter_policy_{};
  uint8_t le_scan_filter_duplicates_{};
  bluetooth::hci::OwnAddressType le_address_type_{};

  bool le_connect_{false};
  bool le_extended_connect_{false};
  bool le_pending_connect_{false};
  uint16_t le_connection_interval_min_{};
  uint16_t le_connection_interval_max_{};
  uint16_t le_connection_latency_{};
  uint16_t le_connection_supervision_timeout_{};
  uint16_t le_connection_minimum_ce_length_{};
  uint16_t le_connection_maximum_ce_length_{};
  uint8_t le_initiator_filter_policy_{};

  Address le_peer_address_{};
  uint8_t le_peer_address_type_{};

  // Classic state
#ifdef ROOTCANAL_LMP
  std::unique_ptr<const LinkManager, void (*)(const LinkManager*)> lm_;
#else
  SecurityManager security_manager_{10};
#endif /* ROOTCANAL_LMP */
  std::chrono::steady_clock::time_point last_inquiry_;
  model::packets::InquiryType inquiry_mode_{
      model::packets::InquiryType::STANDARD};
  AsyncTaskId inquiry_timer_task_id_ = kInvalidTaskId;
  uint64_t inquiry_lap_{};
  uint8_t inquiry_max_responses_{};
  uint16_t default_link_policy_settings_ = 0;

  bool page_scans_enabled_{false};
  bool inquiry_scans_enabled_{false};
};

}  // namespace rootcanal
