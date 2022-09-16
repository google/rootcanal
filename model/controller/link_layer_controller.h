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
#include "model/controller/controller_properties.h"
#include "model/controller/le_advertiser.h"
#include "model/setup/async_manager.h"
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
using ::bluetooth::hci::OpCode;
using ::bluetooth::hci::PageScanRepetitionMode;

class LinkLayerController {
 public:
  static constexpr size_t kIrkSize = 16;

  // HCI LE Set Random Address command (Vol 4, Part E § 7.8.4).
  ErrorCode LeSetRandomAddress(Address random_address);

  // HCI LE Set Host Feature command (Vol 4, Part E § 7.8.115).
  ErrorCode LeSetHostFeature(uint8_t bit_number, uint8_t bit_value);

  LinkLayerController(const Address& address,
                      const ControllerProperties& properties);

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
  ErrorCode Disconnect(uint16_t handle, ErrorCode reason);

 private:
  void SendDisconnectionCompleteEvent(uint16_t handle, ErrorCode reason);

  void IncomingPacketWithRssi(model::packets::LinkLayerPacketView incoming,
                              uint8_t rssi);

 public:
  const Address& GetAddress() const;

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
      bluetooth::hci::LegacyAdvertisingEventProperties type,
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
  ErrorCode LeFilterAcceptListAddDevice(Address addr, AddressType addr_type);
  ErrorCode LeFilterAcceptListRemoveDevice(Address addr, AddressType addr_type);
  bool LeFilterAcceptListContainsDevice(Address addr, AddressType addr_type);
  bool LeFilterAcceptListFull();
  bool ResolvingListBusy();
  ErrorCode LeSetAddressResolutionEnable(bool enable);
  ErrorCode LeResolvingListClear();
  ErrorCode LeResolvingListAddDevice(Address addr, AddressType addr_type,
                                     std::array<uint8_t, kIrkSize> peerIrk,
                                     std::array<uint8_t, kIrkSize> localIrk);
  ErrorCode LeResolvingListRemoveDevice(Address addr, AddressType addr_type);
  bool LeResolvingListContainsDevice(Address addr, AddressType addr_type);
  bool LeResolvingListFull();
  void LeSetPrivacyMode(AddressType address_type, Address addr, uint8_t mode);

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

  void IncomingPingRequest(model::packets::LinkLayerPacketView packet);

 public:
  bool IsEventUnmasked(bluetooth::hci::EventCode event) const;
  bool IsLeEventUnmasked(bluetooth::hci::SubeventCode subevent) const;

  // TODO
  // The Clock Offset should be specific to an ACL connection.
  // Returning a proper value is not that important.
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
  std::array<uint8_t, 248> const& GetName() { return name_; }

  uint64_t GetLeSupportedFeatures() const {
    return properties_.le_features | le_host_supported_features_;
  }

  uint8_t GetLeAdvertisingTxPower() const { return le_advertising_tx_power_; }
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

  void SetClassOfDevice(ClassOfDevice class_of_device) {
    class_of_device_ = class_of_device;
  }
  void SetClassOfDevice(uint32_t class_of_device) {
    class_of_device_.cod[0] = class_of_device & 0xff;
    class_of_device_.cod[1] = (class_of_device >> 8) & 0xff;
    class_of_device_.cod[2] = (class_of_device >> 16) & 0xff;
  }

  void SetExtendedInquiryData(
      std::vector<uint8_t> const& extended_inquiry_data) {
    extended_inquiry_data_ = extended_inquiry_data;
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
  void SetLeEventMask(uint64_t le_event_mask) {
    le_event_mask_ = le_event_mask;
  }

  void SetName(std::vector<uint8_t> const& name);

  void SetLeHostSupport(bool enable);
  void SetSecureSimplePairingSupport(bool enable);
  void SetSecureConnectionsSupport(bool enable);
  void SetLeAdvertisingParameters(uint16_t interval_min, uint16_t interval_max,
                                  uint8_t ad_type, uint8_t own_address_type,
                                  uint8_t peer_address_type,
                                  Address peer_address, uint8_t channel_map,
                                  uint8_t filter_policy);
  void SetConnectionAcceptTimeout(uint16_t timeout) {
    connection_accept_timeout_ = timeout;
  }
  void SetLeScanResponseData(const std::vector<uint8_t>& data) {
    le_scan_response_data_ = data;
  }
  void SetLeAdvertisingData(const std::vector<uint8_t>& data) {
    le_advertising_data_ = data;
  }

  uint8_t GetLeAdvertisementType() const { return le_advertisement_type_; }

  uint16_t GetLeAdvertisingIntervalMin() const {
    return le_advertising_interval_min_;
  }

  uint16_t GetLeAdvertisingIntervalMax() const {
    return le_advertising_interval_max_;
  }

  uint8_t GetLeAdvertisingOwnAddressType() const {
    return le_advertising_own_address_type_;
  }

  uint8_t GetLeAdvertisingPeerAddressType() const {
    return le_advertising_peer_address_type_;
  }

  Address GetLeAdvertisingPeerAddress() const {
    return le_advertising_peer_address_;
  }

  uint8_t GetLeAdvertisingChannelMap() const {
    return le_advertising_channel_map_;
  }

  uint8_t GetLeAdvertisingFilterPolicy() const {
    return le_advertising_filter_policy_;
  }

  const std::vector<uint8_t>& GetLeAdvertisingData() const {
    return le_advertising_data_;
  }

  const std::vector<uint8_t>& GetLeScanResponseData() const {
    return le_scan_response_data_;
  }

  void SetLeAdvertisementType(uint8_t ad_type) {
    le_advertisement_type_ = ad_type;
  }

 private:
  const Address& address_;
  const ControllerProperties& properties_;

  // Host Supported Features (Vol 2, Part C § 3.3 Feature Mask Definition).
  // Page 1 of the LMP feature mask.
  uint64_t host_supported_features_;
  bool le_host_support_{false};
  bool secure_simple_pairing_host_support_{false};
  bool secure_connections_host_support_{false};

  // Le Host Supported Features (Vol 4, Part E § 7.8.3).
  // Specifies the bits indicating Host support.
  uint64_t le_host_supported_features_;
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
  AuthenticationEnable authentication_enable_;

  // Default Link Policy Settings (Vol 4, Part E § 6.18).
  uint8_t default_link_policy_settings_;

  // Synchronous Flow Control Enable (Vol 4, Part E § 6.22).
  bool sco_flow_control_enable_{false};

  // Local Name (Vol 4, Part E § 6.23).
  std::array<uint8_t, 248> name_;

  // Class of Device (Vol 4, Part E § 6.26).
  ClassOfDevice class_of_device_{{0, 0, 0}};

  // Other configuration parameters.

  // Min Encryption Key Size (Vol 4, Part E § 7.3.102).
  uint8_t min_encryption_key_size_{16};

  // Event Mask (Vol 4, Part E § 7.3.1) and
  // LE Event Mask (Vol 4, Part E § 7.8.1).
  uint64_t event_mask_{0x00001fffffffffff};
  uint64_t le_event_mask_{0x01f};

  // Page Scan Repetition Mode (Vol 2 Part B § 8.3.1 Page Scan substate).
  // The Page Scan Repetition Mode depends on the selected Page Scan Interval.
  PageScanRepetitionMode page_scan_repetition_mode_{PageScanRepetitionMode::R0};

  std::vector<uint8_t> extended_inquiry_data_;
  std::vector<uint8_t> le_scan_response_data_;
  std::vector<uint8_t> le_advertising_data_;

  int8_t le_advertising_tx_power_{0x00};

  // Note: the advertising parameters are initially set to the default
  // values of the parameters of the HCI command LE Set Advertising Parameters.
  uint16_t le_advertising_interval_min_{0x0800};   // 1.28s
  uint16_t le_advertising_interval_max_{0x0800};   // 1.28s
  uint8_t le_advertisement_type_{0x0};             // ADV_IND
  uint8_t le_advertising_own_address_type_{0x0};   // Public Device Address
  uint8_t le_advertising_peer_address_type_{0x0};  // Public Device Address
  Address le_advertising_peer_address_{};
  uint8_t le_advertising_channel_map_{0x7};    // All channels enabled
  uint8_t le_advertising_filter_policy_{0x0};  // Process scan and connection
                                               // requests from all devices

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
  struct ConnectListEntry {
    Address address;
    AddressType address_type;
  };
  std::vector<ConnectListEntry> le_connect_list_;
  struct ResolvingListEntry {
    Address address;
    AddressType address_type;
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
  struct LinkManagerOps ops_;
#else
  SecurityManager security_manager_{10};
#endif /* ROOTCANAL_LMP */
  std::chrono::steady_clock::time_point last_inquiry_;
  model::packets::InquiryType inquiry_mode_{
      model::packets::InquiryType::STANDARD};
  AsyncTaskId inquiry_timer_task_id_ = kInvalidTaskId;
  uint64_t inquiry_lap_{};
  uint8_t inquiry_max_responses_{};
};

}  // namespace rootcanal
