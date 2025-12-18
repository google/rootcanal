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

#include <packet_runtime.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

#include "hci/address.h"
#include "hci/address_with_type.h"
#include "model/controller/acl_connection_handler.h"
#include "model/controller/controller_properties.h"
#include "model/controller/le_advertiser.h"
#include "model/controller/sco_connection.h"
#include "model/controller/vendor_commands/le_apcf.h"
#include "packets/hci_packets.h"
#include "packets/link_layer_packets.h"
#include "phy.h"
#include "rust/include/rootcanal_rs.h"

namespace rootcanal {

using ::bluetooth::hci::Address;
using ::bluetooth::hci::AuthenticationEnable;
using ::bluetooth::hci::ErrorCode;
using ::bluetooth::hci::OpCode;
using ::bluetooth::hci::PageScanRepetitionMode;

class BrEdrController {
public:
  static constexpr size_t kLocalNameSize = 248;
  static constexpr size_t kExtendedInquiryResponseSize = 240;

  // Unique instance identifier.
  const uint32_t id_;

  BrEdrController(const Address& address, const ControllerProperties& properties, uint32_t id = 0);
  ~BrEdrController();

  ErrorCode SendScoToRemote(bluetooth::hci::ScoView sco_packet);

  void ForwardToLm(bluetooth::hci::CommandView command);

  std::vector<bluetooth::hci::Lap> const& ReadCurrentIacLap() const;
  void WriteCurrentIacLap(std::vector<bluetooth::hci::Lap> iac_lap);

  // Link Control commands (Vol 4, Part E § 7.1).

  ErrorCode Inquiry(uint8_t lap, uint8_t inquiry_length, uint8_t num_responses);
  ErrorCode InquiryCancel();
  ErrorCode CreateConnection(Address bd_addr, uint16_t packet_type,
                             uint8_t page_scan_repetition_mode, uint16_t clock_offset,
                             uint8_t allow_role_switch);
  ErrorCode Disconnect(
          uint16_t connection_handle, ErrorCode host_reason,
          ErrorCode controller_reason = ErrorCode::CONNECTION_TERMINATED_BY_LOCAL_HOST);
  ErrorCode CreateConnectionCancel(Address bd_addr);
  ErrorCode AcceptConnectionRequest(Address bd_addr, bool try_role_switch);
  ErrorCode RejectConnectionRequest(Address bd_addr, uint8_t reason);
  ErrorCode ChangeConnectionPacketType(uint16_t connection_handle, uint16_t packet_type);
  ErrorCode ChangeConnectionLinkKey(uint16_t connection_handle);
  ErrorCode RemoteNameRequest(Address bd_addr, uint8_t page_scan_repetition_mode,
                              uint16_t clock_offset);
  ErrorCode ReadRemoteSupportedFeatures(uint16_t connection_handle);
  ErrorCode ReadRemoteExtendedFeatures(uint16_t connection_handle, uint8_t page_number);
  ErrorCode ReadRemoteVersionInformation(uint16_t connection_handle);
  ErrorCode ReadClockOffset(uint16_t connection_handle);
  ErrorCode AddScoConnection(uint16_t connection_handle, uint16_t packet_type);
  ErrorCode SetupSynchronousConnection(uint16_t connection_handle, uint32_t transmit_bandwidth,
                                       uint32_t receive_bandwidth, uint16_t max_latency,
                                       uint16_t voice_setting, uint8_t retransmission_effort,
                                       uint16_t packet_types, ScoDatapath datapath);
  ErrorCode AcceptSynchronousConnection(Address bd_addr, uint32_t transmit_bandwidth,
                                        uint32_t receive_bandwidth, uint16_t max_latency,
                                        uint16_t voice_setting, uint8_t retransmission_effort,
                                        uint16_t packet_types);
  ErrorCode RejectSynchronousConnection(Address bd_addr, uint16_t reason);
  ErrorCode EnhancedSetupSynchronousConnection(
          uint16_t connection_handle, uint32_t transmit_bandwidth, uint32_t receive_bandwidth,
          bluetooth::hci::ScoCodingFormat transmit_coding_format,
          bluetooth::hci::ScoCodingFormat receive_coding_format, uint16_t transmit_codec_frame_size,
          uint16_t receive_codec_frame_size, uint32_t input_bandwidth, uint32_t output_bandwidth,
          bluetooth::hci::ScoCodingFormat input_coding_format,
          bluetooth::hci::ScoCodingFormat output_coding_format, uint16_t input_coded_data_size,
          uint16_t output_coded_data_size, bluetooth::hci::ScoPcmDataFormat input_pcm_data_format,
          bluetooth::hci::ScoPcmDataFormat output_pcm_data_format,
          uint8_t input_pcm_sample_payload_msb_position,
          uint8_t output_pcm_sample_payload_msb_position,
          bluetooth::hci::ScoDataPath input_data_path, bluetooth::hci::ScoDataPath output_data_path,
          uint8_t input_transport_unit_size, uint8_t output_transport_unit_size,
          uint16_t max_latency, uint16_t packet_type,
          bluetooth::hci::RetransmissionEffort retransmission_effort);
  ErrorCode EnhancedAcceptSynchronousConnection(
          Address bd_addr, uint32_t transmit_bandwidth, uint32_t receive_bandwidth,
          bluetooth::hci::ScoCodingFormat transmit_coding_format,
          bluetooth::hci::ScoCodingFormat receive_coding_format, uint16_t transmit_codec_frame_size,
          uint16_t receive_codec_frame_size, uint32_t input_bandwidth, uint32_t output_bandwidth,
          bluetooth::hci::ScoCodingFormat input_coding_format,
          bluetooth::hci::ScoCodingFormat output_coding_format, uint16_t input_coded_data_size,
          uint16_t output_coded_data_size, bluetooth::hci::ScoPcmDataFormat input_pcm_data_format,
          bluetooth::hci::ScoPcmDataFormat output_pcm_data_format,
          uint8_t input_pcm_sample_payload_msb_position,
          uint8_t output_pcm_sample_payload_msb_position,
          bluetooth::hci::ScoDataPath input_data_path, bluetooth::hci::ScoDataPath output_data_path,
          uint8_t input_transport_unit_size, uint8_t output_transport_unit_size,
          uint16_t max_latency, uint16_t packet_type,
          bluetooth::hci::RetransmissionEffort retransmission_effort);

  // Link Policy commands (Vol 4, Part E § 7.2).

  ErrorCode HoldMode(uint16_t connection_handle, uint16_t hold_mode_max_interval,
                     uint16_t hold_mode_min_interval);
  ErrorCode SniffMode(uint16_t connection_handle, uint16_t sniff_max_interval,
                      uint16_t sniff_min_interval, uint16_t sniff_attempt, uint16_t sniff_timeout);
  ErrorCode ExitSniffMode(uint16_t connection_handle);
  ErrorCode QosSetup(uint16_t connection_handle, uint8_t service_type, uint32_t token_rate,
                     uint32_t peak_bandwidth, uint32_t latency, uint32_t delay_variation);
  ErrorCode RoleDiscovery(uint16_t connection_handle, bluetooth::hci::Role* role);
  ErrorCode SwitchRole(Address bd_addr, bluetooth::hci::Role role);
  ErrorCode ReadLinkPolicySettings(uint16_t connection_handle, uint16_t* link_policy_settings);
  ErrorCode WriteLinkPolicySettings(uint16_t connection_handle, uint16_t link_policy_settings);
  ErrorCode ReadDefaultLinkPolicySettings(uint16_t* default_link_policy_settings) const;
  ErrorCode WriteDefaultLinkPolicySettings(uint16_t default_link_policy_settings);
  ErrorCode FlowSpecification(uint16_t connection_handle, uint8_t flow_direction,
                              uint8_t service_type, uint32_t token_rate, uint32_t token_bucket_size,
                              uint32_t peak_bandwidth, uint32_t access_latency);
  ErrorCode SniffSubrating(uint16_t connection_handle, uint16_t max_latency,
                           uint16_t min_remote_timeout, uint16_t min_local_timeout);

  // Controller & Baseband commands (Vol 4, Part E § 7.3).

  void SetEventMask(uint64_t event_mask) { event_mask_ = event_mask; }
  void Reset();
  void WriteLocalName(std::array<uint8_t, 248> const& local_name);
  void ReadScanEnable(bluetooth::hci::ScanEnable* scan_enable);
  void WriteScanEnable(bluetooth::hci::ScanEnable scan_enable);
  void WriteExtendedInquiryResponse(bool fec_required,
                                    std::array<uint8_t, 240> const& extended_inquiry_response);
  void ReadLocalOobData(std::array<uint8_t, 16>* c, std::array<uint8_t, 16>* r);
  void ReadLocalOobExtendedData(std::array<uint8_t, 16>* c_192, std::array<uint8_t, 16>* r_192,
                                std::array<uint8_t, 16>* c_256, std::array<uint8_t, 16>* r_256);

  // Status parameters (Vol 4, Part E § 7.5).

  ErrorCode ReadRssi(uint16_t connection_handle, int8_t* rssi);
  ErrorCode ReadEncryptionKeySize(uint16_t connection_handle, uint8_t* key_size);

  // Internal task scheduler.
  //
  // This scheduler is driven by the tick function only,
  // hence the precision of the scheduler is within a tick period.

  class Task;
  using TaskId = uint32_t;
  using TaskCallback = std::function<void(void)>;
  static constexpr TaskId kInvalidTaskId = 0;

  /// Schedule a task to be executed \p delay ms in the future.
  TaskId ScheduleTask(std::chrono::milliseconds delay, TaskCallback task_callback);

  /// Schedule a task to be executed every \p period ms starting
  /// \p delay ms in the future. Note that the task will be executed
  /// at most once per \ref Tick() invocation, hence the period
  /// cannot be lower than the \ref Tick() period.
  TaskId SchedulePeriodicTask(std::chrono::milliseconds delay, std::chrono::milliseconds period,
                              TaskCallback task_callback);

  /// Cancel the selected task.
  void CancelScheduledTask(TaskId task_id);

  // Execute tasks that are pending at the current time.
  void RunPendingTasks();

private:
  void SendDisconnectionCompleteEvent(uint16_t handle, ErrorCode reason);
  void MakePeripheralConnection(const Address& addr, bool try_role_switch);
  void RejectPeripheralConnection(const Address& addr, uint8_t reason);

public:
  const Address& GetAddress() const;

  void IncomingPacket(model::packets::LinkLayerPacketView incoming, int8_t rssi);

  void Tick();
  void Close();

  /// Send disconnection events for all connected links, with the provided
  /// reason. Does not remove the local connection contexts.
  void DisconnectAll(ErrorCode reason);

  // Set the callbacks for sending packets to the HCI.
  void RegisterEventChannel(
          const std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>& send_event);

  void RegisterAclChannel(
          const std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)>& send_acl);

  void RegisterScoChannel(
          const std::function<void(std::shared_ptr<bluetooth::hci::ScoBuilder>)>& send_sco);

  void RegisterRemoteChannel(
          const std::function<void(std::shared_ptr<model::packets::LinkLayerPacketBuilder>,
                                   Phy::Type, int8_t)>& send_to_remote);

  void Paging();
  void Inquiry();

  void InquiryTimeout();
  void SetInquiryMode(uint8_t mode);

  uint16_t GetPageTimeout() const { return page_timeout_; }
  void SetPageTimeout(uint16_t page_timeout);

  ErrorCode CentralLinkKey(uint8_t key_flag);
  ErrorCode WriteLinkSupervisionTimeout(uint16_t handle, uint16_t timeout);
  void CheckExpiringConnection(uint16_t handle);

  // Returns true if the specified ACL connection handle is valid.
  bool HasAclConnection(uint16_t connection_handle);

  void HandleAcl(bluetooth::hci::AclView acl);

protected:
  void SendLinkLayerPacket(std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet,
                           int8_t tx_power = 0);

  void IncomingAclPacket(model::packets::LinkLayerPacketView incoming, int8_t rssi);
  void IncomingScoPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingDisconnectPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingEncryptConnection(model::packets::LinkLayerPacketView incoming);
  void IncomingEncryptConnectionResponse(model::packets::LinkLayerPacketView incoming);
  void IncomingInquiryPacket(model::packets::LinkLayerPacketView incoming, uint8_t rssi);
  void IncomingInquiryResponsePacket(model::packets::LinkLayerPacketView incoming);
  void IncomingLmpPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingPagePacket(model::packets::LinkLayerPacketView incoming);
  void IncomingPageRejectPacket(model::packets::LinkLayerPacketView incoming);
  void IncomingPageResponsePacket(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteLmpFeatures(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteLmpFeaturesResponse(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteSupportedFeatures(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteSupportedFeaturesResponse(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteExtendedFeatures(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteExtendedFeaturesResponse(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteVersion(model::packets::LinkLayerPacketView incoming);
  void IncomingReadRemoteVersionResponse(model::packets::LinkLayerPacketView incoming);
  void IncomingReadClockOffset(model::packets::LinkLayerPacketView incoming);
  void IncomingReadClockOffsetResponse(model::packets::LinkLayerPacketView incoming);
  void IncomingRemoteNameRequest(model::packets::LinkLayerPacketView incoming);
  void IncomingRemoteNameRequestResponse(model::packets::LinkLayerPacketView incoming);

  void IncomingScoConnectionRequest(model::packets::LinkLayerPacketView incoming);
  void IncomingScoConnectionResponse(model::packets::LinkLayerPacketView incoming);
  void IncomingScoDisconnect(model::packets::LinkLayerPacketView incoming);

  void IncomingPingRequest(model::packets::LinkLayerPacketView incoming);
  void IncomingRoleSwitchRequest(model::packets::LinkLayerPacketView incoming);
  void IncomingRoleSwitchResponse(model::packets::LinkLayerPacketView incoming);

public:
  bool IsEventUnmasked(bluetooth::hci::EventCode event) const;

  // TODO
  // The Clock Offset should be specific to an ACL connection.
  // Returning a proper value is not that important.
  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  uint32_t GetClockOffset() const { return 0; }

  void SetMinEncryptionKeySize(uint8_t min_encryption_key_size) {
    min_encryption_key_size_ = min_encryption_key_size;
  }

  bool GetScoFlowControlEnable() const { return sco_flow_control_enable_; }
  AuthenticationEnable GetAuthenticationEnable() { return authentication_enable_; }
  std::array<uint8_t, kLocalNameSize> const& GetLocalName() { return local_name_; }
  uint16_t GetConnectionAcceptTimeout() const { return connection_accept_timeout_; }
  uint16_t GetVoiceSetting() const { return voice_setting_; }
  uint32_t GetClassOfDevice() const { return class_of_device_; }

  uint8_t GetMaxLmpFeaturesPageNumber() { return properties_.lmp_features.size() - 1; }

  uint64_t GetLmpFeatures(uint8_t page_number = 0) {
    return page_number == 1 ? host_supported_features_ : properties_.lmp_features[page_number];
  }

  void SetLocalName(std::vector<uint8_t> const& local_name);
  void SetExtendedInquiryResponse(std::vector<uint8_t> const& extended_inquiry_response);
  void SetClassOfDevice(uint32_t class_of_device) { class_of_device_ = class_of_device; }
  void SetAuthenticationEnable(AuthenticationEnable enable) { authentication_enable_ = enable; }
  void SetScoFlowControlEnable(bool enable) { sco_flow_control_enable_ = enable; }
  void SetVoiceSetting(uint16_t voice_setting) { voice_setting_ = voice_setting; }
  void SetEventMaskPage2(uint64_t event_mask) { event_mask_page_2_ = event_mask; }
  void SetLeHostSupport(bool enable);
  void SetSecureSimplePairingSupport(bool enable);
  void SetSecureConnectionsSupport(bool enable);
  void SetConnectionAcceptTimeout(uint16_t timeout) { connection_accept_timeout_ = timeout; }

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

  // Inquiry Mode (Vol 4, Part E § 6.5).
  model::packets::InquiryType inquiry_mode_{model::packets::InquiryType::STANDARD};

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
  AuthenticationEnable authentication_enable_{AuthenticationEnable::NOT_REQUIRED};

  // Default Link Policy Settings (Vol 4, Part E § 6.18).
  uint8_t default_link_policy_settings_{0x0000};

  // Synchronous Flow Control Enable (Vol 4, Part E § 6.22).
  bool sco_flow_control_enable_{false};

  // Local Name (Vol 4, Part E § 6.23).
  std::array<uint8_t, kLocalNameSize> local_name_{};

  // Extended Inquiry Response (Vol 4, Part E § 6.24).
  std::array<uint8_t, kExtendedInquiryResponseSize> extended_inquiry_response_{};

  // Class of Device (Vol 4, Part E § 6.26).
  uint32_t class_of_device_{0};

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

  // Resolvable Private Address Timeout (Vol 4, Part E § 7.8.45).
  std::chrono::seconds resolvable_private_address_timeout_{0x0384};

  // Page Scan Repetition Mode (Vol 2 Part B § 8.3.1 Page Scan substate).
  // The Page Scan Repetition Mode depends on the selected Page Scan Interval.
  PageScanRepetitionMode page_scan_repetition_mode_{PageScanRepetitionMode::R0};

  AclConnectionHandler connections_;

  // Callbacks to send packets back to the HCI.
  std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)> send_acl_;
  std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)> send_event_;
  std::function<void(std::shared_ptr<bluetooth::hci::ScoBuilder>)> send_sco_;

  // Callback to send packets to remote devices.
  std::function<void(std::shared_ptr<model::packets::LinkLayerPacketBuilder>, Phy::Type phy_type,
                     int8_t tx_power)>
          send_to_remote_;

  uint32_t oob_id_{1};
  uint32_t key_id_{1};

  // Rust state.
  std::unique_ptr<const LinkManager, void (*)(const LinkManager*)> lm_;
  struct ControllerOps controller_ops_;

  // Classic state.
  struct PageState {
    Address bd_addr;
    uint8_t allow_role_switch;
    std::chrono::steady_clock::time_point next_page_event{};
    std::chrono::steady_clock::time_point page_timeout{};
  };

  // Page substate.
  // RootCanal will allow only one page request running at the same time.
  std::optional<PageState> page_;

  struct PageScanState {
    Address bd_addr;
    bool authentication_required;
    uint8_t allow_role_switch;
  };

  // Page scan substate.
  // Set when page scan is enabled and a valid page request is received.
  // Holds the state for the connection being established.
  std::optional<PageScanState> page_scan_;

  // Inquiry substate.
  struct InquiryState {
    uint8_t lap;
    uint8_t num_responses;
    std::chrono::steady_clock::time_point next_inquiry_event{};
    std::chrono::steady_clock::time_point inquiry_timeout{};
  };

  // Inquiry substate.
  // RootCanal will allow only one inquiry request running at the same time.
  std::optional<InquiryState> inquiry_;

public:
  // Type of scheduled tasks.
  class Task {
  public:
    Task(std::chrono::steady_clock::time_point time, std::chrono::milliseconds period,
         TaskCallback callback, TaskId task_id)
        : time(time),
          periodic(true),
          period(period),
          callback(std::move(callback)),
          task_id(task_id) {}

    Task(std::chrono::steady_clock::time_point time, TaskCallback callback, TaskId task_id)
        : time(time), periodic(false), callback(std::move(callback)), task_id(task_id) {}

    // Operators needed to be in a collection
    bool operator<(const Task& another) const {
      return std::make_pair(time, task_id) < std::make_pair(another.time, another.task_id);
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
