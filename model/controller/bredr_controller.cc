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

#include "model/controller/bredr_controller.h"

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

using namespace model::packets;
using namespace std::literals;

using TaskId = rootcanal::BrEdrController::TaskId;

namespace rootcanal {

constexpr milliseconds kNoDelayMs(0);
constexpr milliseconds kPageInterval(1000);
constexpr milliseconds kInquiryInterval(2000);

const Address& BrEdrController::GetAddress() const { return address_; }

bool BrEdrController::IsEventUnmasked(EventCode event) const {
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

// =============================================================================
//  Link Control commands (Vol 4, Part E § 7.1)
// =============================================================================

// HCI Inquiry (Vol 4, Part E § 7.1.1).
ErrorCode BrEdrController::Inquiry(uint8_t lap, uint8_t inquiry_length, uint8_t num_responses) {
  if (num_responses > 0xff || inquiry_length < 0x1 || inquiry_length > 0x30) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  if (inquiry_.has_value()) {
    INFO(id_, "Inquiry command is already pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  auto now = std::chrono::steady_clock::now();
  inquiry_ = InquiryState{
          .lap = lap,
          .num_responses = num_responses,
          .next_inquiry_event = now + kInquiryInterval,
          .inquiry_timeout = now + std::chrono::milliseconds(inquiry_length * 1280),
  };

  return ErrorCode::SUCCESS;
}

// HCI Inquiry Cancel (Vol 4, Part E § 7.1.2).
ErrorCode BrEdrController::InquiryCancel() {
  if (!inquiry_.has_value()) {
    INFO(id_, "Inquiry command is not pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  inquiry_ = {};
  return ErrorCode::SUCCESS;
}

// HCI Create Connection (Vol 4, Part E § 7.1.5).
ErrorCode BrEdrController::CreateConnection(Address bd_addr, uint16_t /* packet_type */,
                                            uint8_t /* page_scan_repetition_mode */,
                                            uint16_t /* clock_offset */,
                                            uint8_t allow_role_switch) {
  // RootCanal only accepts one pending outgoing connection at any time.
  if (page_.has_value()) {
    INFO(id_, "Create Connection command is already pending");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // Reject the command if a connection already exists
  // for the selected peer address.
  if (connections_.GetAclConnectionHandle(bd_addr).has_value()) {
    INFO(id_, "Connection with {} already exists", bd_addr);
    return ErrorCode::CONNECTION_ALREADY_EXISTS;
  }

  // Reject the command if a pending connection already exists
  // for the selected peer address.
  if (page_scan_.has_value() && page_scan_->bd_addr == bd_addr) {
    INFO(id_, "Connection with {} is already being established", bd_addr);
    return ErrorCode::CONNECTION_ALREADY_EXISTS;
  }

  auto now = std::chrono::steady_clock::now();
  page_ = PageState{
          .bd_addr = bd_addr,
          .allow_role_switch = allow_role_switch,
          .next_page_event = now + kPageInterval,
          .page_timeout = now + slots(page_timeout_),
  };

  return ErrorCode::SUCCESS;
}

// HCI Disconnect (Vol 4, Part E § 7.1.6).
// \p host_reason is taken from the Disconnect command, and sent over
// to the remote as disconnect error. \p controller_reason is the code
// used in the DisconnectionComplete event.
ErrorCode BrEdrController::Disconnect(uint16_t handle, ErrorCode host_reason,
                                      ErrorCode controller_reason) {
  if (connections_.HasScoHandle(handle)) {
    const Address remote = connections_.GetScoAddress(handle);
    INFO(id_, "Disconnecting eSCO connection with {}", remote);

    SendLinkLayerPacket(model::packets::ScoDisconnectBuilder::Create(
            GetAddress(), remote, static_cast<uint8_t>(host_reason)));

    connections_.Disconnect(handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
    SendDisconnectionCompleteEvent(handle, controller_reason);
    return ErrorCode::SUCCESS;
  }

  if (connections_.HasAclHandle(handle)) {
    auto connection = connections_.GetAclConnection(handle);
    auto address = connection.address;
    INFO(id_, "Disconnecting ACL connection with {}", connection.address);

    auto sco_handle = connections_.GetScoConnectionHandle(connection.address);
    if (sco_handle.has_value()) {
      SendLinkLayerPacket(model::packets::ScoDisconnectBuilder::Create(
              connection.own_address, connection.address, static_cast<uint8_t>(host_reason)));

      connections_.Disconnect(*sco_handle,
                              [this](TaskId task_id) { CancelScheduledTask(task_id); });
      SendDisconnectionCompleteEvent(*sco_handle, controller_reason);
    }

    SendLinkLayerPacket(model::packets::DisconnectBuilder::Create(
            connection.own_address, connection.address, static_cast<uint8_t>(host_reason)));

    connections_.Disconnect(handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
    SendDisconnectionCompleteEvent(handle, controller_reason);

    ASSERT(link_manager_remove_link(lm_.get(), reinterpret_cast<uint8_t (*)[6]>(address.data())));
    return ErrorCode::SUCCESS;
  }

  return ErrorCode::UNKNOWN_CONNECTION;
}

// HCI Create Connection Cancel (Vol 4, Part E § 7.1.7).
ErrorCode BrEdrController::CreateConnectionCancel(Address bd_addr) {
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
              ErrorCode::UNKNOWN_CONNECTION, 0, bd_addr, bluetooth::hci::LinkType::ACL,
              bluetooth::hci::Enable::DISABLED));
    });
  }

  page_ = {};
  return ErrorCode::SUCCESS;
}

// HCI Accept Connection Request (Vol 4, Part E § 7.1.8).
ErrorCode BrEdrController::AcceptConnectionRequest(Address bd_addr, bool try_role_switch) {
  if (page_scan_.has_value() && page_scan_->bd_addr == bd_addr) {
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
    uint16_t sco_handle = *connections_.GetScoConnectionHandle(bd_addr);
    ScoLinkParameters link_parameters = {};
    ScoConnectionParameters connection_parameters =
            connections_.GetScoConnectionParameters(bd_addr);

    if (!connections_.AcceptPendingScoConnection(bd_addr, connection_parameters, [this, bd_addr] {
          return BrEdrController::StartScoStream(bd_addr);
        })) {
      connections_.CancelPendingScoConnection(bd_addr);
      status = ErrorCode::SCO_INTERVAL_REJECTED;  // TODO: proper status code
      sco_handle = 0;
    } else {
      link_parameters = connections_.GetScoLinkParameters(bd_addr);
    }

    // Send eSCO connection response to peer.
    SendLinkLayerPacket(model::packets::ScoConnectionResponseBuilder::Create(
            GetAddress(), bd_addr, (uint8_t)status, link_parameters.transmission_interval,
            link_parameters.retransmission_window, link_parameters.rx_packet_length,
            link_parameters.tx_packet_length, link_parameters.air_mode, link_parameters.extended));

    // Schedule HCI Connection Complete event.
    if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
      ScheduleTask(kNoDelayMs, [this, status, sco_handle, bd_addr]() {
        send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
                ErrorCode(status), sco_handle, bd_addr, bluetooth::hci::LinkType::SCO,
                bluetooth::hci::Enable::DISABLED));
      });
    }

    return ErrorCode::SUCCESS;
  }

  INFO(id_, "No pending connection for {}", bd_addr);
  return ErrorCode::UNKNOWN_CONNECTION;
}

// HCI Accept Connection Request (Vol 4, Part E § 7.1.9).
ErrorCode BrEdrController::RejectConnectionRequest(Address bd_addr, uint8_t reason) {
  if (!page_scan_.has_value() || page_scan_->bd_addr != bd_addr) {
    INFO(id_, "No pending connection for {}", bd_addr);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(kNoDelayMs,
               [this, bd_addr, reason]() { RejectPeripheralConnection(bd_addr, reason); });

  return ErrorCode::SUCCESS;
}

// HCI Change Connection Packet Type (Vol 4, Part E § 7.1.14).
ErrorCode BrEdrController::ChangeConnectionPacketType(uint16_t connection_handle,
                                                      uint16_t packet_type) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  ScheduleTask(kNoDelayMs, [this, connection_handle, packet_type]() {
    if (IsEventUnmasked(EventCode::CONNECTION_PACKET_TYPE_CHANGED)) {
      send_event_(bluetooth::hci::ConnectionPacketTypeChangedBuilder::Create(
              ErrorCode::SUCCESS, connection_handle, packet_type));
    }
  });

  return ErrorCode::SUCCESS;
}

// HCI Change Connection Link Key (Vol 4, Part E § 7.1.17).
ErrorCode BrEdrController::ChangeConnectionLinkKey(uint16_t connection_handle) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

// HCI Remote Name Request (Vol 4, Part E § 7.1.19).
ErrorCode BrEdrController::RemoteNameRequest(Address bd_addr, uint8_t /*page_scan_repetition_mode*/,
                                             uint16_t /*clock_offset*/) {
  // LMP features get requested with remote name requests.
  SendLinkLayerPacket(model::packets::ReadRemoteLmpFeaturesBuilder::Create(GetAddress(), bd_addr));
  SendLinkLayerPacket(model::packets::RemoteNameRequestBuilder::Create(GetAddress(), bd_addr));

  return ErrorCode::SUCCESS;
}

// HCI Read Remote Supported Features (Vol 4, Part E § 7.1.21).
ErrorCode BrEdrController::ReadRemoteSupportedFeatures(uint16_t connection_handle) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetAclConnection(connection_handle);
  SendLinkLayerPacket(model::packets::ReadRemoteSupportedFeaturesBuilder::Create(
          connection.own_address, connection.address));
  return ErrorCode::SUCCESS;
}

// HCI Read Remote Extended Features (Vol 4, Part E § 7.1.22).
ErrorCode BrEdrController::ReadRemoteExtendedFeatures(uint16_t connection_handle,
                                                      uint8_t page_number) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetAclConnection(connection_handle);
  SendLinkLayerPacket(model::packets::ReadRemoteExtendedFeaturesBuilder::Create(
          connection.own_address, connection.address, page_number));
  return ErrorCode::SUCCESS;
}

// HCI Read Remote Version Information (Vol 4, Part E § 7.1.23).
ErrorCode BrEdrController::ReadRemoteVersionInformation(uint16_t connection_handle) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetAclConnection(connection_handle);
  SendLinkLayerPacket(model::packets::ReadRemoteVersionInformationBuilder::Create(
          connection.own_address, connection.address));
  return ErrorCode::SUCCESS;
}

// HCI Read Clock Offset (Vol 4, Part E § 7.1.24).
ErrorCode BrEdrController::ReadClockOffset(uint16_t connection_handle) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto& connection = connections_.GetAclConnection(connection_handle);
  SendLinkLayerPacket(model::packets::ReadClockOffsetBuilder::Create(connection.own_address,
                                                                     connection.address));
  return ErrorCode::SUCCESS;
}

// HCI Add SCO Connection.
// Deprecated in the Core specification v1.2, removed in v4.2.
// Support is provided to satisfy PTS tester requirements.
ErrorCode BrEdrController::AddScoConnection(uint16_t connection_handle, uint16_t packet_type) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto const& connection = connections_.GetAclConnection(connection_handle);
  if (connections_.HasPendingScoConnection(connection.address)) {
    return ErrorCode::COMMAND_DISALLOWED;
  }

  INFO(id_, "Creating SCO connection with {}", connection.address);

  // Save connection parameters.
  ScoConnectionParameters connection_parameters = {
          8000,
          8000,
          0xffff,
          0x60 /* 16bit CVSD */,
          (uint8_t)bluetooth::hci::RetransmissionEffort::NO_RETRANSMISSION,
          (uint16_t)((uint16_t)((packet_type >> 5) & 0x7U) |
                     (uint16_t)bluetooth::hci::SynchronousPacketTypeBits::NO_2_EV3_ALLOWED |
                     (uint16_t)bluetooth::hci::SynchronousPacketTypeBits::NO_3_EV3_ALLOWED |
                     (uint16_t)bluetooth::hci::SynchronousPacketTypeBits::NO_2_EV5_ALLOWED |
                     (uint16_t)bluetooth::hci::SynchronousPacketTypeBits::NO_3_EV5_ALLOWED)};
  connections_.CreateScoConnection(connection.address, connection_parameters, SCO_STATE_PENDING,
                                   ScoDatapath::NORMAL, true);

  // Send SCO connection request to peer.
  SendLinkLayerPacket(model::packets::ScoConnectionRequestBuilder::Create(
          GetAddress(), connection.address, connection_parameters.transmit_bandwidth,
          connection_parameters.receive_bandwidth, connection_parameters.max_latency,
          connection_parameters.voice_setting, connection_parameters.retransmission_effort,
          connection_parameters.packet_type, class_of_device_));
  return ErrorCode::SUCCESS;
}

// HCI Setup Synchronous Connection (Vol 4, Part E § 7.1.26).
ErrorCode BrEdrController::SetupSynchronousConnection(uint16_t connection_handle,
                                                      uint32_t transmit_bandwidth,
                                                      uint32_t receive_bandwidth,
                                                      uint16_t max_latency, uint16_t voice_setting,
                                                      uint8_t retransmission_effort,
                                                      uint16_t packet_types, ScoDatapath datapath) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  auto const& connection = connections_.GetAclConnection(connection_handle);
  if (connections_.HasPendingScoConnection(connection.address)) {
    // This command may be used to modify an exising eSCO link.
    // Skip for now. TODO: should return an event
    // HCI_Synchronous_Connection_Changed on both sides.
    return ErrorCode::COMMAND_DISALLOWED;
  }

  INFO(id_, "Creating eSCO connection with {}", connection.address);

  // Save connection parameters.
  ScoConnectionParameters connection_parameters = {transmit_bandwidth,    receive_bandwidth,
                                                   max_latency,           voice_setting,
                                                   retransmission_effort, packet_types};
  connections_.CreateScoConnection(connection.address, connection_parameters, SCO_STATE_PENDING,
                                   datapath);

  // Send eSCO connection request to peer.
  SendLinkLayerPacket(model::packets::ScoConnectionRequestBuilder::Create(
          GetAddress(), connection.address, transmit_bandwidth, receive_bandwidth, max_latency,
          voice_setting, retransmission_effort, packet_types, class_of_device_));
  return ErrorCode::SUCCESS;
}

// HCI Accept Synchronous Connection (Vol 4, Part E § 7.1.26).
ErrorCode BrEdrController::AcceptSynchronousConnection(Address bd_addr, uint32_t transmit_bandwidth,
                                                       uint32_t receive_bandwidth,
                                                       uint16_t max_latency, uint16_t voice_setting,
                                                       uint8_t retransmission_effort,
                                                       uint16_t packet_types) {
  INFO(id_, "Accepting eSCO connection request from {}", bd_addr);

  if (!connections_.HasPendingScoConnection(bd_addr)) {
    INFO(id_, "No pending eSCO connection for {}", bd_addr);
    return ErrorCode::COMMAND_DISALLOWED;
  }

  ErrorCode status = ErrorCode::SUCCESS;
  uint16_t sco_handle = *connections_.GetScoConnectionHandle(bd_addr);
  ScoLinkParameters link_parameters = {};
  ScoConnectionParameters connection_parameters = {transmit_bandwidth,    receive_bandwidth,
                                                   max_latency,           voice_setting,
                                                   retransmission_effort, packet_types};

  if (!connections_.AcceptPendingScoConnection(bd_addr, connection_parameters, [this, bd_addr] {
        return BrEdrController::StartScoStream(bd_addr);
      })) {
    connections_.CancelPendingScoConnection(bd_addr);
    status = ErrorCode::STATUS_UNKNOWN;  // TODO: proper status code
    sco_handle = 0;
  } else {
    link_parameters = connections_.GetScoLinkParameters(bd_addr);
  }

  // Send eSCO connection response to peer.
  SendLinkLayerPacket(model::packets::ScoConnectionResponseBuilder::Create(
          GetAddress(), bd_addr, (uint8_t)status, link_parameters.transmission_interval,
          link_parameters.retransmission_window, link_parameters.rx_packet_length,
          link_parameters.tx_packet_length, link_parameters.air_mode, link_parameters.extended));

  // Schedule HCI Synchronous Connection Complete event.
  ScheduleTask(kNoDelayMs, [this, status, sco_handle, bd_addr, link_parameters]() {
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

// HCI Reject Synchronous Connection (Vol 4, Part E § 7.1.27).
ErrorCode BrEdrController::RejectSynchronousConnection(Address bd_addr, uint16_t reason) {
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
            ErrorCode(reason), 0, bd_addr, bluetooth::hci::ScoLinkType::ESCO, 0, 0, 0, 0,
            bluetooth::hci::ScoAirMode::TRANSPARENT));
  });

  return ErrorCode::SUCCESS;
}

// HCI Enhanced Setup Synchronous Connection (Vol 4, Part E § 7.1.45).
ErrorCode BrEdrController::EnhancedSetupSynchronousConnection(
        uint16_t connection_handle, uint32_t transmit_bandwidth, uint32_t receive_bandwidth,
        bluetooth::hci::ScoCodingFormat transmit_coding_format,
        bluetooth::hci::ScoCodingFormat receive_coding_format,
        uint16_t /*transmit_codec_frame_size*/, uint16_t /*receive_codec_frame_size*/,
        uint32_t input_bandwidth, uint32_t output_bandwidth,
        bluetooth::hci::ScoCodingFormat input_coding_format,
        bluetooth::hci::ScoCodingFormat output_coding_format, uint16_t /*input_coded_data_size*/,
        uint16_t /*output_coded_data_size*/,
        bluetooth::hci::ScoPcmDataFormat /*input_pcm_data_format*/,
        bluetooth::hci::ScoPcmDataFormat /*output_pcm_data_format*/,
        uint8_t /*input_pcm_sample_payload_msb_position*/,
        uint8_t /*output_pcm_sample_payload_msb_position*/,
        bluetooth::hci::ScoDataPath input_data_path, bluetooth::hci::ScoDataPath output_data_path,
        uint8_t /*input_transport_unit_size*/, uint8_t /*output_transport_unit_size*/,
        uint16_t max_latency, uint16_t packet_type,
        bluetooth::hci::RetransmissionEffort retransmission_effort) {
  // The Host shall set the Transmit_Coding_Format and Receive_Coding_Formats
  // to be equal.
  if (transmit_coding_format.coding_format_ != receive_coding_format.coding_format_ ||
      transmit_coding_format.company_id_ != receive_coding_format.company_id_ ||
      transmit_coding_format.vendor_specific_codec_id_ !=
              receive_coding_format.vendor_specific_codec_id_) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Transmit_Coding_Format "
         "({}) and Receive_Coding_Format ({}) as they are not equal",
         transmit_coding_format.ToString(), receive_coding_format.ToString());
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // The Host shall either set the Input_Bandwidth and Output_Bandwidth
  // to be equal, or shall set one of them to be zero and the other non-zero.
  if (input_bandwidth != output_bandwidth && input_bandwidth != 0 && output_bandwidth != 0) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Input_Bandwidth ({})"
         " and Output_Bandwidth ({}) as they are not equal and different from 0",
         input_bandwidth, output_bandwidth);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // The Host shall set the Input_Coding_Format and Output_Coding_Format
  // to be equal.
  if (input_coding_format.coding_format_ != output_coding_format.coding_format_ ||
      input_coding_format.company_id_ != output_coding_format.company_id_ ||
      input_coding_format.vendor_specific_codec_id_ !=
              output_coding_format.vendor_specific_codec_id_) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Input_Coding_Format ({})"
         " and Output_Coding_Format ({}) as they are not equal",
         input_coding_format.ToString(), output_coding_format.ToString());
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Root-Canal does not implement audio data transport paths other than the
  // default HCI transport - other transports will receive spoofed data
  ScoDatapath datapath = ScoDatapath::NORMAL;
  if (input_data_path != bluetooth::hci::ScoDataPath::HCI ||
      output_data_path != bluetooth::hci::ScoDataPath::HCI) {
    WARNING(id_,
            "EnhancedSetupSynchronousConnection: Input_Data_Path ({})"
            " and/or Output_Data_Path ({}) are not over HCI, so data will be "
            "spoofed",
            static_cast<unsigned>(input_data_path), static_cast<unsigned>(output_data_path));
    datapath = ScoDatapath::SPOOFED;
  }

  // Either both the Transmit_Coding_Format and Input_Coding_Format shall be
  // “transparent” or neither shall be. If both are “transparent”, the
  // Transmit_Bandwidth and the Input_Bandwidth shall be the same and the
  // Controller shall not modify the data sent to the remote device.
  if (transmit_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      input_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      transmit_bandwidth != input_bandwidth) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Transmit_Bandwidth ({})"
         " and Input_Bandwidth ({}) as they are not equal",
         transmit_bandwidth, input_bandwidth);
    INFO(id_,
         "EnhancedSetupSynchronousConnection: the Transmit_Bandwidth and "
         "Input_Bandwidth shall be equal when both Transmit_Coding_Format "
         "and Input_Coding_Format are 'transparent'");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  if ((transmit_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT) !=
      (input_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT)) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Transmit_Coding_Format "
         "({}) and Input_Coding_Format ({}) as they are incompatible",
         transmit_coding_format.ToString(), input_coding_format.ToString());
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Either both the Receive_Coding_Format and Output_Coding_Format shall
  // be “transparent” or neither shall be. If both are “transparent”, the
  // Receive_Bandwidth and the Output_Bandwidth shall be the same and the
  // Controller shall not modify the data sent to the Host.
  if (receive_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      output_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      receive_bandwidth != output_bandwidth) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Receive_Bandwidth ({})"
         " and Output_Bandwidth ({}) as they are not equal",
         receive_bandwidth, output_bandwidth);
    INFO(id_,
         "EnhancedSetupSynchronousConnection: the Receive_Bandwidth and "
         "Output_Bandwidth shall be equal when both Receive_Coding_Format "
         "and Output_Coding_Format are 'transparent'");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  if ((receive_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT) !=
      (output_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT)) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Receive_Coding_Format "
         "({}) and Output_Coding_Format ({}) as they are incompatible",
         receive_coding_format.ToString(), output_coding_format.ToString());
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  return SetupSynchronousConnection(
          connection_handle, transmit_bandwidth, receive_bandwidth, max_latency, GetVoiceSetting(),
          static_cast<uint8_t>(retransmission_effort), packet_type, datapath);
}

// HCI Enhanced Accept Synchronous Connection (Vol 4, Part E § 7.1.46).
ErrorCode BrEdrController::EnhancedAcceptSynchronousConnection(
        Address bd_addr, uint32_t transmit_bandwidth, uint32_t receive_bandwidth,
        bluetooth::hci::ScoCodingFormat transmit_coding_format,
        bluetooth::hci::ScoCodingFormat receive_coding_format,
        uint16_t /*transmit_codec_frame_size*/, uint16_t /*receive_codec_frame_size*/,
        uint32_t input_bandwidth, uint32_t output_bandwidth,
        bluetooth::hci::ScoCodingFormat input_coding_format,
        bluetooth::hci::ScoCodingFormat output_coding_format, uint16_t /*input_coded_data_size*/,
        uint16_t /*output_coded_data_size*/,
        bluetooth::hci::ScoPcmDataFormat /*input_pcm_data_format*/,
        bluetooth::hci::ScoPcmDataFormat /*output_pcm_data_format*/,
        uint8_t /*input_pcm_sample_payload_msb_position*/,
        uint8_t /*output_pcm_sample_payload_msb_position*/,
        bluetooth::hci::ScoDataPath input_data_path, bluetooth::hci::ScoDataPath output_data_path,
        uint8_t /*input_transport_unit_size*/, uint8_t /*output_transport_unit_size*/,
        uint16_t max_latency, uint16_t packet_type,
        bluetooth::hci::RetransmissionEffort retransmission_effort) {
  // The Host shall set the Transmit_Coding_Format and Receive_Coding_Formats
  // to be equal.
  if (transmit_coding_format.coding_format_ != receive_coding_format.coding_format_ ||
      transmit_coding_format.company_id_ != receive_coding_format.company_id_ ||
      transmit_coding_format.vendor_specific_codec_id_ !=
              receive_coding_format.vendor_specific_codec_id_) {
    INFO(id_,
         "EnhancedAcceptSynchronousConnection: rejected Transmit_Coding_Format "
         "({})"
         " and Receive_Coding_Format ({}) as they are not equal",
         transmit_coding_format.ToString(), receive_coding_format.ToString());
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // The Host shall either set the Input_Bandwidth and Output_Bandwidth
  // to be equal, or shall set one of them to be zero and the other non-zero.
  if (input_bandwidth != output_bandwidth && input_bandwidth != 0 && output_bandwidth != 0) {
    INFO(id_,
         "EnhancedAcceptSynchronousConnection: rejected Input_Bandwidth ({})"
         " and Output_Bandwidth ({}) as they are not equal and different from 0",
         input_bandwidth, output_bandwidth);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // The Host shall set the Input_Coding_Format and Output_Coding_Format
  // to be equal.
  if (input_coding_format.coding_format_ != output_coding_format.coding_format_ ||
      input_coding_format.company_id_ != output_coding_format.company_id_ ||
      input_coding_format.vendor_specific_codec_id_ !=
              output_coding_format.vendor_specific_codec_id_) {
    INFO(id_,
         "EnhancedAcceptSynchronousConnection: rejected Input_Coding_Format ({})"
         " and Output_Coding_Format ({}) as they are not equal",
         input_coding_format.ToString(), output_coding_format.ToString());
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Root-Canal does not implement audio data transport paths other than the
  // default HCI transport.
  if (input_data_path != bluetooth::hci::ScoDataPath::HCI ||
      output_data_path != bluetooth::hci::ScoDataPath::HCI) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: Input_Data_Path ({})"
         " and/or Output_Data_Path ({}) are not over HCI, so data will be "
         "spoofed",
         static_cast<unsigned>(input_data_path), static_cast<unsigned>(output_data_path));
  }

  // Either both the Transmit_Coding_Format and Input_Coding_Format shall be
  // “transparent” or neither shall be. If both are “transparent”, the
  // Transmit_Bandwidth and the Input_Bandwidth shall be the same and the
  // Controller shall not modify the data sent to the remote device.
  if (transmit_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      input_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      transmit_bandwidth != input_bandwidth) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Transmit_Bandwidth ({})"
         " and Input_Bandwidth ({}) as they are not equal",
         transmit_bandwidth, input_bandwidth);
    INFO(id_,
         "EnhancedSetupSynchronousConnection: the Transmit_Bandwidth and "
         "Input_Bandwidth shall be equal when both Transmit_Coding_Format "
         "and Input_Coding_Format are 'transparent'");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  if ((transmit_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT) !=
      (input_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT)) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Transmit_Coding_Format "
         "({}) and Input_Coding_Format ({}) as they are incompatible",
         transmit_coding_format.ToString(), input_coding_format.ToString());
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Either both the Receive_Coding_Format and Output_Coding_Format shall
  // be “transparent” or neither shall be. If both are “transparent”, the
  // Receive_Bandwidth and the Output_Bandwidth shall be the same and the
  // Controller shall not modify the data sent to the Host.
  if (receive_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      output_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      receive_bandwidth != output_bandwidth) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Receive_Bandwidth ({})"
         " and Output_Bandwidth ({}) as they are not equal",
         receive_bandwidth, output_bandwidth);
    INFO(id_,
         "EnhancedSetupSynchronousConnection: the Receive_Bandwidth and "
         "Output_Bandwidth shall be equal when both Receive_Coding_Format "
         "and Output_Coding_Format are 'transparent'");
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  if ((receive_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT) !=
      (output_coding_format.coding_format_ == bluetooth::hci::ScoCodingFormatValues::TRANSPARENT)) {
    INFO(id_,
         "EnhancedSetupSynchronousConnection: rejected Receive_Coding_Format "
         "({}) and Output_Coding_Format ({}) as they are incompatible",
         receive_coding_format.ToString(), output_coding_format.ToString());
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  return AcceptSynchronousConnection(bd_addr, transmit_bandwidth, receive_bandwidth, max_latency,
                                     GetVoiceSetting(), static_cast<uint8_t>(retransmission_effort),
                                     packet_type);
}

// =============================================================================
//  Link Policy commands (Vol 4, Part E § 7.2)
// =============================================================================

// HCI Hold Mode command (Vol 4, Part E § 7.2.1).
ErrorCode BrEdrController::HoldMode(uint16_t connection_handle, uint16_t hold_mode_max_interval,
                                    uint16_t hold_mode_min_interval) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (hold_mode_max_interval < hold_mode_min_interval) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

// HCI Sniff Mode command (Vol 4, Part E § 7.2.2).
ErrorCode BrEdrController::SniffMode(uint16_t connection_handle, uint16_t sniff_max_interval,
                                     uint16_t sniff_min_interval, uint16_t sniff_attempt,
                                     uint16_t sniff_timeout) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (sniff_max_interval < sniff_min_interval || sniff_attempt < 0x0001 || sniff_attempt > 0x7FFF ||
      sniff_timeout > 0x7FFF) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

// HCI Exit Sniff Mode command (Vol 4, Part E § 7.2.3).
ErrorCode BrEdrController::ExitSniffMode(uint16_t connection_handle) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

// HCI QoS Setup command (Vol 4, Part E § 7.2.6).
ErrorCode BrEdrController::QosSetup(uint16_t connection_handle, uint8_t service_type,
                                    uint32_t token_rate, uint32_t peak_bandwidth, uint32_t latency,
                                    uint32_t delay_variation) {
  // The Connection_Handle shall be a Connection_Handle for an ACL connection.
  if (!connections_.HasAclHandle(connection_handle)) {
    INFO(id_, "unknown connection handle {}", connection_handle);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // This field indicates the level of service required. The list below defines the different
  // services available. The default value is ‘Best effort’.
  //  - 0x00 No traffic
  //  - 0x01 Best effort (Default)
  //  - 0x02 Guaranteed
  if (service_type > 0x02) {
    INFO(id_, "invalid service_type 0x{:02x}", service_type);
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // When the Link Manager has completed the LMP messages to establish the requested QoS
  // parameters, the BR/EDR Controller shall send an HCI_QoS_Setup_Complete event to the Host, and
  // the event may also be generated on the remote side if there was LMP negotiation.
  if (IsEventUnmasked(EventCode::QOS_SETUP_COMPLETE)) {
    uint32_t selected_token_rate =
            token_rate == 0 || token_rate == 0xffffffff ? 100000 /* Ko/s */ : token_rate;
    uint32_t selected_peak_bandwidth = peak_bandwidth == 0 || peak_bandwidth == 0xffffffff
                                               ? 200000 /* Ko/s */
                                               : peak_bandwidth;
    uint32_t selected_latency = latency == 0 || latency == 0xffffffff ? 50000 /* us */ : latency;
    uint32_t selected_delay_variation = delay_variation == 0 || delay_variation == 0xffffffff
                                                ? 10000 /* us */
                                                : delay_variation;
    ScheduleTask(kNoDelayMs, [=, this]() {
      send_event_(bluetooth::hci::QosSetupCompleteBuilder::Create(
              ErrorCode::SUCCESS, connection_handle, bluetooth::hci::ServiceType(service_type),
              selected_token_rate /* Token_Rate */, selected_peak_bandwidth /* Peak_Bandwidth */,
              selected_latency /* Latency */, selected_delay_variation /* Delay_Variation */));
    });
  }

  // TODO: Implement LMP negotiation with peer.
  // Right now we assume no LMP negotiation takes place.
  return ErrorCode::SUCCESS;
}

// HCI Role Discovery command (Vol 4, Part E § 7.2.7).
ErrorCode BrEdrController::RoleDiscovery(uint16_t connection_handle, bluetooth::hci::Role* role) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  *role = connections_.GetAclConnection(connection_handle).GetRole();
  return ErrorCode::SUCCESS;
}

// HCI Switch Role command (Vol 4, Part E § 7.2.8).
ErrorCode BrEdrController::SwitchRole(Address bd_addr, bluetooth::hci::Role role) {
  // The BD_ADDR command parameter indicates for which connection
  // the role switch is to be performed and shall specify a BR/EDR Controller
  // for which a connection already exists.
  auto connection_handle = connections_.GetAclConnectionHandle(bd_addr);
  if (!connection_handle.has_value()) {
    INFO(id_, "unknown connection address {}", bd_addr);
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  AclConnection& connection = connections_.GetAclConnection(*connection_handle);

  // If there is an (e)SCO connection between the local device and the device
  // identified by the BD_ADDR parameter, an attempt to perform a role switch
  // shall be rejected by the local device.
  if (connections_.GetScoConnectionHandle(bd_addr).has_value()) {
    INFO(id_,
         "role switch rejected because an Sco link is opened with"
         " the target device");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  // If the connection between the local device and the device identified by the
  // BD_ADDR parameter is placed in Sniff mode, an attempt to perform a role
  // switch shall be rejected by the local device.
  if (connection.GetMode() == AclConnectionState::kSniffMode) {
    INFO(id_, "role switch rejected because the acl connection is in sniff mode");
    return ErrorCode::COMMAND_DISALLOWED;
  }

  if (role != connection.GetRole()) {
    SendLinkLayerPacket(model::packets::RoleSwitchRequestBuilder::Create(GetAddress(), bd_addr));
  } else if (IsEventUnmasked(EventCode::ROLE_CHANGE)) {
    // Note: the status is Success only if the role change procedure was
    // actually performed, otherwise the status is >0.
    ScheduleTask(kNoDelayMs, [this, bd_addr, role]() {
      send_event_(bluetooth::hci::RoleChangeBuilder::Create(ErrorCode::ROLE_SWITCH_FAILED, bd_addr,
                                                            role));
    });
  }

  return ErrorCode::SUCCESS;
}

// HCI Read Link Policy Settings command (Vol 4, Part E § 7.2.9.
ErrorCode BrEdrController::ReadLinkPolicySettings(uint16_t connection_handle,
                                                  uint16_t* link_policy_settings) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  *link_policy_settings = connections_.GetAclConnection(connection_handle).GetLinkPolicySettings();
  return ErrorCode::SUCCESS;
}

// HCI Write Link Policy Settings command (Vol 4, Part E § 7.2.10).
ErrorCode BrEdrController::WriteLinkPolicySettings(uint16_t connection_handle,
                                                   uint16_t link_policy_settings) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (link_policy_settings > 7 /* Sniff + Hold + Role switch */) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  connections_.GetAclConnection(connection_handle).SetLinkPolicySettings(link_policy_settings);
  return ErrorCode::SUCCESS;
}

// HCI Read Default Link Policy Settings command (Vol 4, Part E § 7.2.11).
ErrorCode BrEdrController::ReadDefaultLinkPolicySettings(
        uint16_t* default_link_policy_settings) const {
  *default_link_policy_settings = default_link_policy_settings_;
  return ErrorCode::SUCCESS;
}

// HCI Write Default Link Policy Settings command (Vol 4, Part E § 7.2.12).
ErrorCode BrEdrController::WriteDefaultLinkPolicySettings(uint16_t default_link_policy_settings) {
  if (default_link_policy_settings > 7 /* Sniff + Hold + Role switch */) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  default_link_policy_settings_ = default_link_policy_settings;
  return ErrorCode::SUCCESS;
}

// HCI Flow Specification command (Vol 4, Part E § 7.2.13).
ErrorCode BrEdrController::FlowSpecification(uint16_t connection_handle, uint8_t flow_direction,
                                             uint8_t service_type, uint32_t /* token_rate */,
                                             uint32_t /* token_bucket_size */,
                                             uint32_t /* peak_bandwidth */,
                                             uint32_t /* access_latency */) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (flow_direction > 0x01 || service_type > 0x02) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

// HCI Sniff Subrating command (Vol 4, Part E § 7.2.14).
ErrorCode BrEdrController::SniffSubrating(uint16_t connection_handle, uint16_t max_latency,
                                          uint16_t min_remote_timeout, uint16_t min_local_timeout) {
  if (!connections_.HasAclHandle(connection_handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  if (max_latency < 0x2 || max_latency > 0xfffe || min_remote_timeout > 0xfffe ||
      min_local_timeout > 0xfffe) {
    return ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // TODO: generate HCI Sniff Subrating event to emulate sniff subrating negotiation.
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  Controller & Baseband commands (Vol 4, Part E § 7.3)
// =============================================================================

// HCI Reset command (Vol 4, Part E § 7.3.2).
void BrEdrController::Reset() {
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
  page_scan_repetition_mode_ = PageScanRepetitionMode::R0;
  oob_id_ = 1;
  key_id_ = 1;
  inquiry_mode_ = InquiryType::STANDARD;

  bluetooth::hci::Lap general_iac;
  general_iac.lap_ = 0x33;  // 0x9E8B33
  current_iac_lap_list_.clear();
  current_iac_lap_list_.emplace_back(general_iac);

  page_ = {};
  page_scan_ = {};
  inquiry_ = {};

  lm_.reset(link_manager_create(controller_ops_));
}

// HCI Write Local Name command (Vol 4, Part E § 7.3.11).
void BrEdrController::WriteLocalName(std::array<uint8_t, 248> const& local_name) {
  local_name_ = local_name;
}

// HCI Read Scan Enable command (Vol 4, Part E § 7.3.17).
void BrEdrController::ReadScanEnable(bluetooth::hci::ScanEnable* scan_enable) {
  *scan_enable = inquiry_scan_enable_ && page_scan_enable_
                         ? bluetooth::hci::ScanEnable::INQUIRY_AND_PAGE_SCAN
                 : inquiry_scan_enable_ ? bluetooth::hci::ScanEnable::INQUIRY_SCAN_ONLY
                 : page_scan_enable_    ? bluetooth::hci::ScanEnable::PAGE_SCAN_ONLY
                                        : bluetooth::hci::ScanEnable::NO_SCANS;
}

// HCI Write Scan Enable command (Vol 4, Part E § 7.3.18).
void BrEdrController::WriteScanEnable(bluetooth::hci::ScanEnable scan_enable) {
  inquiry_scan_enable_ = scan_enable == bluetooth::hci::ScanEnable::INQUIRY_AND_PAGE_SCAN ||
                         scan_enable == bluetooth::hci::ScanEnable::INQUIRY_SCAN_ONLY;
  page_scan_enable_ = scan_enable == bluetooth::hci::ScanEnable::INQUIRY_AND_PAGE_SCAN ||
                      scan_enable == bluetooth::hci::ScanEnable::PAGE_SCAN_ONLY;
}

// HCI Write Extended Inquiry Response command (Vol 4, Part E § 7.3.56).
void BrEdrController::WriteExtendedInquiryResponse(
        bool /*fec_required*/, std::array<uint8_t, 240> const& extended_inquiry_response) {
  extended_inquiry_response_ = extended_inquiry_response;
}

// HCI Read Local OOB Data command (Vol 4, Part E § 7.3.60).
void BrEdrController::ReadLocalOobData(std::array<uint8_t, 16>* c, std::array<uint8_t, 16>* r) {
  *c = std::array<uint8_t, 16>({'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '0', '0', '0', '0', '0',
                                '0', static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
                                static_cast<uint8_t>(oob_id_ % 0x100)});

  *r = std::array<uint8_t, 16>({'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '0', '0', '0', '0', '0',
                                '0', static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
                                static_cast<uint8_t>(oob_id_ % 0x100)});
  oob_id_ += 1;
}

// HCI Read Local OOB Extended Data command (Vol 4, Part E § 7.3.95).
void BrEdrController::ReadLocalOobExtendedData(std::array<uint8_t, 16>* c_192,
                                               std::array<uint8_t, 16>* r_192,
                                               std::array<uint8_t, 16>* c_256,
                                               std::array<uint8_t, 16>* r_256) {
  *c_192 = std::array<uint8_t, 16>({'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '1', '9', '2', '0', '0',
                                    '0', static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
                                    static_cast<uint8_t>(oob_id_ % 0x100)});

  *r_192 = std::array<uint8_t, 16>({'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '1', '9', '2', '0', '0',
                                    '0', static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
                                    static_cast<uint8_t>(oob_id_ % 0x100)});

  *c_256 = std::array<uint8_t, 16>({'c', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '2', '5', '6', '0', '0',
                                    '0', static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
                                    static_cast<uint8_t>(oob_id_ % 0x100)});

  *r_256 = std::array<uint8_t, 16>({'r', ' ', 'a', 'r', 'r', 'a', 'y', ' ', '2', '5', '6', '0', '0',
                                    '0', static_cast<uint8_t>((oob_id_ % 0x10000) >> 8),
                                    static_cast<uint8_t>(oob_id_ % 0x100)});
  oob_id_ += 1;
}

// =============================================================================
//  Status parameters (Vol 4, Part E § 7.5)
// =============================================================================

// HCI Read Rssi command (Vol 4, Part E § 7.5.4).
ErrorCode BrEdrController::ReadRssi(uint16_t connection_handle, int8_t* rssi) {
  if (!connections_.HasAclHandle(connection_handle)) {
    // Not documented: If the connection handle is not found, the Controller
    // shall return the error code Unknown Connection Identifier (0x02).
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  *rssi = connections_.GetAclConnection(connection_handle).GetRssi();
  return ErrorCode::SUCCESS;
}

// HCI Read Encryption Key Size command (Vol 4, Part E § 7.5.7).
ErrorCode BrEdrController::ReadEncryptionKeySize(uint16_t connection_handle, uint8_t* key_size) {
  if (!connections_.HasAclHandle(connection_handle)) {
    // Not documented: If the connection handle is not found, the Controller
    // shall return the error code Unknown Connection Identifier (0x02).
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: The Encryption Key Size should be specific to an ACL connection.
  *key_size = 16;
  return ErrorCode::SUCCESS;
}

// =============================================================================
//  BR/EDR Commands
// =============================================================================

void BrEdrController::SetSecureSimplePairingSupport(bool enable) {
  uint64_t bit = 0x1;
  secure_simple_pairing_host_support_ = enable;
  if (enable) {
    host_supported_features_ |= bit;
  } else {
    host_supported_features_ &= ~bit;
  }
}

void BrEdrController::SetLeHostSupport(bool enable) {
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

void BrEdrController::SetSecureConnectionsSupport(bool enable) {
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

void BrEdrController::SetLocalName(std::vector<uint8_t> const& local_name) {
  ASSERT(local_name.size() <= local_name_.size());
  local_name_.fill(0);
  std::copy(local_name.begin(), local_name.end(), local_name_.begin());
}

void BrEdrController::SetExtendedInquiryResponse(
        std::vector<uint8_t> const& extended_inquiry_response) {
  ASSERT(extended_inquiry_response.size() <= extended_inquiry_response_.size());
  extended_inquiry_response_.fill(0);
  std::copy(extended_inquiry_response.begin(), extended_inquiry_response.end(),
            extended_inquiry_response_.begin());
}

BrEdrController::BrEdrController(const Address& address, const ControllerProperties& properties,
                                 uint32_t id)
    : id_(id), address_(address), properties_(properties), lm_(nullptr, link_manager_destroy) {
  controller_ops_ = {
          .user_pointer = this,
          .get_handle =
                  [](void* user, const uint8_t (*address)[6]) {
                    auto controller = static_cast<BrEdrController*>(user);

                    // Returns the connection handle but only for established
                    // BR-EDR connections.
                    return controller->connections_.GetAclConnectionHandle(Address(*address))
                            .value_or(-1);
                  },

          .get_address =
                  [](void* user, uint16_t handle, uint8_t (*result)[6]) {
                    auto controller = static_cast<BrEdrController*>(user);
                    Address address = {};

                    if (controller->connections_.HasAclHandle(handle)) {
                      address = controller->connections_.GetAclConnection(handle).address;
                    } else if (controller->connections_.HasLeAclHandle(handle)) {
                      address = controller->connections_.GetLeAclConnection(handle)
                                        .address.GetAddress();
                    }

                    std::copy(address.data(), address.data() + 6,
                              reinterpret_cast<uint8_t*>(result));
                  },

          .get_extended_features =
                  [](void* user, uint8_t features_page) {
                    auto controller = static_cast<BrEdrController*>(user);
                    return controller->GetLmpFeatures(features_page);
                  },

          .send_hci_event =
                  [](void* user, const uint8_t* data, uintptr_t len) {
                    auto controller = static_cast<BrEdrController*>(user);

                    auto event_code = static_cast<EventCode>(data[0]);
                    controller->send_event_(bluetooth::hci::EventBuilder::Create(
                            event_code, std::vector(data + 2, data + len)));
                  },

          .send_lmp_packet =
                  [](void* user, const uint8_t (*to)[6], const uint8_t* data, uintptr_t len) {
                    auto controller = static_cast<BrEdrController*>(user);

                    Address source = controller->GetAddress();
                    Address dest(*to);

                    controller->SendLinkLayerPacket(model::packets::LmpBuilder::Create(
                            source, dest, std::vector(data, data + len)));
                  }};

  lm_.reset(link_manager_create(controller_ops_));
}

BrEdrController::~BrEdrController() {}

void BrEdrController::SendLinkLayerPacket(
        std::unique_ptr<model::packets::LinkLayerPacketBuilder> packet, int8_t tx_power) {
  std::shared_ptr<model::packets::LinkLayerPacketBuilder> shared_packet = std::move(packet);
  ScheduleTask(kNoDelayMs, [this, shared_packet, tx_power]() {
    send_to_remote_(shared_packet, Phy::Type::BR_EDR, tx_power);
  });
}

ErrorCode BrEdrController::SendScoToRemote(bluetooth::hci::ScoView sco_packet) {
  uint16_t handle = sco_packet.GetHandle();
  if (!connections_.HasScoHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }

  // TODO: SCO flow control
  Address source = GetAddress();
  Address destination = connections_.GetScoAddress(handle);

  auto sco_data = sco_packet.GetData();
  std::vector<uint8_t> sco_data_bytes(sco_data.begin(), sco_data.end());

  SendLinkLayerPacket(
          model::packets::ScoBuilder::Create(source, destination, std::move(sco_data_bytes)));
  return ErrorCode::SUCCESS;
}

void BrEdrController::IncomingPacket(model::packets::LinkLayerPacketView incoming, int8_t rssi) {
  ASSERT(incoming.IsValid());
  auto destination_address = incoming.GetDestinationAddress();
  auto source_address = incoming.GetSourceAddress();

  // Accept broadcasts to address 00:00:00:00:00:00 but otherwise ignore the incoming
  // packet if the destination address is not the local public address.
  if (destination_address != Address::kEmpty && destination_address != address_) {
    DEBUG(id_, "[LM] {} | Dropping {} packet not addressed to me {}->{}", address_,
          PacketTypeText(incoming.GetType()), source_address, destination_address);
    return;
  }

  // Update link timeout for established ACL connections.
  auto connection_handle = connections_.GetAclConnectionHandle(source_address);
  if (connection_handle.has_value()) {
    connections_.GetAclConnection(*connection_handle).ResetLinkTimer();
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
    case model::packets::PacketType::LMP:
      IncomingLmpPacket(incoming);
      break;
    case model::packets::PacketType::INQUIRY:
      IncomingInquiryPacket(incoming, rssi);
      break;
    case model::packets::PacketType::INQUIRY_RESPONSE:
      IncomingInquiryResponsePacket(incoming);
      break;
    case model::packets::PacketType::PAGE:
      IncomingPagePacket(incoming);
      break;
    case model::packets::PacketType::PAGE_RESPONSE:
      IncomingPageResponsePacket(incoming);
      break;
    case model::packets::PacketType::PAGE_REJECT:
      IncomingPageRejectPacket(incoming);
      break;
    case model::packets::PacketType::REMOTE_NAME_REQUEST:
      IncomingRemoteNameRequest(incoming);
      break;
    case model::packets::PacketType::REMOTE_NAME_REQUEST_RESPONSE:
      IncomingRemoteNameRequestResponse(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_SUPPORTED_FEATURES:
      IncomingReadRemoteSupportedFeatures(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_SUPPORTED_FEATURES_RESPONSE:
      IncomingReadRemoteSupportedFeaturesResponse(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_LMP_FEATURES:
      IncomingReadRemoteLmpFeatures(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_LMP_FEATURES_RESPONSE:
      IncomingReadRemoteLmpFeaturesResponse(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_EXTENDED_FEATURES:
      IncomingReadRemoteExtendedFeatures(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_EXTENDED_FEATURES_RESPONSE:
      IncomingReadRemoteExtendedFeaturesResponse(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_VERSION_INFORMATION:
      IncomingReadRemoteVersion(incoming);
      break;
    case model::packets::PacketType::READ_REMOTE_VERSION_INFORMATION_RESPONSE:
      IncomingReadRemoteVersionResponse(incoming);
      break;
    case model::packets::PacketType::READ_CLOCK_OFFSET:
      IncomingReadClockOffset(incoming);
      break;
    case model::packets::PacketType::READ_CLOCK_OFFSET_RESPONSE:
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
    default:
      WARNING(id_, "Dropping unhandled packet of type {}",
              model::packets::PacketTypeText(incoming.GetType()));
  }
}

void BrEdrController::IncomingAclPacket(model::packets::LinkLayerPacketView incoming, int8_t rssi) {
  auto acl = model::packets::AclView::Create(incoming);
  ASSERT(acl.IsValid());

  auto acl_data = acl.GetData();
  auto packet_boundary_flag = bluetooth::hci::PacketBoundaryFlag(acl.GetPacketBoundaryFlag());
  auto broadcast_flag = bluetooth::hci::BroadcastFlag(acl.GetBroadcastFlag());

  if (packet_boundary_flag ==
      bluetooth::hci::PacketBoundaryFlag::FIRST_NON_AUTOMATICALLY_FLUSHABLE) {
    packet_boundary_flag = bluetooth::hci::PacketBoundaryFlag::FIRST_AUTOMATICALLY_FLUSHABLE;
  }

  INFO(id_, "ACL Packet [{}] {} -> {}", acl_data.size(), incoming.GetSourceAddress(),
       incoming.GetDestinationAddress());

  auto connection_handle = connections_.GetAclConnectionHandle(incoming.GetSourceAddress());
  if (!connection_handle.has_value()) {
    INFO(id_, "Dropping packet since connection does not exist");
    return;
  }

  // Update the RSSI for the local ACL connection.
  auto& connection = connections_.GetAclConnection(*connection_handle);
  connection.SetRssi(rssi);

  send_acl_(bluetooth::hci::AclBuilder::Create(
          *connection_handle, packet_boundary_flag, broadcast_flag,
          std::vector<uint8_t>(acl_data.begin(), acl_data.end())));
}

void BrEdrController::IncomingScoPacket(model::packets::LinkLayerPacketView incoming) {
  Address source = incoming.GetSourceAddress();
  auto sco_handle = connections_.GetScoConnectionHandle(source);
  if (!sco_handle.has_value()) {
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
          *sco_handle, bluetooth::hci::PacketStatusFlag::CORRECTLY_RECEIVED, sco_data_bytes));
}

void BrEdrController::IncomingRemoteNameRequest(model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::RemoteNameRequestView::Create(incoming);
  ASSERT(view.IsValid());

  SendLinkLayerPacket(model::packets::RemoteNameRequestResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(), local_name_));
}

void BrEdrController::IncomingRemoteNameRequestResponse(
        model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::RemoteNameRequestResponseView::Create(incoming);
  ASSERT(view.IsValid());

  if (IsEventUnmasked(EventCode::REMOTE_NAME_REQUEST_COMPLETE)) {
    send_event_(bluetooth::hci::RemoteNameRequestCompleteBuilder::Create(
            ErrorCode::SUCCESS, incoming.GetSourceAddress(), view.GetName()));
  }
}

void BrEdrController::IncomingReadRemoteLmpFeatures(model::packets::LinkLayerPacketView incoming) {
  SendLinkLayerPacket(model::packets::ReadRemoteLmpFeaturesResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(), host_supported_features_));
}

void BrEdrController::IncomingReadRemoteLmpFeaturesResponse(
        model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadRemoteLmpFeaturesResponseView::Create(incoming);
  ASSERT(view.IsValid());
  if (IsEventUnmasked(EventCode::REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION)) {
    send_event_(bluetooth::hci::RemoteHostSupportedFeaturesNotificationBuilder::Create(
            incoming.GetSourceAddress(), view.GetFeatures()));
  }
}

void BrEdrController::IncomingReadRemoteSupportedFeatures(
        model::packets::LinkLayerPacketView incoming) {
  SendLinkLayerPacket(model::packets::ReadRemoteSupportedFeaturesResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
          properties_.lmp_features[0]));
}

void BrEdrController::IncomingReadRemoteSupportedFeaturesResponse(
        model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadRemoteSupportedFeaturesResponseView::Create(incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();
  auto handle = connections_.GetAclConnectionHandle(source);
  if (!handle.has_value()) {
    INFO(id_, "Discarding response from a disconnected device {}", source);
    return;
  }
  if (IsEventUnmasked(EventCode::READ_REMOTE_SUPPORTED_FEATURES_COMPLETE)) {
    send_event_(bluetooth::hci::ReadRemoteSupportedFeaturesCompleteBuilder::Create(
            ErrorCode::SUCCESS, *handle, view.GetFeatures()));
  }
}

void BrEdrController::IncomingReadRemoteExtendedFeatures(
        model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadRemoteExtendedFeaturesView::Create(incoming);
  ASSERT(view.IsValid());
  uint8_t page_number = view.GetPageNumber();
  uint8_t error_code = static_cast<uint8_t>(ErrorCode::SUCCESS);
  if (page_number >= properties_.lmp_features.size()) {
    error_code = static_cast<uint8_t>(ErrorCode::INVALID_LMP_OR_LL_PARAMETERS);
  }
  SendLinkLayerPacket(model::packets::ReadRemoteExtendedFeaturesResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(), error_code, page_number,
          GetMaxLmpFeaturesPageNumber(), GetLmpFeatures(page_number)));
}

void BrEdrController::IncomingReadRemoteExtendedFeaturesResponse(
        model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadRemoteExtendedFeaturesResponseView::Create(incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();
  auto handle = connections_.GetAclConnectionHandle(source);
  if (!handle.has_value()) {
    INFO(id_, "Discarding response from a disconnected device {}", source);
    return;
  }
  if (IsEventUnmasked(EventCode::READ_REMOTE_EXTENDED_FEATURES_COMPLETE)) {
    send_event_(bluetooth::hci::ReadRemoteExtendedFeaturesCompleteBuilder::Create(
            static_cast<ErrorCode>(view.GetStatus()), *handle, view.GetPageNumber(),
            view.GetMaxPageNumber(), view.GetFeatures()));
  }
}

void BrEdrController::IncomingReadRemoteVersion(model::packets::LinkLayerPacketView incoming) {
  SendLinkLayerPacket(model::packets::ReadRemoteVersionInformationResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(),
          static_cast<uint8_t>(properties_.lmp_version),
          static_cast<uint16_t>(properties_.lmp_subversion), properties_.company_identifier));
}

void BrEdrController::IncomingReadRemoteVersionResponse(
        model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadRemoteVersionInformationResponseView::Create(incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();

  auto handle = connections_.GetAclConnectionHandle(source);

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

void BrEdrController::IncomingReadClockOffset(model::packets::LinkLayerPacketView incoming) {
  SendLinkLayerPacket(model::packets::ReadClockOffsetResponseBuilder::Create(
          incoming.GetDestinationAddress(), incoming.GetSourceAddress(), GetClockOffset()));
}

void BrEdrController::IncomingReadClockOffsetResponse(
        model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::ReadClockOffsetResponseView::Create(incoming);
  ASSERT(view.IsValid());
  Address source = incoming.GetSourceAddress();
  auto handle = connections_.GetAclConnectionHandle(source);
  if (!handle.has_value()) {
    INFO(id_, "Discarding response from a disconnected device {}", source);
    return;
  }
  if (IsEventUnmasked(EventCode::READ_CLOCK_OFFSET_COMPLETE)) {
    send_event_(bluetooth::hci::ReadClockOffsetCompleteBuilder::Create(ErrorCode::SUCCESS, *handle,
                                                                       view.GetOffset()));
  }
}

void BrEdrController::IncomingDisconnectPacket(model::packets::LinkLayerPacketView incoming) {
  INFO(id_, "Disconnect Packet");

  auto disconnect = model::packets::DisconnectView::Create(incoming);
  ASSERT(disconnect.IsValid());

  Address peer = incoming.GetSourceAddress();
  auto handle = connections_.GetAclConnectionHandle(peer);
  if (!handle.has_value()) {
    INFO(id_, "Discarding disconnect from a disconnected device {}", peer);
    return;
  }

  ASSERT_LOG(connections_.Disconnect(*handle,
                                     [this](TaskId task_id) { CancelScheduledTask(task_id); }),
             "GetHandle() returned invalid handle 0x{:x}", *handle);

  uint8_t reason = disconnect.GetReason();
  ASSERT(link_manager_remove_link(lm_.get(), reinterpret_cast<uint8_t (*)[6]>(peer.data())));
  SendDisconnectionCompleteEvent(*handle, ErrorCode(reason));
}

void BrEdrController::IncomingInquiryPacket(model::packets::LinkLayerPacketView incoming,
                                            uint8_t rssi) {
  if (!inquiry_scan_enable_) {
    return;
  }

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
              GetAddress(), peer, static_cast<uint8_t>(page_scan_repetition_mode_),
              class_of_device_, GetClockOffset()));
    } break;
    case (model::packets::InquiryType::RSSI): {
      SendLinkLayerPacket(model::packets::InquiryResponseWithRssiBuilder::Create(
              GetAddress(), peer, static_cast<uint8_t>(page_scan_repetition_mode_),
              class_of_device_, GetClockOffset(), rssi));
    } break;
    case (model::packets::InquiryType::EXTENDED): {
      SendLinkLayerPacket(model::packets::ExtendedInquiryResponseBuilder::Create(
              GetAddress(), peer, static_cast<uint8_t>(page_scan_repetition_mode_),
              class_of_device_, GetClockOffset(), rssi, extended_inquiry_response_));
    } break;
    default:
      WARNING(id_, "Unhandled Incoming Inquiry of type {}", static_cast<int>(inquiry.GetType()));
      return;
  }
  // TODO: Send an Inquiry Response Notification Event 7.7.74
}

void BrEdrController::IncomingInquiryResponsePacket(model::packets::LinkLayerPacketView incoming) {
  auto basic_inquiry_response = model::packets::BasicInquiryResponseView::Create(incoming);
  ASSERT(basic_inquiry_response.IsValid());
  std::vector<uint8_t> eir;

  switch (basic_inquiry_response.GetInquiryType()) {
    case (model::packets::InquiryType::STANDARD): {
      // TODO: Support multiple inquiries in the same packet.
      auto inquiry_response = model::packets::InquiryResponseView::Create(basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      auto page_scan_repetition_mode =
              (bluetooth::hci::PageScanRepetitionMode)inquiry_response.GetPageScanRepetitionMode();

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
              model::packets::InquiryResponseWithRssiView::Create(basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      auto page_scan_repetition_mode =
              (bluetooth::hci::PageScanRepetitionMode)inquiry_response.GetPageScanRepetitionMode();

      std::vector<bluetooth::hci::InquiryResponseWithRssi> responses;
      responses.emplace_back();
      responses.back().address_ = inquiry_response.GetSourceAddress();
      responses.back().page_scan_repetition_mode_ = page_scan_repetition_mode;
      responses.back().class_of_device_ = inquiry_response.GetClassOfDevice();
      responses.back().clock_offset_ = inquiry_response.GetClockOffset();
      responses.back().rssi_ = inquiry_response.GetRssi();
      if (IsEventUnmasked(EventCode::INQUIRY_RESULT_WITH_RSSI)) {
        send_event_(bluetooth::hci::InquiryResultWithRssiBuilder::Create(responses));
      }
    } break;

    case (model::packets::InquiryType::EXTENDED): {
      auto inquiry_response =
              model::packets::ExtendedInquiryResponseView::Create(basic_inquiry_response);
      ASSERT(inquiry_response.IsValid());

      send_event_(bluetooth::hci::ExtendedInquiryResultBuilder::Create(
              inquiry_response.GetSourceAddress(),
              static_cast<bluetooth::hci::PageScanRepetitionMode>(
                      inquiry_response.GetPageScanRepetitionMode()),
              inquiry_response.GetClassOfDevice(), inquiry_response.GetClockOffset(),
              inquiry_response.GetRssi(), inquiry_response.GetExtendedInquiryResponse()));
    } break;

    default:
      WARNING(id_, "Unhandled Incoming Inquiry Response of type {}",
              static_cast<int>(basic_inquiry_response.GetInquiryType()));
  }
}

void BrEdrController::IncomingScoConnectionRequest(model::packets::LinkLayerPacketView incoming) {
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
            GetAddress(), address, (uint8_t)ErrorCode::SYNCHRONOUS_CONNECTION_LIMIT_EXCEEDED, 0, 0,
            0, 0, 0, 0));
    return;
  }

  // Create local connection context.
  ScoConnectionParameters connection_parameters = {
          request.GetTransmitBandwidth(),    request.GetReceiveBandwidth(),
          request.GetMaxLatency(),           request.GetVoiceSetting(),
          request.GetRetransmissionEffort(), request.GetPacketType()};

  bool extended = connection_parameters.IsExtended();
  connections_.CreateScoConnection(address, connection_parameters,
                                   extended ? ScoState::SCO_STATE_SENT_ESCO_CONNECTION_REQUEST
                                            : ScoState::SCO_STATE_SENT_SCO_CONNECTION_REQUEST,
                                   ScoDatapath::NORMAL);

  // Send connection request event and wait for Accept or Reject command.
  send_event_(bluetooth::hci::ConnectionRequestBuilder::Create(
          address, request.GetClassOfDevice(),
          extended ? bluetooth::hci::ConnectionRequestLinkType::ESCO
                   : bluetooth::hci::ConnectionRequestLinkType::SCO));
}

void BrEdrController::IncomingScoConnectionResponse(model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto response = model::packets::ScoConnectionResponseView::Create(incoming);
  ASSERT(response.IsValid());
  auto status = ErrorCode(response.GetStatus());
  auto sco_connection_handle = connections_.GetScoConnectionHandle(address);
  bool is_legacy = connections_.IsLegacyScoConnection(address);

  if (!sco_connection_handle.has_value()) {
    INFO(id_, "Received spurious eSCO connection response from {}", address);
    return;
  }

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

    connections_.AcceptPendingScoConnection(address, link_parameters, [this, address] {
      return BrEdrController::StartScoStream(address);
    });

    if (is_legacy) {
      send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
              ErrorCode::SUCCESS, *sco_connection_handle, address, bluetooth::hci::LinkType::SCO,
              bluetooth::hci::Enable::DISABLED));
    } else {
      send_event_(bluetooth::hci::SynchronousConnectionCompleteBuilder::Create(
              ErrorCode::SUCCESS, *sco_connection_handle, address,
              extended ? bluetooth::hci::ScoLinkType::ESCO : bluetooth::hci::ScoLinkType::SCO,
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
              status, 0, address, bluetooth::hci::LinkType::SCO, bluetooth::hci::Enable::DISABLED));
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

void BrEdrController::IncomingScoDisconnect(model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto request = model::packets::ScoDisconnectView::Create(incoming);
  ASSERT(request.IsValid());
  auto reason = request.GetReason();
  auto handle = connections_.GetScoConnectionHandle(address);

  INFO(id_,
       "Received eSCO disconnection request with"
       " reason 0x{:02x} from {}",
       static_cast<unsigned>(reason), incoming.GetSourceAddress());

  if (handle.has_value()) {
    connections_.Disconnect(*handle, [this](TaskId task_id) { CancelScheduledTask(task_id); });
    SendDisconnectionCompleteEvent(*handle, ErrorCode(reason));
  }
}

void BrEdrController::IncomingLmpPacket(model::packets::LinkLayerPacketView incoming) {
  Address address = incoming.GetSourceAddress();
  auto request = model::packets::LmpView::Create(incoming);
  ASSERT(request.IsValid());
  auto payload = request.GetPayload();
  auto packet = std::vector(payload.begin(), payload.end());

  ASSERT(link_manager_ingest_lmp(lm_.get(), reinterpret_cast<uint8_t (*)[6]>(address.data()),
                                 packet.data(), packet.size()));
}

void BrEdrController::HandleAcl(bluetooth::hci::AclView acl) {
  uint16_t connection_handle = acl.GetHandle();
  auto pb_flag = acl.GetPacketBoundaryFlag();
  auto bc_flag = acl.GetBroadcastFlag();

  // TODO: Support Broadcast_Flag value of BR/EDR broadcast.
  if (bc_flag != bluetooth::hci::BroadcastFlag::POINT_TO_POINT) {
    FATAL("Received ACL HCI packet with Broadcast_flag set to unsupported value {}",
          static_cast<int>(bc_flag));
  }

  if (connections_.HasAclHandle(connection_handle)) {
    // Classic ACL connection.
    auto& connection = connections_.GetAclConnection(connection_handle);
    auto acl_payload = acl.GetPayload();
    auto acl_packet = model::packets::AclBuilder::Create(
            connection.own_address, connection.address, static_cast<uint8_t>(pb_flag),
            static_cast<uint8_t>(bc_flag), std::vector(acl_payload.begin(), acl_payload.end()));
    SendLinkLayerPacket(std::move(acl_packet));

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

void BrEdrController::IncomingPagePacket(model::packets::LinkLayerPacketView incoming) {
  if (!page_scan_enable_) {
    return;
  }

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
         " event is masked by the Host",
         bd_addr);
    SendLinkLayerPacket(model::packets::PageRejectBuilder::Create(
            GetAddress(), bd_addr, static_cast<uint8_t>(ErrorCode::CONNECTION_TIMEOUT)));
    return;
  }

  // Cannot establish two BR-EDR connections with the same peer.
  if (connections_.GetAclConnectionHandle(bd_addr).has_value()) {
    return;
  }

  // Cannot establish multiple connections simultaneously.
  if (page_scan_.has_value()) {
    INFO(id_, "ignoring connection request from {}, already connecting to {}", bd_addr,
         page_scan_->bd_addr);
    return;
  }

  INFO(id_, "processing connection request from {}", bd_addr);

  page_scan_ = PageScanState{
          .bd_addr = bd_addr,
          .authentication_required = authentication_enable_ == AuthenticationEnable::REQUIRED,
          .allow_role_switch = page.GetAllowRoleSwitch(),
  };

  send_event_(bluetooth::hci::ConnectionRequestBuilder::Create(
          bd_addr, page.GetClassOfDevice(), bluetooth::hci::ConnectionRequestLinkType::ACL));
}

void BrEdrController::IncomingPageRejectPacket(model::packets::LinkLayerPacketView incoming) {
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
            static_cast<ErrorCode>(reject.GetReason()), 0, bd_addr, bluetooth::hci::LinkType::ACL,
            bluetooth::hci::Enable::DISABLED));
  }
}

void BrEdrController::IncomingPageResponsePacket(model::packets::LinkLayerPacketView incoming) {
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

  uint16_t connection_handle = connections_.CreateConnection(bd_addr, GetAddress());

  bluetooth::hci::Role role = page_->allow_role_switch && response.GetTryRoleSwitch()
                                      ? bluetooth::hci::Role::PERIPHERAL
                                      : bluetooth::hci::Role::CENTRAL;

  AclConnection& connection = connections_.GetAclConnection(connection_handle);
  CheckExpiringConnection(connection_handle);
  connection.SetLinkPolicySettings(default_link_policy_settings_);
  connection.SetRole(role);
  page_ = {};

  ASSERT(link_manager_add_link(lm_.get(), reinterpret_cast<const uint8_t (*)[6]>(bd_addr.data())));

  // Role change event before connection complete generates an HCI Role Change
  // event on the initiator side if accepted; the event is sent before the
  // HCI Connection Complete event.
  if (role == bluetooth::hci::Role::PERIPHERAL && IsEventUnmasked(EventCode::ROLE_CHANGE)) {
    send_event_(bluetooth::hci::RoleChangeBuilder::Create(ErrorCode::SUCCESS, bd_addr, role));
  }

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
            ErrorCode::SUCCESS, connection_handle, bd_addr, bluetooth::hci::LinkType::ACL,
            bluetooth::hci::Enable::DISABLED));
  }
}

void BrEdrController::Tick() {
  RunPendingTasks();
  Paging();
  Inquiry();
  link_manager_tick(lm_.get());
}

void BrEdrController::Close() {
  DisconnectAll(ErrorCode::REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF);
}

void BrEdrController::RegisterEventChannel(
        const std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>& send_event) {
  send_event_ = send_event;
}

void BrEdrController::RegisterAclChannel(
        const std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)>& send_acl) {
  send_acl_ = send_acl;
}

void BrEdrController::RegisterScoChannel(
        const std::function<void(std::shared_ptr<bluetooth::hci::ScoBuilder>)>& send_sco) {
  send_sco_ = send_sco;
}

void BrEdrController::RegisterRemoteChannel(
        const std::function<void(std::shared_ptr<model::packets::LinkLayerPacketBuilder>, Phy::Type,
                                 int8_t)>& send_to_remote) {
  send_to_remote_ = send_to_remote;
}

void BrEdrController::ForwardToLm(bluetooth::hci::CommandView command) {
  auto packet = command.bytes().bytes();
  ASSERT(link_manager_ingest_hci(lm_.get(), packet.data(), packet.size()));
}

std::vector<bluetooth::hci::Lap> const& BrEdrController::ReadCurrentIacLap() const {
  return current_iac_lap_list_;
}

void BrEdrController::WriteCurrentIacLap(std::vector<bluetooth::hci::Lap> iac_lap) {
  current_iac_lap_list_.swap(iac_lap);

  //  If Num_Current_IAC is greater than Num_Supported_IAC then only the first
  //  Num_Supported_IAC shall be stored in the Controller
  if (current_iac_lap_list_.size() > properties_.num_supported_iac) {
    current_iac_lap_list_.resize(properties_.num_supported_iac);
  }
}

void BrEdrController::MakePeripheralConnection(const Address& bd_addr, bool try_role_switch) {
  uint16_t connection_handle = connections_.CreateConnection(bd_addr, GetAddress());

  bluetooth::hci::Role role = try_role_switch && page_scan_->allow_role_switch
                                      ? bluetooth::hci::Role::CENTRAL
                                      : bluetooth::hci::Role::PERIPHERAL;

  AclConnection& connection = connections_.GetAclConnection(connection_handle);
  CheckExpiringConnection(connection_handle);
  connection.SetLinkPolicySettings(default_link_policy_settings_);
  connection.SetRole(role);

  ASSERT(link_manager_add_link(lm_.get(), reinterpret_cast<const uint8_t (*)[6]>(bd_addr.data())));

  // Role change event before connection complete generates an HCI Role Change
  // event on the acceptor side if accepted; the event is sent before the
  // HCI Connection Complete event.
  if (role == bluetooth::hci::Role::CENTRAL && IsEventUnmasked(EventCode::ROLE_CHANGE)) {
    INFO(id_, "Role at connection setup accepted");
    send_event_(bluetooth::hci::RoleChangeBuilder::Create(ErrorCode::SUCCESS, bd_addr, role));
  }

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
            ErrorCode::SUCCESS, connection_handle, bd_addr, bluetooth::hci::LinkType::ACL,
            bluetooth::hci::Enable::DISABLED));
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

  // Reset the page scan state.
  page_scan_ = {};

  INFO(id_, "Sending page response to {}", bd_addr.ToString());
  SendLinkLayerPacket(
          model::packets::PageResponseBuilder::Create(GetAddress(), bd_addr, try_role_switch));
}

void BrEdrController::RejectPeripheralConnection(const Address& addr, uint8_t reason) {
  INFO(id_, "Sending page reject to {} (reason 0x{:02x})", addr, reason);
  SendLinkLayerPacket(model::packets::PageRejectBuilder::Create(GetAddress(), addr, reason));

  if (IsEventUnmasked(EventCode::CONNECTION_COMPLETE)) {
    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
            static_cast<ErrorCode>(reason), 0xeff, addr, bluetooth::hci::LinkType::ACL,
            bluetooth::hci::Enable::DISABLED));
  }
}

void BrEdrController::SendDisconnectionCompleteEvent(uint16_t handle, ErrorCode reason) {
  if (IsEventUnmasked(EventCode::DISCONNECTION_COMPLETE)) {
    ScheduleTask(kNoDelayMs, [this, handle, reason]() {
      send_event_(bluetooth::hci::DisconnectionCompleteBuilder::Create(ErrorCode::SUCCESS, handle,
                                                                       reason));
    });
  }
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
ErrorCode BrEdrController::CentralLinkKey(uint8_t /* key_flag */) {
  // TODO: implement real logic
  return ErrorCode::COMMAND_DISALLOWED;
}

void BrEdrController::IncomingRoleSwitchRequest(model::packets::LinkLayerPacketView incoming) {
  auto bd_addr = incoming.GetSourceAddress();
  auto connection_handle = connections_.GetAclConnectionHandle(bd_addr);
  auto switch_req = model::packets::RoleSwitchRequestView::Create(incoming);
  ASSERT(switch_req.IsValid());

  if (!connection_handle.has_value()) {
    INFO(id_, "ignoring Switch Request received on unknown connection");
    return;
  }

  AclConnection& connection = connections_.GetAclConnection(*connection_handle);

  if (!connection.IsRoleSwitchEnabled()) {
    INFO(id_, "role switch disabled by local link policy settings");
    SendLinkLayerPacket(model::packets::RoleSwitchResponseBuilder::Create(
            GetAddress(), bd_addr, static_cast<uint8_t>(ErrorCode::ROLE_CHANGE_NOT_ALLOWED)));
  } else {
    INFO(id_, "role switch request accepted by local device");
    SendLinkLayerPacket(model::packets::RoleSwitchResponseBuilder::Create(
            GetAddress(), bd_addr, static_cast<uint8_t>(ErrorCode::SUCCESS)));

    bluetooth::hci::Role new_role = connection.GetRole() == bluetooth::hci::Role::CENTRAL
                                            ? bluetooth::hci::Role::PERIPHERAL
                                            : bluetooth::hci::Role::CENTRAL;

    connection.SetRole(new_role);

    if (IsEventUnmasked(EventCode::ROLE_CHANGE)) {
      ScheduleTask(kNoDelayMs, [this, bd_addr, new_role]() {
        send_event_(
                bluetooth::hci::RoleChangeBuilder::Create(ErrorCode::SUCCESS, bd_addr, new_role));
      });
    }
  }
}

void BrEdrController::IncomingRoleSwitchResponse(model::packets::LinkLayerPacketView incoming) {
  auto bd_addr = incoming.GetSourceAddress();
  auto connection_handle = connections_.GetAclConnectionHandle(bd_addr);
  auto switch_rsp = model::packets::RoleSwitchResponseView::Create(incoming);
  ASSERT(switch_rsp.IsValid());

  if (!connection_handle.has_value()) {
    INFO(id_, "ignoring Switch Response received on unknown connection");
    return;
  }

  AclConnection& connection = connections_.GetAclConnection(*connection_handle);
  ErrorCode status = ErrorCode(switch_rsp.GetStatus());
  bluetooth::hci::Role new_role = status != ErrorCode::SUCCESS ? connection.GetRole()
                                  : connection.GetRole() == bluetooth::hci::Role::CENTRAL
                                          ? bluetooth::hci::Role::PERIPHERAL
                                          : bluetooth::hci::Role::CENTRAL;

  connection.SetRole(new_role);

  if (IsEventUnmasked(EventCode::ROLE_CHANGE)) {
    ScheduleTask(kNoDelayMs, [this, status, bd_addr, new_role]() {
      send_event_(bluetooth::hci::RoleChangeBuilder::Create(status, bd_addr, new_role));
    });
  }
}

ErrorCode BrEdrController::WriteLinkSupervisionTimeout(uint16_t handle, uint16_t /* timeout */) {
  if (!connections_.HasAclHandle(handle)) {
    return ErrorCode::UNKNOWN_CONNECTION;
  }
  return ErrorCode::SUCCESS;
}

bool BrEdrController::HasAclConnection(uint16_t connection_handle) {
  return connections_.HasAclHandle(connection_handle);
}

void BrEdrController::DisconnectAll(ErrorCode reason) {
  for (auto connection_handle : connections_.GetScoHandles()) {
    SendLinkLayerPacket(model::packets::ScoDisconnectBuilder::Create(
            GetAddress(), connections_.GetScoAddress(connection_handle),
            static_cast<uint8_t>(reason)));
  }
  for (auto connection_handle : connections_.GetAclHandles()) {
    auto const& connection = connections_.GetAclConnection(connection_handle);
    SendLinkLayerPacket(model::packets::DisconnectBuilder::Create(
            connection.own_address, connection.address, static_cast<uint8_t>(reason)));
  }
}

/// Drive the logic for the Page controller substate.
void BrEdrController::Paging() {
  auto now = std::chrono::steady_clock::now();

  if (page_.has_value() && now >= page_->page_timeout) {
    INFO("page timeout triggered for connection with {}", page_->bd_addr.ToString());

    send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
            ErrorCode::PAGE_TIMEOUT, 0, page_->bd_addr, bluetooth::hci::LinkType::ACL,
            bluetooth::hci::Enable::DISABLED));

    page_ = {};
    return;
  }

  // Send a Page packet to the peer when a paging interval has passed.
  // Paging is suppressed while a pending connection with the same peer is
  // being established (i.e. two hosts initiated a connection simultaneously).
  if (page_.has_value() && now >= page_->next_page_event &&
      !(page_scan_.has_value() && page_scan_->bd_addr == page_->bd_addr)) {
    SendLinkLayerPacket(model::packets::PageBuilder::Create(
            GetAddress(), page_->bd_addr, class_of_device_, page_->allow_role_switch));
    page_->next_page_event = now + kPageInterval;
  }
}

void BrEdrController::SetInquiryMode(uint8_t mode) {
  inquiry_mode_ = static_cast<model::packets::InquiryType>(mode);
}

/// Drive the logic for the Inquiry controller substate.
void BrEdrController::Inquiry() {
  auto now = std::chrono::steady_clock::now();

  if (inquiry_.has_value() && now >= inquiry_->inquiry_timeout) {
    INFO("inquiry timeout triggered");

    if (IsEventUnmasked(EventCode::INQUIRY_COMPLETE)) {
      send_event_(bluetooth::hci::InquiryCompleteBuilder::Create(ErrorCode::SUCCESS));
    }

    inquiry_ = {};
    return;
  }

  // Send an Inquiry packet to the peer when an inquiry interval has passed.
  if (inquiry_.has_value() && now >= inquiry_->next_inquiry_event) {
    SendLinkLayerPacket(model::packets::InquiryBuilder::Create(GetAddress(), Address::kEmpty,
                                                               inquiry_mode_, inquiry_->lap));
    inquiry_->next_inquiry_event = now + kInquiryInterval;
  }
}

void BrEdrController::SetPageTimeout(uint16_t page_timeout) { page_timeout_ = page_timeout; }

void BrEdrController::CheckExpiringConnection(uint16_t handle) {
  if (!connections_.HasAclHandle(handle)) {
    return;
  }

  auto& connection = connections_.GetAclConnection(handle);

  if (connection.HasExpired()) {
    Disconnect(handle, ErrorCode::CONNECTION_TIMEOUT, ErrorCode::CONNECTION_TIMEOUT);
    return;
  }

  if (connection.IsNearExpiring()) {
    SendLinkLayerPacket(
            model::packets::PingRequestBuilder::Create(connection.own_address, connection.address));
    ScheduleTask(std::chrono::duration_cast<milliseconds>(connection.TimeUntilExpired()),
                 [this, handle] { CheckExpiringConnection(handle); });
    return;
  }

  ScheduleTask(std::chrono::duration_cast<milliseconds>(connection.TimeUntilNearExpiring()),
               [this, handle] { CheckExpiringConnection(handle); });
}

void BrEdrController::IncomingPingRequest(model::packets::LinkLayerPacketView incoming) {
  auto view = model::packets::PingRequestView::Create(incoming);
  ASSERT(view.IsValid());
  SendLinkLayerPacket(model::packets::PingResponseBuilder::Create(incoming.GetDestinationAddress(),
                                                                  incoming.GetSourceAddress()));
}

TaskId BrEdrController::StartScoStream(Address address) {
  auto sco_handle = connections_.GetScoConnectionHandle(address);
  ASSERT(sco_handle.has_value());

  auto sco_builder = bluetooth::hci::ScoBuilder::Create(
          *sco_handle, PacketStatusFlag::CORRECTLY_RECEIVED, {0, 0, 0, 0, 0});

  auto sco_bytes = sco_builder->SerializeToBytes();
  auto sco_view = bluetooth::hci::ScoView::Create(
          pdl::packet::slice(std::make_shared<std::vector<uint8_t>>(std::move(sco_bytes))));
  ASSERT(sco_view.IsValid());

  return SchedulePeriodicTask(0ms, 20ms, [this, address, sco_view]() {
    INFO(id_, "SCO sending...");
    SendScoToRemote(sco_view);
  });
}

TaskId BrEdrController::NextTaskId() {
  TaskId task_id = task_counter_++;
  while (task_id == kInvalidTaskId ||
         std::any_of(task_queue_.begin(), task_queue_.end(),
                     [=](Task const& task) { return task.task_id == task_id; })) {
    task_id = task_counter_++;
  }
  return task_id;
}

TaskId BrEdrController::ScheduleTask(std::chrono::milliseconds delay, TaskCallback task_callback) {
  TaskId task_id = NextTaskId();
  task_queue_.emplace(std::chrono::steady_clock::now() + delay, std::move(task_callback), task_id);
  return task_id;
}

TaskId BrEdrController::SchedulePeriodicTask(std::chrono::milliseconds delay,
                                             std::chrono::milliseconds period,
                                             TaskCallback task_callback) {
  TaskId task_id = NextTaskId();
  task_queue_.emplace(std::chrono::steady_clock::now() + delay, period, std::move(task_callback),
                      task_id);
  return task_id;
}

void BrEdrController::CancelScheduledTask(TaskId task_id) {
  auto it = task_queue_.cbegin();
  for (; it != task_queue_.cend(); it++) {
    if (it->task_id == task_id) {
      task_queue_.erase(it);
      return;
    }
  }
}

void BrEdrController::RunPendingTasks() {
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
