/*
 * Copyright 2015 The Android Open Source Project
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

#include "dual_mode_controller.h"

#include <algorithm>
#include <memory>
#include <random>

#include "crypto/crypto.h"
#include "log.h"
#include "packet/raw_builder.h"

using bluetooth::hci::ErrorCode;
using bluetooth::hci::LoopbackMode;
using bluetooth::hci::OpCode;
using std::vector;

namespace rootcanal {
constexpr uint16_t kNumCommandPackets = 0x01;
constexpr uint16_t kLeMaximumAdvertisingDataLength = 512;
constexpr uint16_t kLeMaximumDataLength = 64;
constexpr uint16_t kLeMaximumDataTime = 0x148;

// Device methods.
std::string DualModeController::GetTypeString() const {
  return "Simulated Bluetooth Controller";
}

void DualModeController::ReceiveLinkLayerPacket(
    model::packets::LinkLayerPacketView incoming, Phy::Type /*type*/,
    int8_t rssi) {
  link_layer_controller_.IncomingPacket(incoming, rssi);
}

void DualModeController::Tick() { link_layer_controller_.Tick(); }

void DualModeController::Close() {
  link_layer_controller_.Close();
  Device::Close();
}

void DualModeController::SendCommandCompleteUnknownOpCodeEvent(
    bluetooth::hci::OpCode op_code) const {
  send_event_(bluetooth::hci::CommandCompleteBuilder::Create(
      kNumCommandPackets, op_code,
      std::make_unique<bluetooth::packet::RawBuilder>(std::vector<uint8_t>{
          static_cast<uint8_t>(ErrorCode::UNKNOWN_HCI_COMMAND)})));
}

#ifdef ROOTCANAL_LMP
DualModeController::DualModeController(const std::string& properties_filename,
                                       uint16_t /*num_keys*/)
    : properties_(properties_filename) {
#else
DualModeController::DualModeController(const std::string& properties_filename,
                                       uint16_t num_keys)
    : properties_(properties_filename), security_manager_(num_keys) {
#endif
  loopback_mode_ = LoopbackMode::NO_LOOPBACK;

  Address public_address{};
  ASSERT(Address::FromString("3C:5A:B4:04:05:06", public_address));
  SetAddress(public_address);

  link_layer_controller_.RegisterRemoteChannel(
      [this](std::shared_ptr<model::packets::LinkLayerPacketBuilder> packet,
             Phy::Type phy_type, int8_t tx_power) {
        this->SendLinkLayerPacket(packet, phy_type, tx_power);
      });
}

void DualModeController::SniffSubrating(CommandView command) {
  auto command_view = bluetooth::hci::SniffSubratingView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  send_event_(bluetooth::hci::SniffSubratingCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      command_view.GetConnectionHandle()));
}

void DualModeController::HandleAcl(
    std::shared_ptr<std::vector<uint8_t>> packet) {
  bluetooth::hci::PacketView<bluetooth::hci::kLittleEndian> raw_packet(packet);
  auto acl_packet = bluetooth::hci::AclView::Create(raw_packet);
  ASSERT(acl_packet.IsValid());
  if (loopback_mode_ == LoopbackMode::ENABLE_LOCAL) {
    uint16_t handle = acl_packet.GetHandle();

    std::vector<uint8_t> payload{acl_packet.GetPayload().begin(),
                                 acl_packet.GetPayload().end()};
    send_acl_(bluetooth::hci::AclBuilder::Create(
        handle, acl_packet.GetPacketBoundaryFlag(),
        acl_packet.GetBroadcastFlag(),
        std::make_unique<bluetooth::packet::RawBuilder>(payload)));

    std::vector<bluetooth::hci::CompletedPackets> completed_packets;
    bluetooth::hci::CompletedPackets cp;
    cp.connection_handle_ = handle;
    cp.host_num_of_completed_packets_ = 1;
    completed_packets.push_back(cp);
    send_event_(bluetooth::hci::NumberOfCompletedPacketsBuilder::Create(
        completed_packets));
    return;
  }

  link_layer_controller_.SendAclToRemote(acl_packet);
}

void DualModeController::HandleSco(
    std::shared_ptr<std::vector<uint8_t>> packet) {
  bluetooth::hci::PacketView<bluetooth::hci::kLittleEndian> raw_packet(packet);
  auto sco_packet = bluetooth::hci::ScoView::Create(raw_packet);
  ASSERT(sco_packet.IsValid());
  if (loopback_mode_ == LoopbackMode::ENABLE_LOCAL) {
    uint16_t handle = sco_packet.GetHandle();

    send_sco_(bluetooth::hci::ScoBuilder::Create(
        handle, sco_packet.GetPacketStatusFlag(), sco_packet.GetData()));

    std::vector<bluetooth::hci::CompletedPackets> completed_packets;
    bluetooth::hci::CompletedPackets cp;
    cp.connection_handle_ = handle;
    cp.host_num_of_completed_packets_ = 1;
    completed_packets.push_back(cp);
    if (link_layer_controller_.GetScoFlowControlEnable()) {
      send_event_(bluetooth::hci::NumberOfCompletedPacketsBuilder::Create(
          completed_packets));
    }
    return;
  }

  link_layer_controller_.SendScoToRemote(sco_packet);
}

void DualModeController::HandleIso(
    std::shared_ptr<std::vector<uint8_t>> packet) {
  bluetooth::hci::PacketView<bluetooth::hci::kLittleEndian> raw_packet(packet);
  auto iso = bluetooth::hci::IsoView::Create(raw_packet);
  ASSERT(iso.IsValid());
  link_layer_controller_.HandleIso(iso);
}

void DualModeController::HandleCommand(
    std::shared_ptr<std::vector<uint8_t>> packet) {
  auto command_packet = bluetooth::hci::CommandView::Create(
      bluetooth::hci::PacketView<bluetooth::hci::kLittleEndian>(packet));
  ASSERT(command_packet.IsValid());

  OpCode op_code = command_packet.GetOpCode();
  const bool is_vendor_command = (static_cast<uint16_t>(op_code) >> 10) == 0x3f;
  const bool is_known_command =
      hci_command_op_code_to_index_.count(op_code) > 0;
  const bool is_implemented_command = hci_command_handlers_.count(op_code) > 0;

  // HCI Read Local Supported Commands is supported by default.
  // Vendor commands are supported when implemented.
  bool is_supported_command =
      (op_code == OpCode::READ_LOCAL_SUPPORTED_COMMANDS) ||
      (is_vendor_command && is_implemented_command);

  // For other commands, query the Support Commands bit mask in
  // the controller properties.
  if (!is_supported_command && is_known_command) {
    int index = static_cast<int>(hci_command_op_code_to_index_.at(op_code));
    is_supported_command = (properties_.supported_commands[index / 10] &
                            (1U << (index % 10))) != 0;
  }

  // Loopback mode, the commands are sent back to the host.
  if (loopback_mode_ == LoopbackMode::ENABLE_LOCAL &&
      op_code != OpCode::RESET &&
      op_code != OpCode::SET_CONTROLLER_TO_HOST_FLOW_CONTROL &&
      op_code != OpCode::HOST_BUFFER_SIZE &&
      op_code != OpCode::HOST_NUMBER_OF_COMPLETED_PACKETS &&
      op_code != OpCode::READ_BUFFER_SIZE &&
      op_code != OpCode::READ_LOOPBACK_MODE &&
      op_code != OpCode::WRITE_LOOPBACK_MODE) {
    std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
        std::make_unique<bluetooth::packet::RawBuilder>(255);
    raw_builder_ptr->AddOctets(*packet);
    send_event_(bluetooth::hci::LoopbackCommandBuilder::Create(
        std::move(raw_builder_ptr)));
  }
  // Command is both supported and implemented.
  // Invoke the registered handler.
  else if (is_supported_command && is_implemented_command) {
    hci_command_handlers_.at(op_code)(this, command_packet);
  }
  // Command is supported but not implemented:
  // the command needs to be implemented to fix this.
  else if (is_supported_command) {
    LOG_ALWAYS_FATAL(
        "Unimplemented command %s;\n"
        "This message will be displayed if the command is set as supported\n"
        "in the command mask but no implementation was provided.\n"
        "This warning will be fixed by implementing the command in "
        "DualModeController",
        OpCodeText(op_code).c_str());
  }
  // The command is not supported.
  // Respond with the status code Unknown Command.
  else {
    SendCommandCompleteUnknownOpCodeEvent(op_code);
    uint16_t raw_op_code = static_cast<uint16_t>(op_code);
    LOG_INFO("Unknown command, opcode: 0x%04X, OGF: 0x%04X, OCF: 0x%04X",
             raw_op_code, (raw_op_code & 0xFC00) >> 10, raw_op_code & 0x03FF);
  }
}

void DualModeController::RegisterEventChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
        send_event) {
  send_event_ =
      [send_event](std::shared_ptr<bluetooth::hci::EventBuilder> event) {
        auto bytes = std::make_shared<std::vector<uint8_t>>();
        bluetooth::packet::BitInserter bit_inserter(*bytes);
        bytes->reserve(event->size());
        event->Serialize(bit_inserter);
        send_event(std::move(bytes));
      };
  link_layer_controller_.RegisterEventChannel(send_event_);
}

void DualModeController::RegisterAclChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
        send_acl) {
  send_acl_ = [send_acl](std::shared_ptr<bluetooth::hci::AclBuilder> acl_data) {
    auto bytes = std::make_shared<std::vector<uint8_t>>();
    bluetooth::packet::BitInserter bit_inserter(*bytes);
    bytes->reserve(acl_data->size());
    acl_data->Serialize(bit_inserter);
    send_acl(std::move(bytes));
  };
  link_layer_controller_.RegisterAclChannel(send_acl_);
}

void DualModeController::RegisterScoChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
        send_sco) {
  send_sco_ = [send_sco](std::shared_ptr<bluetooth::hci::ScoBuilder> sco_data) {
    auto bytes = std::make_shared<std::vector<uint8_t>>();
    bluetooth::packet::BitInserter bit_inserter(*bytes);
    bytes->reserve(sco_data->size());
    sco_data->Serialize(bit_inserter);
    send_sco(std::move(bytes));
  };
  link_layer_controller_.RegisterScoChannel(send_sco_);
}

void DualModeController::RegisterIsoChannel(
    const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
        send_iso) {
  send_iso_ = [send_iso](std::shared_ptr<bluetooth::hci::IsoBuilder> iso_data) {
    auto bytes = std::make_shared<std::vector<uint8_t>>();
    bluetooth::packet::BitInserter bit_inserter(*bytes);
    bytes->reserve(iso_data->size());
    iso_data->Serialize(bit_inserter);
    send_iso(std::move(bytes));
  };
  link_layer_controller_.RegisterIsoChannel(send_iso_);
}

void DualModeController::Reset(CommandView command) {
  auto command_view = bluetooth::hci::ResetView::Create(command);
  ASSERT(command_view.IsValid());
  link_layer_controller_.Reset();
  if (loopback_mode_ == LoopbackMode::ENABLE_LOCAL) {
    loopback_mode_ = LoopbackMode::NO_LOOPBACK;
  }

  send_event_(bluetooth::hci::ResetCompleteBuilder::Create(kNumCommandPackets,
                                                           ErrorCode::SUCCESS));
}

void DualModeController::ReadBufferSize(CommandView command) {
  auto command_view = bluetooth::hci::ReadBufferSizeView::Create(command);
  ASSERT(command_view.IsValid());

  send_event_(bluetooth::hci::ReadBufferSizeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      properties_.acl_data_packet_length, properties_.sco_data_packet_length,
      properties_.total_num_acl_data_packets,
      properties_.total_num_sco_data_packets));
}

void DualModeController::ReadRssi(CommandView command) {
  auto command_view = bluetooth::hci::ReadRssiView::Create(
      bluetooth::hci::AclCommandView::Create(command));
  ASSERT(command_view.IsValid());

  uint16_t connection_handle = command_view.GetConnectionHandle();
  int8_t rssi = 0;

  ErrorCode status = link_layer_controller_.ReadRssi(connection_handle, &rssi);
  send_event_(bluetooth::hci::ReadRssiCompleteBuilder::Create(
      kNumCommandPackets, status, connection_handle, rssi));
}

void DualModeController::ReadEncryptionKeySize(CommandView command) {
  auto command_view = bluetooth::hci::ReadEncryptionKeySizeView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  send_event_(bluetooth::hci::ReadEncryptionKeySizeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      command_view.GetConnectionHandle(),
      link_layer_controller_.GetEncryptionKeySize()));
}

void DualModeController::HostBufferSize(CommandView command) {
  auto command_view = bluetooth::hci::HostBufferSizeView::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::HostBufferSizeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadLocalVersionInformation(CommandView command) {
  auto command_view =
      bluetooth::hci::ReadLocalVersionInformationView::Create(command);
  ASSERT(command_view.IsValid());

  bluetooth::hci::LocalVersionInformation local_version_information;
  local_version_information.hci_version_ = properties_.hci_version;
  local_version_information.lmp_version_ = properties_.lmp_version;
  local_version_information.hci_revision_ = properties_.hci_subversion;
  local_version_information.lmp_subversion_ = properties_.lmp_subversion;
  local_version_information.manufacturer_name_ = properties_.company_identifier;

  send_event_(
      bluetooth::hci::ReadLocalVersionInformationCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS, local_version_information));
}

void DualModeController::ReadRemoteVersionInformation(CommandView command) {
  auto command_view = bluetooth::hci::ReadRemoteVersionInformationView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      OpCode::READ_REMOTE_VERSION_INFORMATION, command.GetPayload(),
      command_view.GetConnectionHandle());

  send_event_(bluetooth::hci::ReadRemoteVersionInformationStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::ReadBdAddr(CommandView command) {
  auto command_view = bluetooth::hci::ReadBdAddrView::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::ReadBdAddrCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, GetAddress()));
}

void DualModeController::ReadLocalSupportedCommands(CommandView command) {
  auto command_view =
      bluetooth::hci::ReadLocalSupportedCommandsView::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::ReadLocalSupportedCommandsCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, properties_.supported_commands));
}

void DualModeController::ReadLocalSupportedFeatures(CommandView command) {
  auto command_view =
      bluetooth::hci::ReadLocalSupportedFeaturesView::Create(command);
  ASSERT(command_view.IsValid());

  send_event_(bluetooth::hci::ReadLocalSupportedFeaturesCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      link_layer_controller_.GetLmpFeatures()));
}

void DualModeController::ReadLocalSupportedCodecsV1(CommandView command) {
  auto command_view =
      bluetooth::hci::ReadLocalSupportedCodecsV1View::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::ReadLocalSupportedCodecsV1CompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      properties_.supported_standard_codecs,
      properties_.supported_vendor_specific_codecs));
}

void DualModeController::ReadLocalExtendedFeatures(CommandView command) {
  auto command_view =
      bluetooth::hci::ReadLocalExtendedFeaturesView::Create(command);
  ASSERT(command_view.IsValid());
  uint8_t page_number = command_view.GetPageNumber();

  send_event_(bluetooth::hci::ReadLocalExtendedFeaturesCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, page_number,
      link_layer_controller_.GetMaxLmpFeaturesPageNumber(),
      link_layer_controller_.GetLmpFeatures(page_number)));
}

void DualModeController::ReadRemoteExtendedFeatures(CommandView command) {
  auto command_view = bluetooth::hci::ReadRemoteExtendedFeaturesView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      OpCode::READ_REMOTE_EXTENDED_FEATURES, command_view.GetPayload(),
      command_view.GetConnectionHandle());

  send_event_(bluetooth::hci::ReadRemoteExtendedFeaturesStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::SwitchRole(CommandView command) {
  auto command_view = bluetooth::hci::SwitchRoleView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status = link_layer_controller_.SwitchRole(command_view.GetBdAddr(),
                                                  command_view.GetRole());

  send_event_(bluetooth::hci::SwitchRoleStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::ReadRemoteSupportedFeatures(CommandView command) {
  auto command_view = bluetooth::hci::ReadRemoteSupportedFeaturesView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      OpCode::READ_REMOTE_SUPPORTED_FEATURES, command_view.GetPayload(),
      command_view.GetConnectionHandle());

  send_event_(bluetooth::hci::ReadRemoteSupportedFeaturesStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::ReadClockOffset(CommandView command) {
  auto command_view = bluetooth::hci::ReadClockOffsetView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      OpCode::READ_CLOCK_OFFSET, command_view.GetPayload(), handle);

  send_event_(bluetooth::hci::ReadClockOffsetStatusBuilder::Create(
      status, kNumCommandPackets));
}

// Deprecated command, removed in v4.2.
// Support is provided to satisfy PTS tester requirements.
void DualModeController::AddScoConnection(CommandView command) {
  auto command_view = bluetooth::hci::AddScoConnectionView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status = link_layer_controller_.AddScoConnection(
      command_view.GetConnectionHandle(), command_view.GetPacketType(),
      ScoDatapath::NORMAL);

  send_event_(bluetooth::hci::AddScoConnectionStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::SetupSynchronousConnection(CommandView command) {
  auto command_view = bluetooth::hci::SetupSynchronousConnectionView::Create(
      bluetooth::hci::ScoConnectionCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status = link_layer_controller_.SetupSynchronousConnection(
      command_view.GetConnectionHandle(), command_view.GetTransmitBandwidth(),
      command_view.GetReceiveBandwidth(), command_view.GetMaxLatency(),
      command_view.GetVoiceSetting(),
      static_cast<uint8_t>(command_view.GetRetransmissionEffort()),
      command_view.GetPacketType(), ScoDatapath::NORMAL);

  send_event_(bluetooth::hci::SetupSynchronousConnectionStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::AcceptSynchronousConnection(CommandView command) {
  auto command_view = bluetooth::hci::AcceptSynchronousConnectionView::Create(
      bluetooth::hci::ScoConnectionCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status = link_layer_controller_.AcceptSynchronousConnection(
      command_view.GetBdAddr(), command_view.GetTransmitBandwidth(),
      command_view.GetReceiveBandwidth(), command_view.GetMaxLatency(),
      command_view.GetVoiceSetting(),
      static_cast<uint8_t>(command_view.GetRetransmissionEffort()),
      command_view.GetPacketType());

  send_event_(bluetooth::hci::AcceptSynchronousConnectionStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::EnhancedSetupSynchronousConnection(
    CommandView command) {
  auto command_view =
      bluetooth::hci::EnhancedSetupSynchronousConnectionView::Create(
          bluetooth::hci::ScoConnectionCommandView::Create(
              bluetooth::hci::AclCommandView::Create(command)));
  auto status = ErrorCode::SUCCESS;
  ASSERT(command_view.IsValid());

  // The Host shall set the Transmit_Coding_Format and Receive_Coding_Formats
  // to be equal.
  auto transmit_coding_format = command_view.GetTransmitCodingFormat();
  auto receive_coding_format = command_view.GetReceiveCodingFormat();
  if (transmit_coding_format.coding_format_ !=
          receive_coding_format.coding_format_ ||
      transmit_coding_format.company_id_ != receive_coding_format.company_id_ ||
      transmit_coding_format.vendor_specific_codec_id_ !=
          receive_coding_format.vendor_specific_codec_id_) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Transmit_Coding_Format "
        "(%s)"
        " and Receive_Coding_Format (%s) as they are not equal",
        transmit_coding_format.ToString().c_str(),
        receive_coding_format.ToString().c_str());
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // The Host shall either set the Input_Bandwidth and Output_Bandwidth
  // to be equal, or shall set one of them to be zero and the other non-zero.
  auto input_bandwidth = command_view.GetInputBandwidth();
  auto output_bandwidth = command_view.GetOutputBandwidth();
  if (input_bandwidth != output_bandwidth && input_bandwidth != 0 &&
      output_bandwidth != 0) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Input_Bandwidth (%u)"
        " and Output_Bandwidth (%u) as they are not equal and different from 0",
        input_bandwidth, output_bandwidth);
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // The Host shall set the Input_Coding_Format and Output_Coding_Format
  // to be equal.
  auto input_coding_format = command_view.GetInputCodingFormat();
  auto output_coding_format = command_view.GetOutputCodingFormat();
  if (input_coding_format.coding_format_ !=
          output_coding_format.coding_format_ ||
      input_coding_format.company_id_ != output_coding_format.company_id_ ||
      input_coding_format.vendor_specific_codec_id_ !=
          output_coding_format.vendor_specific_codec_id_) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Input_Coding_Format (%s)"
        " and Output_Coding_Format (%s) as they are not equal",
        input_coding_format.ToString().c_str(),
        output_coding_format.ToString().c_str());
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Root-Canal does not implement audio data transport paths other than the
  // default HCI transport - other transports will receive spoofed data
  ScoDatapath datapath = ScoDatapath::NORMAL;
  if (command_view.GetInputDataPath() != bluetooth::hci::ScoDataPath::HCI ||
      command_view.GetOutputDataPath() != bluetooth::hci::ScoDataPath::HCI) {
    LOG_WARN(
        "EnhancedSetupSynchronousConnection: Input_Data_Path (%u)"
        " and/or Output_Data_Path (%u) are not over HCI, so data will be "
        "spoofed",
        static_cast<unsigned>(command_view.GetInputDataPath()),
        static_cast<unsigned>(command_view.GetOutputDataPath()));
    datapath = ScoDatapath::SPOOFED;
  }

  // Either both the Transmit_Coding_Format and Input_Coding_Format shall be
  // “transparent” or neither shall be. If both are “transparent”, the
  // Transmit_Bandwidth and the Input_Bandwidth shall be the same and the
  // Controller shall not modify the data sent to the remote device.
  auto transmit_bandwidth = command_view.GetTransmitBandwidth();
  auto receive_bandwidth = command_view.GetReceiveBandwidth();
  if (transmit_coding_format.coding_format_ ==
          bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      input_coding_format.coding_format_ ==
          bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      transmit_bandwidth != input_bandwidth) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Transmit_Bandwidth (%u)"
        " and Input_Bandwidth (%u) as they are not equal",
        transmit_bandwidth, input_bandwidth);
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: the Transmit_Bandwidth and "
        "Input_Bandwidth shall be equal when both Transmit_Coding_Format "
        "and Input_Coding_Format are 'transparent'");
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  if ((transmit_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT) !=
      (input_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT)) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Transmit_Coding_Format "
        "(%s) and Input_Coding_Format (%s) as they are incompatible",
        transmit_coding_format.ToString().c_str(),
        input_coding_format.ToString().c_str());
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Either both the Receive_Coding_Format and Output_Coding_Format shall
  // be “transparent” or neither shall be. If both are “transparent”, the
  // Receive_Bandwidth and the Output_Bandwidth shall be the same and the
  // Controller shall not modify the data sent to the Host.
  if (receive_coding_format.coding_format_ ==
          bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      output_coding_format.coding_format_ ==
          bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      receive_bandwidth != output_bandwidth) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Receive_Bandwidth (%u)"
        " and Output_Bandwidth (%u) as they are not equal",
        receive_bandwidth, output_bandwidth);
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: the Receive_Bandwidth and "
        "Output_Bandwidth shall be equal when both Receive_Coding_Format "
        "and Output_Coding_Format are 'transparent'");
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  if ((receive_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT) !=
      (output_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT)) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Receive_Coding_Format "
        "(%s) and Output_Coding_Format (%s) as they are incompatible",
        receive_coding_format.ToString().c_str(),
        output_coding_format.ToString().c_str());
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  if (status == ErrorCode::SUCCESS) {
    status = link_layer_controller_.SetupSynchronousConnection(
        command_view.GetConnectionHandle(), transmit_bandwidth,
        receive_bandwidth, command_view.GetMaxLatency(),
        link_layer_controller_.GetVoiceSetting(),
        static_cast<uint8_t>(command_view.GetRetransmissionEffort()),
        command_view.GetPacketType(), datapath);
  }

  send_event_(
      bluetooth::hci::EnhancedSetupSynchronousConnectionStatusBuilder::Create(
          status, kNumCommandPackets));
}

void DualModeController::EnhancedAcceptSynchronousConnection(
    CommandView command) {
  auto command_view =
      bluetooth::hci::EnhancedAcceptSynchronousConnectionView::Create(
          bluetooth::hci::ScoConnectionCommandView::Create(
              bluetooth::hci::AclCommandView::Create(command)));
  auto status = ErrorCode::SUCCESS;
  ASSERT(command_view.IsValid());

  // The Host shall set the Transmit_Coding_Format and Receive_Coding_Formats
  // to be equal.
  auto transmit_coding_format = command_view.GetTransmitCodingFormat();
  auto receive_coding_format = command_view.GetReceiveCodingFormat();
  if (transmit_coding_format.coding_format_ !=
          receive_coding_format.coding_format_ ||
      transmit_coding_format.company_id_ != receive_coding_format.company_id_ ||
      transmit_coding_format.vendor_specific_codec_id_ !=
          receive_coding_format.vendor_specific_codec_id_) {
    LOG_INFO(
        "EnhancedAcceptSynchronousConnection: rejected Transmit_Coding_Format "
        "(%s)"
        " and Receive_Coding_Format (%s) as they are not equal",
        transmit_coding_format.ToString().c_str(),
        receive_coding_format.ToString().c_str());
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // The Host shall either set the Input_Bandwidth and Output_Bandwidth
  // to be equal, or shall set one of them to be zero and the other non-zero.
  auto input_bandwidth = command_view.GetInputBandwidth();
  auto output_bandwidth = command_view.GetOutputBandwidth();
  if (input_bandwidth != output_bandwidth && input_bandwidth != 0 &&
      output_bandwidth != 0) {
    LOG_INFO(
        "EnhancedAcceptSynchronousConnection: rejected Input_Bandwidth (%u)"
        " and Output_Bandwidth (%u) as they are not equal and different from 0",
        input_bandwidth, output_bandwidth);
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // The Host shall set the Input_Coding_Format and Output_Coding_Format
  // to be equal.
  auto input_coding_format = command_view.GetInputCodingFormat();
  auto output_coding_format = command_view.GetOutputCodingFormat();
  if (input_coding_format.coding_format_ !=
          output_coding_format.coding_format_ ||
      input_coding_format.company_id_ != output_coding_format.company_id_ ||
      input_coding_format.vendor_specific_codec_id_ !=
          output_coding_format.vendor_specific_codec_id_) {
    LOG_INFO(
        "EnhancedAcceptSynchronousConnection: rejected Input_Coding_Format (%s)"
        " and Output_Coding_Format (%s) as they are not equal",
        input_coding_format.ToString().c_str(),
        output_coding_format.ToString().c_str());
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Root-Canal does not implement audio data transport paths other than the
  // default HCI transport.
  if (command_view.GetInputDataPath() != bluetooth::hci::ScoDataPath::HCI ||
      command_view.GetOutputDataPath() != bluetooth::hci::ScoDataPath::HCI) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: Input_Data_Path (%u)"
        " and/or Output_Data_Path (%u) are not over HCI, so data will be "
        "spoofed",
        static_cast<unsigned>(command_view.GetInputDataPath()),
        static_cast<unsigned>(command_view.GetOutputDataPath()));
  }

  // Either both the Transmit_Coding_Format and Input_Coding_Format shall be
  // “transparent” or neither shall be. If both are “transparent”, the
  // Transmit_Bandwidth and the Input_Bandwidth shall be the same and the
  // Controller shall not modify the data sent to the remote device.
  auto transmit_bandwidth = command_view.GetTransmitBandwidth();
  auto receive_bandwidth = command_view.GetReceiveBandwidth();
  if (transmit_coding_format.coding_format_ ==
          bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      input_coding_format.coding_format_ ==
          bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      transmit_bandwidth != input_bandwidth) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Transmit_Bandwidth (%u)"
        " and Input_Bandwidth (%u) as they are not equal",
        transmit_bandwidth, input_bandwidth);
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: the Transmit_Bandwidth and "
        "Input_Bandwidth shall be equal when both Transmit_Coding_Format "
        "and Input_Coding_Format are 'transparent'");
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  if ((transmit_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT) !=
      (input_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT)) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Transmit_Coding_Format "
        "(%s) and Input_Coding_Format (%s) as they are incompatible",
        transmit_coding_format.ToString().c_str(),
        input_coding_format.ToString().c_str());
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  // Either both the Receive_Coding_Format and Output_Coding_Format shall
  // be “transparent” or neither shall be. If both are “transparent”, the
  // Receive_Bandwidth and the Output_Bandwidth shall be the same and the
  // Controller shall not modify the data sent to the Host.
  if (receive_coding_format.coding_format_ ==
          bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      output_coding_format.coding_format_ ==
          bluetooth::hci::ScoCodingFormatValues::TRANSPARENT &&
      receive_bandwidth != output_bandwidth) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Receive_Bandwidth (%u)"
        " and Output_Bandwidth (%u) as they are not equal",
        receive_bandwidth, output_bandwidth);
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: the Receive_Bandwidth and "
        "Output_Bandwidth shall be equal when both Receive_Coding_Format "
        "and Output_Coding_Format are 'transparent'");
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }
  if ((receive_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT) !=
      (output_coding_format.coding_format_ ==
       bluetooth::hci::ScoCodingFormatValues::TRANSPARENT)) {
    LOG_INFO(
        "EnhancedSetupSynchronousConnection: rejected Receive_Coding_Format "
        "(%s) and Output_Coding_Format (%s) as they are incompatible",
        receive_coding_format.ToString().c_str(),
        output_coding_format.ToString().c_str());
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  }

  if (status == ErrorCode::SUCCESS) {
    status = link_layer_controller_.AcceptSynchronousConnection(
        command_view.GetBdAddr(), transmit_bandwidth, receive_bandwidth,
        command_view.GetMaxLatency(), link_layer_controller_.GetVoiceSetting(),
        static_cast<uint8_t>(command_view.GetRetransmissionEffort()),
        command_view.GetPacketType());
  }

  send_event_(
      bluetooth::hci::EnhancedAcceptSynchronousConnectionStatusBuilder::Create(
          status, kNumCommandPackets));
}

void DualModeController::RejectSynchronousConnection(CommandView command) {
  auto command_view = bluetooth::hci::RejectSynchronousConnectionView::Create(
      bluetooth::hci::ScoConnectionCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status = link_layer_controller_.RejectSynchronousConnection(
      command_view.GetBdAddr(), (uint16_t)command_view.GetReason());

  send_event_(bluetooth::hci::RejectSynchronousConnectionStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::IoCapabilityRequestReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::IoCapabilityRequestReplyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();
  uint8_t io_capability = static_cast<uint8_t>(command_view.GetIoCapability());
  uint8_t oob_data_present_flag =
      static_cast<uint8_t>(command_view.GetOobPresent());
  uint8_t authentication_requirements =
      static_cast<uint8_t>(command_view.GetAuthenticationRequirements());

  auto status = link_layer_controller_.IoCapabilityRequestReply(
      peer, io_capability, oob_data_present_flag, authentication_requirements);
  send_event_(bluetooth::hci::IoCapabilityRequestReplyCompleteBuilder::Create(
      kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::UserConfirmationRequestReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::UserConfirmationRequestReplyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();

  auto status = link_layer_controller_.UserConfirmationRequestReply(peer);
  send_event_(
      bluetooth::hci::UserConfirmationRequestReplyCompleteBuilder::Create(
          kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::UserConfirmationRequestNegativeReply(
    CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view =
      bluetooth::hci::UserConfirmationRequestNegativeReplyView::Create(
          bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();

  auto status =
      link_layer_controller_.UserConfirmationRequestNegativeReply(peer);
  send_event_(
      bluetooth::hci::UserConfirmationRequestNegativeReplyCompleteBuilder::
          Create(kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::PinCodeRequestReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::PinCodeRequestReplyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  LOG_INFO("%s", GetAddress().ToString().c_str());

  Address peer = command_view.GetBdAddr();
  uint8_t pin_length = command_view.GetPinCodeLength();
  std::array<uint8_t, 16> pin = command_view.GetPinCode();
  ErrorCode status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  if (pin_length >= 1 && pin_length <= 0x10) {
    status = link_layer_controller_.PinCodeRequestReply(
        peer, std::vector<uint8_t>(pin.begin(), pin.begin() + pin_length));
  }

  send_event_(bluetooth::hci::PinCodeRequestReplyCompleteBuilder::Create(
      kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::PinCodeRequestNegativeReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::PinCodeRequestNegativeReplyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  LOG_INFO("%s", GetAddress().ToString().c_str());

  Address peer = command_view.GetBdAddr();

  auto status = link_layer_controller_.PinCodeRequestNegativeReply(peer);
  send_event_(
      bluetooth::hci::PinCodeRequestNegativeReplyCompleteBuilder::Create(
          kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::UserPasskeyRequestReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::UserPasskeyRequestReplyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();
  uint32_t numeric_value = command_view.GetNumericValue();

  auto status =
      link_layer_controller_.UserPasskeyRequestReply(peer, numeric_value);
  send_event_(bluetooth::hci::UserPasskeyRequestReplyCompleteBuilder::Create(
      kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::UserPasskeyRequestNegativeReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view =
      bluetooth::hci::UserPasskeyRequestNegativeReplyView::Create(
          bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();

  auto status = link_layer_controller_.UserPasskeyRequestNegativeReply(peer);
  send_event_(
      bluetooth::hci::UserPasskeyRequestNegativeReplyCompleteBuilder::Create(
          kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::RemoteOobDataRequestReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::RemoteOobDataRequestReplyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();

  auto status = link_layer_controller_.RemoteOobDataRequestReply(
      peer, command_view.GetC(), command_view.GetR());

  send_event_(bluetooth::hci::RemoteOobDataRequestReplyCompleteBuilder::Create(
      kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::RemoteOobDataRequestNegativeReply(
    CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view =
      bluetooth::hci::RemoteOobDataRequestNegativeReplyView::Create(
          bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();

  auto status = link_layer_controller_.RemoteOobDataRequestNegativeReply(peer);
  send_event_(
      bluetooth::hci::RemoteOobDataRequestNegativeReplyCompleteBuilder::Create(
          kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::IoCapabilityRequestNegativeReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view =
      bluetooth::hci::IoCapabilityRequestNegativeReplyView::Create(
          bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();
  ErrorCode reason = command_view.GetReason();

  auto status =
      link_layer_controller_.IoCapabilityRequestNegativeReply(peer, reason);
  send_event_(
      bluetooth::hci::IoCapabilityRequestNegativeReplyCompleteBuilder::Create(
          kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::RemoteOobExtendedDataRequestReply(
    CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view =
      bluetooth::hci::RemoteOobExtendedDataRequestReplyView::Create(
          bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address peer = command_view.GetBdAddr();

  auto status = link_layer_controller_.RemoteOobExtendedDataRequestReply(
      peer, command_view.GetC192(), command_view.GetR192(),
      command_view.GetC256(), command_view.GetR256());

  send_event_(
      bluetooth::hci::RemoteOobExtendedDataRequestReplyCompleteBuilder::Create(
          kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::ReadInquiryResponseTransmitPowerLevel(
    CommandView command) {
  auto command_view =
      bluetooth::hci::ReadInquiryResponseTransmitPowerLevelView::Create(
          bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());

  uint8_t tx_power = 20;  // maximum
  send_event_(
      bluetooth::hci::ReadInquiryResponseTransmitPowerLevelCompleteBuilder::
          Create(kNumCommandPackets, ErrorCode::SUCCESS, tx_power));
}

void DualModeController::SendKeypressNotification(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::SendKeypressNotificationView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  auto peer = command_view.GetBdAddr();

  auto status = link_layer_controller_.SendKeypressNotification(
      peer, command_view.GetNotificationType());
  send_event_(bluetooth::hci::SendKeypressNotificationCompleteBuilder::Create(
      kNumCommandPackets, status, peer));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::EnhancedFlush(CommandView command) {
  auto command_view = bluetooth::hci::EnhancedFlushView::Create(command);
  ASSERT(command_view.IsValid());

  auto handle = command_view.GetConnectionHandle();
  send_event_(bluetooth::hci::EnhancedFlushStatusBuilder::Create(
      ErrorCode::SUCCESS, kNumCommandPackets));

  // TODO: When adding a queue of ACL packets.
  // Send the Enhanced Flush Complete event after discarding
  // all L2CAP packets identified by the Packet Type.
  if (link_layer_controller_.IsEventUnmasked(
          bluetooth::hci::EventCode::ENHANCED_FLUSH_COMPLETE)) {
    send_event_(bluetooth::hci::EnhancedFlushCompleteBuilder::Create(handle));
  }
}

void DualModeController::SetEventMaskPage2(CommandView command) {
  auto command_view = bluetooth::hci::SetEventMaskPage2View::Create(command);
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetEventMaskPage2(command_view.GetEventMaskPage2());
  send_event_(bluetooth::hci::SetEventMaskPage2CompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadLocalOobData(CommandView command) {
  auto command_view = bluetooth::hci::ReadLocalOobDataView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  link_layer_controller_.ReadLocalOobData();
}

void DualModeController::ReadLocalOobExtendedData(CommandView command) {
  auto command_view = bluetooth::hci::ReadLocalOobExtendedDataView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  link_layer_controller_.ReadLocalOobExtendedData();
}

void DualModeController::WriteSimplePairingMode(CommandView command) {
  auto command_view = bluetooth::hci::WriteSimplePairingModeView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  auto enabled =
      command_view.GetSimplePairingMode() == bluetooth::hci::Enable::ENABLED;
  link_layer_controller_.SetSecureSimplePairingSupport(enabled);
  send_event_(bluetooth::hci::WriteSimplePairingModeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ChangeConnectionPacketType(CommandView command) {
  auto command_view = bluetooth::hci::ChangeConnectionPacketTypeView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();
  uint16_t packet_type = static_cast<uint16_t>(command_view.GetPacketType());

  auto status =
      link_layer_controller_.ChangeConnectionPacketType(handle, packet_type);
  send_event_(bluetooth::hci::ChangeConnectionPacketTypeStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::WriteLeHostSupport(CommandView command) {
  auto command_view = bluetooth::hci::WriteLeHostSupportView::Create(command);
  ASSERT(command_view.IsValid());
  auto le_support =
      command_view.GetLeSupportedHost() == bluetooth::hci::Enable::ENABLED;
  link_layer_controller_.SetLeHostSupport(le_support);
  send_event_(bluetooth::hci::WriteLeHostSupportCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::WriteSecureConnectionsHostSupport(
    CommandView command) {
  auto command_view =
      bluetooth::hci::WriteSecureConnectionsHostSupportView::Create(
          bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetSecureConnectionsSupport(
      command_view.GetSecureConnectionsHostSupport() ==
      bluetooth::hci::Enable::ENABLED);
  send_event_(
      bluetooth::hci::WriteSecureConnectionsHostSupportCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::SetEventMask(CommandView command) {
  auto command_view = bluetooth::hci::SetEventMaskView::Create(command);
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetEventMask(command_view.GetEventMask());
  send_event_(bluetooth::hci::SetEventMaskCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadInquiryMode(CommandView command) {
  auto command_view = bluetooth::hci::ReadInquiryModeView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  bluetooth::hci::InquiryMode inquiry_mode =
      bluetooth::hci::InquiryMode::STANDARD;
  send_event_(bluetooth::hci::ReadInquiryModeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, inquiry_mode));
}

void DualModeController::WriteInquiryMode(CommandView command) {
  auto command_view = bluetooth::hci::WriteInquiryModeView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetInquiryMode(
      static_cast<uint8_t>(command_view.GetInquiryMode()));
  send_event_(bluetooth::hci::WriteInquiryModeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadPageScanType(CommandView command) {
  auto command_view = bluetooth::hci::ReadPageScanTypeView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  bluetooth::hci::PageScanType page_scan_type =
      bluetooth::hci::PageScanType::STANDARD;
  send_event_(bluetooth::hci::ReadPageScanTypeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, page_scan_type));
}

void DualModeController::WritePageScanType(CommandView command) {
  auto command_view = bluetooth::hci::WritePageScanTypeView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::WritePageScanTypeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadInquiryScanType(CommandView command) {
  auto command_view = bluetooth::hci::ReadInquiryScanTypeView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  bluetooth::hci::InquiryScanType inquiry_scan_type =
      bluetooth::hci::InquiryScanType::STANDARD;
  send_event_(bluetooth::hci::ReadInquiryScanTypeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, inquiry_scan_type));
}

void DualModeController::WriteInquiryScanType(CommandView command) {
  auto command_view = bluetooth::hci::WriteInquiryScanTypeView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::WriteInquiryScanTypeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::AuthenticationRequested(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::AuthenticationRequestedView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();
  auto status = link_layer_controller_.AuthenticationRequested(handle);

  send_event_(bluetooth::hci::AuthenticationRequestedStatusBuilder::Create(
      status, kNumCommandPackets));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::SetConnectionEncryption(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::SetConnectionEncryptionView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();
  uint8_t encryption_enable =
      static_cast<uint8_t>(command_view.GetEncryptionEnable());
  auto status =
      link_layer_controller_.SetConnectionEncryption(handle, encryption_enable);

  send_event_(bluetooth::hci::SetConnectionEncryptionStatusBuilder::Create(
      status, kNumCommandPackets));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::ChangeConnectionLinkKey(CommandView command) {
  auto command_view = bluetooth::hci::ChangeConnectionLinkKeyView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();

  auto status = link_layer_controller_.ChangeConnectionLinkKey(handle);

  send_event_(bluetooth::hci::ChangeConnectionLinkKeyStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::CentralLinkKey(CommandView command) {
  auto command_view = bluetooth::hci::CentralLinkKeyView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint8_t key_flag = static_cast<uint8_t>(command_view.GetKeyFlag());

  auto status = link_layer_controller_.CentralLinkKey(key_flag);

  send_event_(bluetooth::hci::CentralLinkKeyStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::WriteAuthenticationEnable(CommandView command) {
  auto command_view = bluetooth::hci::WriteAuthenticationEnableView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetAuthenticationEnable(
      command_view.GetAuthenticationEnable());
  send_event_(bluetooth::hci::WriteAuthenticationEnableCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadAuthenticationEnable(CommandView command) {
  auto command_view =
      bluetooth::hci::ReadAuthenticationEnableView::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::ReadAuthenticationEnableCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      static_cast<bluetooth::hci::AuthenticationEnable>(
          link_layer_controller_.GetAuthenticationEnable())));
}

void DualModeController::WriteClassOfDevice(CommandView command) {
  auto command_view = bluetooth::hci::WriteClassOfDeviceView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetClassOfDevice(command_view.GetClassOfDevice());
  send_event_(bluetooth::hci::WriteClassOfDeviceCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadPageTimeout(CommandView command) {
  auto command_view = bluetooth::hci::ReadPageTimeoutView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  uint16_t page_timeout = link_layer_controller_.GetPageTimeout();
  send_event_(bluetooth::hci::ReadPageTimeoutCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, page_timeout));
}

void DualModeController::WritePageTimeout(CommandView command) {
  auto command_view = bluetooth::hci::WritePageTimeoutView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetPageTimeout(command_view.GetPageTimeout());
  send_event_(bluetooth::hci::WritePageTimeoutCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::HoldMode(CommandView command) {
  auto command_view = bluetooth::hci::HoldModeView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();
  uint16_t hold_mode_max_interval = command_view.GetHoldModeMaxInterval();
  uint16_t hold_mode_min_interval = command_view.GetHoldModeMinInterval();

  auto status = link_layer_controller_.HoldMode(handle, hold_mode_max_interval,
                                                hold_mode_min_interval);

  send_event_(bluetooth::hci::HoldModeStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::SniffMode(CommandView command) {
  auto command_view = bluetooth::hci::SniffModeView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();
  uint16_t sniff_max_interval = command_view.GetSniffMaxInterval();
  uint16_t sniff_min_interval = command_view.GetSniffMinInterval();
  uint16_t sniff_attempt = command_view.GetSniffAttempt();
  uint16_t sniff_timeout = command_view.GetSniffTimeout();

  auto status = link_layer_controller_.SniffMode(handle, sniff_max_interval,
                                                 sniff_min_interval,
                                                 sniff_attempt, sniff_timeout);

  send_event_(bluetooth::hci::SniffModeStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::ExitSniffMode(CommandView command) {
  auto command_view = bluetooth::hci::ExitSniffModeView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  auto status =
      link_layer_controller_.ExitSniffMode(command_view.GetConnectionHandle());

  send_event_(bluetooth::hci::ExitSniffModeStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::QosSetup(CommandView command) {
  auto command_view = bluetooth::hci::QosSetupView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();
  uint8_t service_type = static_cast<uint8_t>(command_view.GetServiceType());
  uint32_t token_rate = command_view.GetTokenRate();
  uint32_t peak_bandwidth = command_view.GetPeakBandwidth();
  uint32_t latency = command_view.GetLatency();
  uint32_t delay_variation = command_view.GetDelayVariation();

  auto status =
      link_layer_controller_.QosSetup(handle, service_type, token_rate,
                                      peak_bandwidth, latency, delay_variation);

  send_event_(bluetooth::hci::QosSetupStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::RoleDiscovery(CommandView command) {
  auto command_view = bluetooth::hci::RoleDiscoveryView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();

  auto role = bluetooth::hci::Role::CENTRAL;
  auto status = link_layer_controller_.RoleDiscovery(handle, &role);

  send_event_(bluetooth::hci::RoleDiscoveryCompleteBuilder::Create(
      kNumCommandPackets, status, handle, role));
}

void DualModeController::ReadDefaultLinkPolicySettings(CommandView command) {
  auto command_view = bluetooth::hci::ReadDefaultLinkPolicySettingsView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t settings = link_layer_controller_.ReadDefaultLinkPolicySettings();
  send_event_(
      bluetooth::hci::ReadDefaultLinkPolicySettingsCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS, settings));
}

void DualModeController::WriteDefaultLinkPolicySettings(CommandView command) {
  auto command_view =
      bluetooth::hci::WriteDefaultLinkPolicySettingsView::Create(
          bluetooth::hci::ConnectionManagementCommandView::Create(
              bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.WriteDefaultLinkPolicySettings(
      command_view.GetDefaultLinkPolicySettings());
  send_event_(
      bluetooth::hci::WriteDefaultLinkPolicySettingsCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::FlowSpecification(CommandView command) {
  auto command_view = bluetooth::hci::FlowSpecificationView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();
  uint8_t flow_direction =
      static_cast<uint8_t>(command_view.GetFlowDirection());
  uint8_t service_type = static_cast<uint8_t>(command_view.GetServiceType());
  uint32_t token_rate = command_view.GetTokenRate();
  uint32_t token_bucket_size = command_view.GetTokenBucketSize();
  uint32_t peak_bandwidth = command_view.GetPeakBandwidth();
  uint32_t access_latency = command_view.GetAccessLatency();

  auto status = link_layer_controller_.FlowSpecification(
      handle, flow_direction, service_type, token_rate, token_bucket_size,
      peak_bandwidth, access_latency);

  send_event_(bluetooth::hci::FlowSpecificationStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::ReadLinkPolicySettings(CommandView command) {
  auto command_view = bluetooth::hci::ReadLinkPolicySettingsView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();
  uint16_t settings;

  auto status =
      link_layer_controller_.ReadLinkPolicySettings(handle, &settings);

  send_event_(bluetooth::hci::ReadLinkPolicySettingsCompleteBuilder::Create(
      kNumCommandPackets, status, handle, settings));
}

void DualModeController::WriteLinkPolicySettings(CommandView command) {
  auto command_view = bluetooth::hci::WriteLinkPolicySettingsView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();
  uint16_t settings = command_view.GetLinkPolicySettings();

  auto status =
      link_layer_controller_.WriteLinkPolicySettings(handle, settings);

  send_event_(bluetooth::hci::WriteLinkPolicySettingsCompleteBuilder::Create(
      kNumCommandPackets, status, handle));
}

void DualModeController::WriteLinkSupervisionTimeout(CommandView command) {
  auto command_view = bluetooth::hci::WriteLinkSupervisionTimeoutView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();
  uint16_t timeout = command_view.GetLinkSupervisionTimeout();

  auto status =
      link_layer_controller_.WriteLinkSupervisionTimeout(handle, timeout);
  send_event_(
      bluetooth::hci::WriteLinkSupervisionTimeoutCompleteBuilder::Create(
          kNumCommandPackets, status, handle));
}

void DualModeController::ReadLocalName(CommandView command) {
  auto command_view = bluetooth::hci::ReadLocalNameView::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::ReadLocalNameCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      link_layer_controller_.GetLocalName()));
}

void DualModeController::WriteLocalName(CommandView command) {
  auto command_view = bluetooth::hci::WriteLocalNameView::Create(command);
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetLocalName(command_view.GetLocalName());
  send_event_(bluetooth::hci::WriteLocalNameCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::WriteExtendedInquiryResponse(CommandView command) {
  auto command_view =
      bluetooth::hci::WriteExtendedInquiryResponseView::Create(command);
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetExtendedInquiryResponse(std::vector<uint8_t>(
      command_view.GetPayload().begin() + 1, command_view.GetPayload().end()));
  send_event_(
      bluetooth::hci::WriteExtendedInquiryResponseCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::RefreshEncryptionKey(CommandView command) {
  auto command_view = bluetooth::hci::RefreshEncryptionKeyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  uint16_t handle = command_view.GetConnectionHandle();
  send_event_(bluetooth::hci::RefreshEncryptionKeyStatusBuilder::Create(
      ErrorCode::SUCCESS, kNumCommandPackets));
  // TODO: Support this in the link layer
  send_event_(bluetooth::hci::EncryptionKeyRefreshCompleteBuilder::Create(
      ErrorCode::SUCCESS, handle));
}

void DualModeController::WriteVoiceSetting(CommandView command) {
  auto command_view = bluetooth::hci::WriteVoiceSettingView::Create(command);
  ASSERT(command_view.IsValid());

  link_layer_controller_.SetVoiceSetting(command_view.GetVoiceSetting());

  send_event_(bluetooth::hci::WriteVoiceSettingCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadNumberOfSupportedIac(CommandView command) {
  auto command_view = bluetooth::hci::ReadNumberOfSupportedIacView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::ReadNumberOfSupportedIacCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, properties_.num_supported_iac));
}

void DualModeController::ReadCurrentIacLap(CommandView command) {
  auto command_view = bluetooth::hci::ReadCurrentIacLapView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::ReadCurrentIacLapCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      link_layer_controller_.ReadCurrentIacLap()));
}

void DualModeController::WriteCurrentIacLap(CommandView command) {
  auto command_view = bluetooth::hci::WriteCurrentIacLapView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.WriteCurrentIacLap(command_view.GetLapsToWrite());
  send_event_(bluetooth::hci::WriteCurrentIacLapCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadPageScanActivity(CommandView command) {
  auto command_view = bluetooth::hci::ReadPageScanActivityView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  uint16_t interval = 0x1000;
  uint16_t window = 0x0012;
  send_event_(bluetooth::hci::ReadPageScanActivityCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, interval, window));
}

void DualModeController::WritePageScanActivity(CommandView command) {
  auto command_view = bluetooth::hci::WritePageScanActivityView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::WritePageScanActivityCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadInquiryScanActivity(CommandView command) {
  auto command_view = bluetooth::hci::ReadInquiryScanActivityView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  uint16_t interval = 0x1000;
  uint16_t window = 0x0012;
  send_event_(bluetooth::hci::ReadInquiryScanActivityCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, interval, window));
}

void DualModeController::WriteInquiryScanActivity(CommandView command) {
  auto command_view = bluetooth::hci::WriteInquiryScanActivityView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::WriteInquiryScanActivityCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadScanEnable(CommandView command) {
  auto command_view = bluetooth::hci::ReadScanEnableView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());

  bool inquiry_scan = link_layer_controller_.GetInquiryScanEnable();
  bool page_scan = link_layer_controller_.GetPageScanEnable();

  bluetooth::hci::ScanEnable scan_enable =
      inquiry_scan && page_scan
          ? bluetooth::hci::ScanEnable::INQUIRY_AND_PAGE_SCAN
      : inquiry_scan ? bluetooth::hci::ScanEnable::INQUIRY_SCAN_ONLY
      : page_scan    ? bluetooth::hci::ScanEnable::PAGE_SCAN_ONLY
                     : bluetooth::hci::ScanEnable::NO_SCANS;

  send_event_(bluetooth::hci::ReadScanEnableCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, scan_enable));
}

void DualModeController::WriteScanEnable(CommandView command) {
  auto command_view = bluetooth::hci::WriteScanEnableView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());

  bluetooth::hci::ScanEnable scan_enable = command_view.GetScanEnable();
  bool inquiry_scan =
      scan_enable == bluetooth::hci::ScanEnable::INQUIRY_AND_PAGE_SCAN ||
      scan_enable == bluetooth::hci::ScanEnable::INQUIRY_SCAN_ONLY;
  bool page_scan =
      scan_enable == bluetooth::hci::ScanEnable::INQUIRY_AND_PAGE_SCAN ||
      scan_enable == bluetooth::hci::ScanEnable::PAGE_SCAN_ONLY;

  LOG_INFO("%s | WriteScanEnable %s", GetAddress().ToString().c_str(),
           bluetooth::hci::ScanEnableText(scan_enable).c_str());

  link_layer_controller_.SetInquiryScanEnable(inquiry_scan);
  link_layer_controller_.SetPageScanEnable(page_scan);
  send_event_(bluetooth::hci::WriteScanEnableCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadSynchronousFlowControlEnable(CommandView command) {
  auto command_view =
      bluetooth::hci::ReadSynchronousFlowControlEnableView::Create(
          bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  auto enabled = bluetooth::hci::Enable::DISABLED;
  if (link_layer_controller_.GetScoFlowControlEnable()) {
    enabled = bluetooth::hci::Enable::ENABLED;
  }
  send_event_(
      bluetooth::hci::ReadSynchronousFlowControlEnableCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS, enabled));
}

void DualModeController::WriteSynchronousFlowControlEnable(
    CommandView command) {
  auto command_view =
      bluetooth::hci::WriteSynchronousFlowControlEnableView::Create(
          bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  auto enabled = command_view.GetEnable() == bluetooth::hci::Enable::ENABLED;
  link_layer_controller_.SetScoFlowControlEnable(enabled);
  send_event_(
      bluetooth::hci::WriteSynchronousFlowControlEnableCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::SetEventFilter(CommandView command) {
  auto command_view = bluetooth::hci::SetEventFilterView::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::SetEventFilterCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::Inquiry(CommandView command) {
  auto command_view = bluetooth::hci::InquiryView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  auto max_responses = command_view.GetNumResponses();
  auto length = command_view.GetInquiryLength();
  if (max_responses > 0xff || length < 1 || length > 0x30) {
    send_event_(bluetooth::hci::InquiryStatusBuilder::Create(
        ErrorCode::INVALID_HCI_COMMAND_PARAMETERS, kNumCommandPackets));
    return;
  }
  link_layer_controller_.SetInquiryLAP(command_view.GetLap().lap_);
  link_layer_controller_.SetInquiryMaxResponses(max_responses);
  link_layer_controller_.StartInquiry(std::chrono::milliseconds(length * 1280));

  send_event_(bluetooth::hci::InquiryStatusBuilder::Create(ErrorCode::SUCCESS,
                                                           kNumCommandPackets));
}

void DualModeController::InquiryCancel(CommandView command) {
  auto command_view = bluetooth::hci::InquiryCancelView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.InquiryCancel();
  send_event_(bluetooth::hci::InquiryCancelCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::AcceptConnectionRequest(CommandView command) {
  auto command_view = bluetooth::hci::AcceptConnectionRequestView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  Address addr = command_view.GetBdAddr();
  bool try_role_switch =
      command_view.GetRole() ==
      bluetooth::hci::AcceptConnectionRequestRole::BECOME_CENTRAL;
  auto status =
      link_layer_controller_.AcceptConnectionRequest(addr, try_role_switch);
  send_event_(bluetooth::hci::AcceptConnectionRequestStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::RejectConnectionRequest(CommandView command) {
  auto command_view = bluetooth::hci::RejectConnectionRequestView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  Address addr = command_view.GetBdAddr();
  uint8_t reason = static_cast<uint8_t>(command_view.GetReason());
  auto status = link_layer_controller_.RejectConnectionRequest(addr, reason);
  send_event_(bluetooth::hci::RejectConnectionRequestStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LinkKeyRequestReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::LinkKeyRequestReplyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  Address addr = command_view.GetBdAddr();
  auto key = command_view.GetLinkKey();
  auto status = link_layer_controller_.LinkKeyRequestReply(addr, key);
  send_event_(bluetooth::hci::LinkKeyRequestReplyCompleteBuilder::Create(
      kNumCommandPackets, status, addr));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::LinkKeyRequestNegativeReply(CommandView command) {
#ifdef ROOTCANAL_LMP
  link_layer_controller_.ForwardToLm(command);
#else
  auto command_view = bluetooth::hci::LinkKeyRequestNegativeReplyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  Address addr = command_view.GetBdAddr();
  auto status = link_layer_controller_.LinkKeyRequestNegativeReply(addr);
  send_event_(
      bluetooth::hci::LinkKeyRequestNegativeReplyCompleteBuilder::Create(
          kNumCommandPackets, status, addr));
#endif /* ROOTCANAL_LMP */
}

void DualModeController::DeleteStoredLinkKey(CommandView command) {
  auto command_view = bluetooth::hci::DeleteStoredLinkKeyView::Create(
      bluetooth::hci::SecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  uint16_t deleted_keys = 0;

  auto flag = command_view.GetDeleteAllFlag();
  if (flag ==
      bluetooth::hci::DeleteStoredLinkKeyDeleteAllFlag::SPECIFIED_BD_ADDR) {
    Address addr = command_view.GetBdAddr();
#ifndef ROOTCANAL_LMP
    deleted_keys = security_manager_.DeleteKey(addr);
#endif /* !ROOTCANAL_LMP */
  }

  if (flag == bluetooth::hci::DeleteStoredLinkKeyDeleteAllFlag::ALL) {
#ifndef ROOTCANAL_LMP
    security_manager_.DeleteAllKeys();
#endif /* !ROOTCANAL_LMP */
  }

  send_event_(bluetooth::hci::DeleteStoredLinkKeyCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, deleted_keys));
}

void DualModeController::RemoteNameRequest(CommandView command) {
  auto command_view = bluetooth::hci::RemoteNameRequestView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());

  Address remote_addr = command_view.GetBdAddr();

  auto status = link_layer_controller_.SendCommandToRemoteByAddress(
      OpCode::REMOTE_NAME_REQUEST, command_view.GetPayload(), GetAddress(),
      remote_addr);

  send_event_(bluetooth::hci::RemoteNameRequestStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeSetEventMask(CommandView command) {
  auto command_view = bluetooth::hci::LeSetEventMaskView::Create(command);
  ASSERT(command_view.IsValid());
  link_layer_controller_.SetLeEventMask(command_view.GetLeEventMask());
  send_event_(bluetooth::hci::LeSetEventMaskCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::LeSetHostFeature(CommandView command) {
  auto command_view = bluetooth::hci::LeSetHostFeatureView::Create(command);
  ASSERT(command_view.IsValid());

  ErrorCode status = link_layer_controller_.LeSetHostFeature(
      static_cast<uint8_t>(command_view.GetBitNumber()),
      static_cast<uint8_t>(command_view.GetBitValue()));
  send_event_(bluetooth::hci::LeSetHostFeatureCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeReadBufferSizeV1(CommandView command) {
  auto command_view = bluetooth::hci::LeReadBufferSizeV1View::Create(command);
  ASSERT(command_view.IsValid());

  bluetooth::hci::LeBufferSize le_buffer_size;
  le_buffer_size.le_data_packet_length_ = properties_.le_acl_data_packet_length;
  le_buffer_size.total_num_le_packets_ =
      properties_.total_num_le_acl_data_packets;

  send_event_(bluetooth::hci::LeReadBufferSizeV1CompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, le_buffer_size));
}

void DualModeController::LeReadBufferSizeV2(CommandView command) {
  auto command_view = bluetooth::hci::LeReadBufferSizeV2View::Create(command);
  ASSERT(command_view.IsValid());

  bluetooth::hci::LeBufferSize le_buffer_size;
  le_buffer_size.le_data_packet_length_ = properties_.le_acl_data_packet_length;
  le_buffer_size.total_num_le_packets_ =
      properties_.total_num_le_acl_data_packets;
  bluetooth::hci::LeBufferSize iso_buffer_size;
  iso_buffer_size.le_data_packet_length_ = properties_.iso_data_packet_length;
  iso_buffer_size.total_num_le_packets_ =
      properties_.total_num_iso_data_packets;

  send_event_(bluetooth::hci::LeReadBufferSizeV2CompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, le_buffer_size, iso_buffer_size));
}

void DualModeController::LeSetAddressResolutionEnable(CommandView command) {
  auto command_view = bluetooth::hci::LeSetAddressResolutionEnableView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(
          bluetooth::hci::SecurityCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetAddressResolutionEnable(
      command_view.GetAddressResolutionEnable() ==
      bluetooth::hci::Enable::ENABLED);
  send_event_(
      bluetooth::hci::LeSetAddressResolutionEnableCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeSetResolvablePrivateAddressTimeout(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeSetResolvablePrivateAddressTimeoutView::Create(
          bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status =
      link_layer_controller_.LeSetResolvablePrivateAddressTimeout(
          command_view.GetRpaTimeout());
  send_event_(
      bluetooth::hci::LeSetResolvablePrivateAddressTimeoutCompleteBuilder::
          Create(kNumCommandPackets, status));
}

void DualModeController::LeReadLocalSupportedFeatures(CommandView command) {
  auto command_view =
      bluetooth::hci::LeReadLocalSupportedFeaturesView::Create(command);
  ASSERT(command_view.IsValid());
  LOG_INFO("%s | LeReadLocalSupportedFeatures (%016llx)",
           GetAddress().ToString().c_str(),
           static_cast<unsigned long long>(properties_.le_features));

  send_event_(
      bluetooth::hci::LeReadLocalSupportedFeaturesCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS, properties_.le_features));
}

void DualModeController::LeSetRandomAddress(CommandView command) {
  auto command_view = bluetooth::hci::LeSetRandomAddressView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetRandomAddress(
      command_view.GetRandomAddress());
  send_event_(bluetooth::hci::LeSetRandomAddressCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeSetAdvertisingParameters(CommandView command) {
  auto command_view = bluetooth::hci::LeSetAdvertisingParametersView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetAdvertisingParameters(
      command_view.GetAdvertisingIntervalMin(),
      command_view.GetAdvertisingIntervalMax(),
      command_view.GetAdvertisingType(), command_view.GetOwnAddressType(),
      command_view.GetPeerAddressType(), command_view.GetPeerAddress(),
      command_view.GetAdvertisingChannelMap(),
      command_view.GetAdvertisingFilterPolicy());
  send_event_(bluetooth::hci::LeSetAdvertisingParametersCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeReadAdvertisingPhysicalChannelTxPower(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeReadAdvertisingPhysicalChannelTxPowerView::Create(
          bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(
      bluetooth::hci::LeReadAdvertisingPhysicalChannelTxPowerCompleteBuilder::
          Create(kNumCommandPackets, ErrorCode::SUCCESS,
                 properties_.le_advertising_physical_channel_tx_power));
}

void DualModeController::LeSetAdvertisingData(CommandView command) {
  auto command_view = bluetooth::hci::LeSetAdvertisingDataRawView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetAdvertisingData(
      command_view.GetAdvertisingData());
  send_event_(bluetooth::hci::LeSetAdvertisingDataCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeSetScanResponseData(CommandView command) {
  auto command_view = bluetooth::hci::LeSetScanResponseDataRawView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetScanResponseData(
      command_view.GetAdvertisingData());
  send_event_(bluetooth::hci::LeSetScanResponseDataCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeSetAdvertisingEnable(CommandView command) {
  auto command_view = bluetooth::hci::LeSetAdvertisingEnableView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());

  LOG_INFO(
      "%s | LeSetAdvertisingEnable (%d)", GetAddress().ToString().c_str(),
      command_view.GetAdvertisingEnable() == bluetooth::hci::Enable::ENABLED);

  ErrorCode status = link_layer_controller_.LeSetAdvertisingEnable(
      command_view.GetAdvertisingEnable() == bluetooth::hci::Enable::ENABLED);
  send_event_(bluetooth::hci::LeSetAdvertisingEnableCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeSetScanParameters(CommandView command) {
  auto command_view = bluetooth::hci::LeSetScanParametersView::Create(
      bluetooth::hci::LeScanningCommandView::Create(command));
  ASSERT(command_view.IsValid());

  ErrorCode status = link_layer_controller_.LeSetScanParameters(
      command_view.GetLeScanType(), command_view.GetLeScanInterval(),
      command_view.GetLeScanWindow(), command_view.GetOwnAddressType(),
      command_view.GetScanningFilterPolicy());
  send_event_(bluetooth::hci::LeSetScanParametersCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeSetScanEnable(CommandView command) {
  auto command_view = bluetooth::hci::LeSetScanEnableView::Create(
      bluetooth::hci::LeScanningCommandView::Create(command));
  ASSERT(command_view.IsValid());

  LOG_INFO("%s | LeSetScanEnable (%d)", GetAddress().ToString().c_str(),
           command_view.GetLeScanEnable() == bluetooth::hci::Enable::ENABLED);

  ErrorCode status = link_layer_controller_.LeSetScanEnable(
      command_view.GetLeScanEnable() == bluetooth::hci::Enable::ENABLED,
      command_view.GetFilterDuplicates() == bluetooth::hci::Enable::ENABLED);
  send_event_(bluetooth::hci::LeSetScanEnableCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeCreateConnection(CommandView command) {
  auto command_view = bluetooth::hci::LeCreateConnectionView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeCreateConnection(
      command_view.GetLeScanInterval(), command_view.GetLeScanWindow(),
      command_view.GetInitiatorFilterPolicy(),
      AddressWithType{
          command_view.GetPeerAddress(),
          command_view.GetPeerAddressType(),
      },
      command_view.GetOwnAddressType(), command_view.GetConnIntervalMin(),
      command_view.GetConnIntervalMax(), command_view.GetConnLatency(),
      command_view.GetSupervisionTimeout(), command_view.GetMinimumCeLength(),
      command_view.GetMaximumCeLength());
  send_event_(bluetooth::hci::LeCreateConnectionStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeCreateConnectionCancel(CommandView command) {
  auto command_view = bluetooth::hci::LeCreateConnectionCancelView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeCreateConnectionCancel();
  send_event_(bluetooth::hci::LeCreateConnectionCancelCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeConnectionUpdate(CommandView command) {
  auto command_view = bluetooth::hci::LeConnectionUpdateView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeConnectionUpdate(
      command_view.GetConnectionHandle(), command_view.GetConnIntervalMin(),
      command_view.GetConnIntervalMax(), command_view.GetConnLatency(),
      command_view.GetSupervisionTimeout());

  send_event_(bluetooth::hci::LeConnectionUpdateStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::CreateConnection(CommandView command) {
  auto command_view = bluetooth::hci::CreateConnectionView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  Address address = command_view.GetBdAddr();
  uint16_t packet_type = command_view.GetPacketType();
  uint8_t page_scan_mode =
      static_cast<uint8_t>(command_view.GetPageScanRepetitionMode());
  uint16_t clock_offset = (command_view.GetClockOffsetValid() ==
                                   bluetooth::hci::ClockOffsetValid::VALID
                               ? command_view.GetClockOffset()
                               : 0);
  uint8_t allow_role_switch =
      static_cast<uint8_t>(command_view.GetAllowRoleSwitch());

  auto status = link_layer_controller_.CreateConnection(
      address, packet_type, page_scan_mode, clock_offset, allow_role_switch);

  send_event_(bluetooth::hci::CreateConnectionStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::CreateConnectionCancel(CommandView command) {
  auto command_view = bluetooth::hci::CreateConnectionCancelView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  Address address = command_view.GetBdAddr();

  auto status = link_layer_controller_.CreateConnectionCancel(address);

  send_event_(bluetooth::hci::CreateConnectionCancelCompleteBuilder::Create(
      kNumCommandPackets, status, address));
}

void DualModeController::Disconnect(CommandView command) {
  auto command_view = bluetooth::hci::DisconnectView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();

  auto status = link_layer_controller_.Disconnect(
      handle, ErrorCode(command_view.GetReason()));

  send_event_(bluetooth::hci::DisconnectStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeReadFilterAcceptListSize(CommandView command) {
  auto command_view = bluetooth::hci::LeReadFilterAcceptListSizeView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::LeReadFilterAcceptListSizeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      properties_.le_filter_accept_list_size));
}

void DualModeController::LeClearFilterAcceptList(CommandView command) {
  auto command_view = bluetooth::hci::LeClearFilterAcceptListView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeClearFilterAcceptList();
  send_event_(bluetooth::hci::LeClearFilterAcceptListCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeAddDeviceToFilterAcceptList(CommandView command) {
  auto command_view = bluetooth::hci::LeAddDeviceToFilterAcceptListView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeAddDeviceToFilterAcceptList(
      command_view.GetAddressType(), command_view.GetAddress());
  send_event_(
      bluetooth::hci::LeAddDeviceToFilterAcceptListCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeRemoveDeviceFromFilterAcceptList(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeRemoveDeviceFromFilterAcceptListView::Create(
          bluetooth::hci::LeConnectionManagementCommandView::Create(
              bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeRemoveDeviceFromFilterAcceptList(
      command_view.GetAddressType(), command_view.GetAddress());
  send_event_(
      bluetooth::hci::LeRemoveDeviceFromFilterAcceptListCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeClearResolvingList(CommandView command) {
  auto command_view = bluetooth::hci::LeClearResolvingListView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeClearResolvingList();
  send_event_(bluetooth::hci::LeClearResolvingListCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeReadResolvingListSize(CommandView command) {
  auto command_view = bluetooth::hci::LeReadResolvingListSizeView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::LeReadResolvingListSizeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      properties_.le_resolving_list_size));
}

void DualModeController::LeReadMaximumDataLength(CommandView command) {
  auto command_view = bluetooth::hci::LeReadMaximumDataLengthView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  bluetooth::hci::LeMaximumDataLength data_length;
  data_length.supported_max_rx_octets_ = kLeMaximumDataLength;
  data_length.supported_max_rx_time_ = kLeMaximumDataTime;
  data_length.supported_max_tx_octets_ = kLeMaximumDataLength + 10;
  data_length.supported_max_tx_time_ = kLeMaximumDataTime + 10;
  send_event_(bluetooth::hci::LeReadMaximumDataLengthCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, data_length));
}

void DualModeController::LeReadPhy(CommandView command) {
  auto command_view = bluetooth::hci::LeReadPhyView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  uint16_t connection_handle = command_view.GetConnectionHandle();
  bluetooth::hci::PhyType tx_phy{};
  bluetooth::hci::PhyType rx_phy{};
  ErrorCode status =
      link_layer_controller_.LeReadPhy(connection_handle, &tx_phy, &rx_phy);
  send_event_(bluetooth::hci::LeReadPhyCompleteBuilder::Create(
      kNumCommandPackets, status, connection_handle, tx_phy, rx_phy));
}

void DualModeController::LeSetDefaultPhy(CommandView command) {
  auto command_view = bluetooth::hci::LeSetDefaultPhyView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetDefaultPhy(
      command_view.GetAllPhysNoTransmitPreference(),
      command_view.GetAllPhysNoReceivePreference(),
      command_view.GetTxPhysBitmask(), command_view.GetRxPhysBitmask());
  send_event_(bluetooth::hci::LeSetDefaultPhyCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeSetPhy(CommandView command) {
  auto command_view = bluetooth::hci::LeSetPhyView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetPhy(
      command_view.GetConnectionHandle(),
      command_view.GetAllPhysNoTransmitPreference(),
      command_view.GetAllPhysNoReceivePreference(),
      command_view.GetTxPhysBitmask(), command_view.GetRxPhysBitmask(),
      command_view.GetPhyOptions());
  send_event_(bluetooth::hci::LeSetPhyStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeReadSuggestedDefaultDataLength(CommandView command) {
  auto command_view =
      bluetooth::hci::LeReadSuggestedDefaultDataLengthView::Create(
          bluetooth::hci::LeConnectionManagementCommandView::Create(
              bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  send_event_(
      bluetooth::hci::LeReadSuggestedDefaultDataLengthCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS,
          link_layer_controller_.GetLeSuggestedMaxTxOctets(),
          link_layer_controller_.GetLeSuggestedMaxTxTime()));
}

void DualModeController::LeWriteSuggestedDefaultDataLength(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeWriteSuggestedDefaultDataLengthView::Create(
          bluetooth::hci::LeConnectionManagementCommandView::Create(
              bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  uint16_t max_tx_octets = command_view.GetTxOctets();
  uint16_t max_tx_time = command_view.GetTxTime();
  ErrorCode status = ErrorCode::SUCCESS;
  if (max_tx_octets > 0xFB || max_tx_octets < 0x1B || max_tx_time < 0x148 ||
      max_tx_time > 0x4290) {
    status = ErrorCode::INVALID_HCI_COMMAND_PARAMETERS;
  } else {
    link_layer_controller_.SetLeSuggestedMaxTxOctets(max_tx_octets);
    link_layer_controller_.SetLeSuggestedMaxTxTime(max_tx_time);
  }

  send_event_(
      bluetooth::hci::LeWriteSuggestedDefaultDataLengthCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeAddDeviceToResolvingList(CommandView command) {
  auto command_view = bluetooth::hci::LeAddDeviceToResolvingListView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeAddDeviceToResolvingList(
      command_view.GetPeerIdentityAddressType(),
      command_view.GetPeerIdentityAddress(), command_view.GetPeerIrk(),
      command_view.GetLocalIrk());
  send_event_(bluetooth::hci::LeAddDeviceToResolvingListCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeRemoveDeviceFromResolvingList(CommandView command) {
  auto command_view =
      bluetooth::hci::LeRemoveDeviceFromResolvingListView::Create(
          bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeRemoveDeviceFromResolvingList(
      command_view.GetPeerIdentityAddressType(),
      command_view.GetPeerIdentityAddress());
  send_event_(
      bluetooth::hci::LeRemoveDeviceFromResolvingListCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeSetExtendedScanParameters(CommandView command) {
  auto command_view = bluetooth::hci::LeSetExtendedScanParametersView::Create(
      bluetooth::hci::LeScanningCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetExtendedScanParameters(
      command_view.GetOwnAddressType(), command_view.GetScanningFilterPolicy(),
      command_view.GetScanningPhys(), command_view.GetParameters());
  send_event_(
      bluetooth::hci::LeSetExtendedScanParametersCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeSetExtendedScanEnable(CommandView command) {
  auto command_view = bluetooth::hci::LeSetExtendedScanEnableView::Create(
      bluetooth::hci::LeScanningCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetExtendedScanEnable(
      command_view.GetEnable() == bluetooth::hci::Enable::ENABLED,
      command_view.GetFilterDuplicates(), command_view.GetDuration(),
      command_view.GetPeriod());
  send_event_(bluetooth::hci::LeSetExtendedScanEnableCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeExtendedCreateConnection(CommandView command) {
  auto command_view = bluetooth::hci::LeExtendedCreateConnectionView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeExtendedCreateConnection(
      command_view.GetInitiatorFilterPolicy(), command_view.GetOwnAddressType(),
      AddressWithType{
          command_view.GetPeerAddress(),
          command_view.GetPeerAddressType(),
      },
      command_view.GetInitiatingPhys(), command_view.GetPhyScanParameters());
  send_event_(bluetooth::hci::LeExtendedCreateConnectionStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeSetPrivacyMode(CommandView command) {
  auto command_view = bluetooth::hci::LeSetPrivacyModeView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetPrivacyMode(
      command_view.GetPeerIdentityAddressType(),
      command_view.GetPeerIdentityAddress(), command_view.GetPrivacyMode());
  send_event_(bluetooth::hci::LeSetPrivacyModeCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeReadIsoTxSync(CommandView command) {
  auto command_view = bluetooth::hci::LeReadIsoTxSyncView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.LeReadIsoTxSync(command_view.GetConnectionHandle());
}

void DualModeController::LeSetCigParameters(CommandView command) {
  auto command_view = bluetooth::hci::LeSetCigParametersView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.LeSetCigParameters(
      command_view.GetCigId(), command_view.GetSduIntervalMToS(),
      command_view.GetSduIntervalSToM(),
      command_view.GetPeripheralsClockAccuracy(), command_view.GetPacking(),
      command_view.GetFraming(), command_view.GetMaxTransportLatencyMToS(),
      command_view.GetMaxTransportLatencySToM(), command_view.GetCisConfig());
}

void DualModeController::LeCreateCis(CommandView command) {
  auto command_view = bluetooth::hci::LeCreateCisView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status =
      link_layer_controller_.LeCreateCis(command_view.GetCisConfig());
  send_event_(bluetooth::hci::LeCreateCisStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeRemoveCig(CommandView command) {
  auto command_view = bluetooth::hci::LeRemoveCigView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  uint8_t cig = command_view.GetCigId();
  ErrorCode status = link_layer_controller_.LeRemoveCig(cig);
  send_event_(bluetooth::hci::LeRemoveCigCompleteBuilder::Create(
      kNumCommandPackets, status, cig));
}

void DualModeController::LeAcceptCisRequest(CommandView command) {
  auto command_view = bluetooth::hci::LeAcceptCisRequestView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeAcceptCisRequest(
      command_view.GetConnectionHandle());
  send_event_(bluetooth::hci::LeAcceptCisRequestStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeRejectCisRequest(CommandView command) {
  auto command_view = bluetooth::hci::LeRejectCisRequestView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.LeRejectCisRequest(command_view.GetConnectionHandle(),
                                            command_view.GetReason());
}

void DualModeController::LeCreateBig(CommandView command) {
  auto command_view = bluetooth::hci::LeCreateBigView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeCreateBig(
      command_view.GetBigHandle(), command_view.GetAdvertisingHandle(),
      command_view.GetNumBis(), command_view.GetSduInterval(),
      command_view.GetMaxSdu(), command_view.GetMaxTransportLatency(),
      command_view.GetRtn(), command_view.GetPhy(), command_view.GetPacking(),
      command_view.GetFraming(), command_view.GetEncryption(),
      command_view.GetBroadcastCode());
  send_event_(bluetooth::hci::LeCreateBigStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeTerminateBig(CommandView command) {
  auto command_view = bluetooth::hci::LeTerminateBigView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeTerminateBig(
      command_view.GetBigHandle(), command_view.GetReason());
  send_event_(bluetooth::hci::LeTerminateBigStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeBigCreateSync(CommandView command) {
  auto command_view = bluetooth::hci::LeBigCreateSyncView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeBigCreateSync(
      command_view.GetBigHandle(), command_view.GetSyncHandle(),
      command_view.GetEncryption(), command_view.GetBroadcastCode(),
      command_view.GetMse(), command_view.GetBigSyncTimeout(),
      command_view.GetBis());
  send_event_(bluetooth::hci::LeBigCreateSyncStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeBigTerminateSync(CommandView command) {
  auto command_view = bluetooth::hci::LeBigTerminateSyncView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.LeBigTerminateSync(command_view.GetBigHandle());
}

void DualModeController::LeRequestPeerSca(CommandView command) {
  auto command_view = bluetooth::hci::LeRequestPeerScaView::Create(command);
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeRequestPeerSca(
      command_view.GetConnectionHandle());
  send_event_(bluetooth::hci::LeRequestPeerScaStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeSetupIsoDataPath(CommandView command) {
  auto command_view = bluetooth::hci::LeSetupIsoDataPathView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.LeSetupIsoDataPath(
      command_view.GetConnectionHandle(), command_view.GetDataPathDirection(),
      command_view.GetDataPathId(), command_view.GetCodecId(),
      command_view.GetControllerDelay(), command_view.GetCodecConfiguration());
}

void DualModeController::LeRemoveIsoDataPath(CommandView command) {
  auto command_view = bluetooth::hci::LeRemoveIsoDataPathView::Create(
      bluetooth::hci::LeIsoCommandView::Create(command));
  ASSERT(command_view.IsValid());
  link_layer_controller_.LeRemoveIsoDataPath(
      command_view.GetConnectionHandle(),
      command_view.GetRemoveDataPathDirection());
}

void DualModeController::LeReadRemoteFeatures(CommandView command) {
  auto command_view = bluetooth::hci::LeReadRemoteFeaturesView::Create(
      bluetooth::hci::LeConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();

  auto status = link_layer_controller_.SendCommandToRemoteByHandle(
      OpCode::LE_READ_REMOTE_FEATURES, command_view.GetPayload(), handle);

  send_event_(bluetooth::hci::LeReadRemoteFeaturesStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeEncrypt(CommandView command) {
  auto command_view = bluetooth::hci::LeEncryptView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  auto encrypted_data = rootcanal::crypto::aes_128(
      command_view.GetKey(), command_view.GetPlaintextData());

  send_event_(bluetooth::hci::LeEncryptCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, encrypted_data));
}

static std::random_device rd{};
static std::mt19937_64 s_mt{rd()};

void DualModeController::LeRand(CommandView command) {
  auto command_view = bluetooth::hci::LeRandView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  uint64_t random_val = s_mt();

  send_event_(bluetooth::hci::LeRandCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, random_val));
}

void DualModeController::LeReadSupportedStates(CommandView command) {
  auto command_view =
      bluetooth::hci::LeReadSupportedStatesView::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::LeReadSupportedStatesCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, properties_.le_supported_states));
}

void DualModeController::LeRemoteConnectionParameterRequestReply(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeRemoteConnectionParameterRequestReplyView::Create(
          bluetooth::hci::LeConnectionManagementCommandView::Create(
              bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  auto status = link_layer_controller_.LeRemoteConnectionParameterRequestReply(
      command_view.GetConnectionHandle(), command_view.GetIntervalMin(),
      command_view.GetIntervalMax(), command_view.GetTimeout(),
      command_view.GetLatency(), command_view.GetMinimumCeLength(),
      command_view.GetMaximumCeLength());
  send_event_(
      bluetooth::hci::LeRemoteConnectionParameterRequestReplyCompleteBuilder::
          Create(kNumCommandPackets, status,
                 command_view.GetConnectionHandle()));
}

void DualModeController::LeRemoteConnectionParameterRequestNegativeReply(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeRemoteConnectionParameterRequestNegativeReplyView::
          Create(bluetooth::hci::LeConnectionManagementCommandView::Create(
              bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());
  auto status =
      link_layer_controller_.LeRemoteConnectionParameterRequestNegativeReply(
          command_view.GetConnectionHandle(), command_view.GetReason());
  send_event_(
      bluetooth::hci::
          LeRemoteConnectionParameterRequestNegativeReplyCompleteBuilder::
              Create(kNumCommandPackets, status,
                     command_view.GetConnectionHandle()));
}

void DualModeController::LeGetVendorCapabilities(CommandView command) {
  auto command_view = bluetooth::hci::LeGetVendorCapabilitiesView::Create(
      bluetooth::hci::VendorCommandView::Create(command));
  ASSERT(command_view.IsValid());
  vector<uint8_t> caps = properties_.le_vendor_capabilities;
  if (caps.empty()) {
    SendCommandCompleteUnknownOpCodeEvent(OpCode::LE_GET_VENDOR_CAPABILITIES);
    return;
  }

  std::unique_ptr<bluetooth::packet::RawBuilder> raw_builder_ptr =
      std::make_unique<bluetooth::packet::RawBuilder>();
  raw_builder_ptr->AddOctets1(static_cast<uint8_t>(ErrorCode::SUCCESS));
  raw_builder_ptr->AddOctets(properties_.le_vendor_capabilities);

  send_event_(bluetooth::hci::CommandCompleteBuilder::Create(
      kNumCommandPackets, OpCode::LE_GET_VENDOR_CAPABILITIES,
      std::move(raw_builder_ptr)));
}

void DualModeController::LeMultiAdv(CommandView command) {
  auto command_view = bluetooth::hci::LeMultiAdvtView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  SendCommandCompleteUnknownOpCodeEvent(OpCode::LE_MULTI_ADVT);
}

void DualModeController::LeAdvertisingFilter(CommandView command) {
  auto command_view = bluetooth::hci::LeAdvFilterView::Create(
      bluetooth::hci::LeScanningCommandView::Create(command));
  ASSERT(command_view.IsValid());
  SendCommandCompleteUnknownOpCodeEvent(OpCode::LE_ADV_FILTER);
}

void DualModeController::LeEnergyInfo(CommandView command) {
  auto command_view = bluetooth::hci::LeEnergyInfoView::Create(
      bluetooth::hci::VendorCommandView::Create(command));
  ASSERT(command_view.IsValid());
  SendCommandCompleteUnknownOpCodeEvent(OpCode::LE_ENERGY_INFO);
}

// CSR vendor command.
// Implement the command specific to the CSR controller
// used specifically by the PTS tool to pass certification tests.
void DualModeController::CsrVendorCommand(CommandView command) {
  // The byte order is little endian.
  // The command parameters are formatted as
  //
  //  00    | 0xc2
  //  01 02 | action
  //          read = 0
  //          write = 2
  //  03 04 | (value length / 2) + 5
  //  04 05 | sequence number
  //  06 07 | varid
  //  08 09 | 00 00
  //  0a .. | value
  //
  // BlueZ has a reference implementation of the CSR vendor command.

  std::vector<uint8_t> parameters(command.GetPayload().begin(),
                                  command.GetPayload().end());

  uint16_t type = 0;
  uint16_t length = 0;
  uint16_t varid = 0;

  if (parameters.empty()) {
    LOG_INFO("Empty CSR vendor command");
    goto complete;
  }

  if (parameters[0] != 0xc2 || parameters.size() < 11) {
    LOG_INFO(
        "Unsupported CSR vendor command with code %02x "
        "and parameter length %zu",
        static_cast<int>(parameters[0]), parameters.size());
    goto complete;
  }

  type = (uint16_t)parameters[1] | ((uint16_t)parameters[2] << 8);
  length = (uint16_t)parameters[3] | ((uint16_t)parameters[4] << 8);
  varid = (uint16_t)parameters[7] | ((uint16_t)parameters[8] << 8);
  length = 2 * (length - 5);

  if (parameters.size() < (11 + length) ||
      (varid == CsrVarid::CSR_VARID_PS && length < 6)) {
    LOG_INFO("Invalid CSR vendor command parameter length %zu, expected %u",
             parameters.size(), 11 + length);
    goto complete;
  }

  if (varid == CsrVarid::CSR_VARID_PS) {
    // Subcommand to read or write PSKEY of the selected identifier
    // instead of VARID.
    uint16_t pskey = (uint16_t)parameters[11] | ((uint16_t)parameters[12] << 8);
    uint16_t length =
        (uint16_t)parameters[13] | ((uint16_t)parameters[14] << 8);
    length = 2 * length;

    if (parameters.size() < (17 + length)) {
      LOG_INFO("Invalid CSR vendor command parameter length %zu, expected %u",
               parameters.size(), 17 + length);
      goto complete;
    }

    std::vector<uint8_t> value(parameters.begin() + 17,
                               parameters.begin() + 17 + length);

    LOG_INFO("CSR vendor command type=%04x length=%04x pskey=%04x", type,
             length, pskey);

    if (type == 0) {
      CsrReadPskey(static_cast<CsrPskey>(pskey), value);
      std::copy(value.begin(), value.end(), parameters.begin() + 17);
    } else {
      CsrWritePskey(static_cast<CsrPskey>(pskey), value);
    }

  } else {
    // Subcommand to read or write VARID of the selected identifier.
    std::vector<uint8_t> value(parameters.begin() + 11,
                               parameters.begin() + 11 + length);

    LOG_INFO("CSR vendor command type=%04x length=%04x varid=%04x", type,
             length, varid);

    if (type == 0) {
      CsrReadVarid(static_cast<CsrVarid>(varid), value);
      std::copy(value.begin(), value.end(), parameters.begin() + 11);
    } else {
      CsrWriteVarid(static_cast<CsrVarid>(varid), value);
    }
  }

complete:
  // Overwrite the command type.
  parameters[1] = 0x1;
  parameters[2] = 0x0;
  send_event_(bluetooth::hci::EventBuilder::Create(
      bluetooth::hci::EventCode::VENDOR_SPECIFIC,
      std::make_unique<bluetooth::packet::RawBuilder>(std::move(parameters))));
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
void DualModeController::CsrReadVarid(CsrVarid varid,
                                      std::vector<uint8_t>& value) {
  switch (varid) {
    case CsrVarid::CSR_VARID_BUILDID:
      // Return the extact Build ID returned by the official PTS dongle.
      ASSERT(value.size() >= 2);
      value[0] = 0xe8;
      value[1] = 0x30;
      break;

    default:
      LOG_INFO("Unsupported read of CSR varid 0x%04x", varid);
      break;
  }
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
void DualModeController::CsrWriteVarid(CsrVarid varid,
                                       std::vector<uint8_t> const& value) {
  LOG_INFO("Unsupported write of CSR varid 0x%04x", varid);
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
void DualModeController::CsrReadPskey(CsrPskey pskey,
                                      std::vector<uint8_t>& value) {
  switch (pskey) {
    case CsrPskey::CSR_PSKEY_ENC_KEY_LMIN:
      ASSERT(!value.empty());
      value[0] = 7;
      break;

    case CsrPskey::CSR_PSKEY_ENC_KEY_LMAX:
      ASSERT(!value.empty());
      value[0] = 16;
      break;

    case CSR_PSKEY_HCI_LMP_LOCAL_VERSION:
      // Return the extact version returned by the official PTS dongle.
      ASSERT(value.size() >= 2);
      value[0] = 0x08;
      value[1] = 0x08;
      break;

    default:
      LOG_INFO("Unsupported read of CSR pskey 0x%04x", pskey);
      break;
  }
}

void DualModeController::CsrWritePskey(CsrPskey pskey,
                                       std::vector<uint8_t> const& value) {
  switch (pskey) {
    case CsrPskey::CSR_PSKEY_LOCAL_SUPPORTED_FEATURES:
      ASSERT(value.size() >= 8);
      LOG_INFO("CSR Vendor updating the Local Supported Features");
      properties_.lmp_features[0] =
          ((uint64_t)value[0] << 0) | ((uint64_t)value[1] << 8) |
          ((uint64_t)value[2] << 16) | ((uint64_t)value[3] << 24) |
          ((uint64_t)value[4] << 32) | ((uint64_t)value[5] << 40) |
          ((uint64_t)value[6] << 48) | ((uint64_t)value[7] << 56);
      break;

    default:
      LOG_INFO("Unsupported write of CSR pskey 0x%04x", pskey);
      break;
  }
}

void DualModeController::LeSetAdvertisingSetRandomAddress(CommandView command) {
  auto command_view =
      bluetooth::hci::LeSetAdvertisingSetRandomAddressView::Create(
          bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetAdvertisingSetRandomAddress(
      command_view.GetAdvertisingHandle(), command_view.GetRandomAddress());
  send_event_(
      bluetooth::hci::LeSetAdvertisingSetRandomAddressCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeSetExtendedAdvertisingParameters(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeSetExtendedAdvertisingParametersView::Create(
          bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetExtendedAdvertisingParameters(
      command_view.GetAdvertisingHandle(),
      command_view.GetAdvertisingEventProperties(),
      command_view.GetPrimaryAdvertisingIntervalMin(),
      command_view.GetPrimaryAdvertisingIntervalMax(),
      command_view.GetPrimaryAdvertisingChannelMap(),
      command_view.GetOwnAddressType(), command_view.GetPeerAddressType(),
      command_view.GetPeerAddress(), command_view.GetAdvertisingFilterPolicy(),
      command_view.GetAdvertisingTxPower(),
      command_view.GetPrimaryAdvertisingPhy(),
      command_view.GetSecondaryAdvertisingMaxSkip(),
      command_view.GetSecondaryAdvertisingPhy(),
      command_view.GetAdvertisingSid(),
      command_view.GetScanRequestNotificationEnable() == Enable::ENABLED);
  // The selected TX power is always the requested TX power
  // at the moment.
  send_event_(
      bluetooth::hci::LeSetExtendedAdvertisingParametersCompleteBuilder::Create(
          kNumCommandPackets, status, command_view.GetAdvertisingTxPower()));
}

void DualModeController::LeSetExtendedAdvertisingData(CommandView command) {
  auto command_view = bluetooth::hci::LeSetExtendedAdvertisingDataView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  auto raw_command_view =
      bluetooth::hci::LeSetExtendedAdvertisingDataRawView::Create(
          bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(raw_command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetExtendedAdvertisingData(
      command_view.GetAdvertisingHandle(), command_view.GetOperation(),
      command_view.GetFragmentPreference(),
      raw_command_view.GetAdvertisingData());
  send_event_(
      bluetooth::hci::LeSetExtendedAdvertisingDataCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeSetExtendedScanResponseData(CommandView command) {
  auto command_view = bluetooth::hci::LeSetExtendedScanResponseDataView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  auto raw_command_view =
      bluetooth::hci::LeSetExtendedScanResponseDataRawView::Create(
          bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(raw_command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetExtendedScanResponseData(
      command_view.GetAdvertisingHandle(), command_view.GetOperation(),
      command_view.GetFragmentPreference(),
      raw_command_view.GetScanResponseData());
  send_event_(
      bluetooth::hci::LeSetExtendedScanResponseDataCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeSetExtendedAdvertisingEnable(CommandView command) {
  auto command_view =
      bluetooth::hci::LeSetExtendedAdvertisingEnableView::Create(
          bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  ErrorCode status = link_layer_controller_.LeSetExtendedAdvertisingEnable(
      command_view.GetEnable() == bluetooth::hci::Enable::ENABLED,
      command_view.GetEnabledSets());
  send_event_(
      bluetooth::hci::LeSetExtendedAdvertisingEnableCompleteBuilder::Create(
          kNumCommandPackets, status));
}

void DualModeController::LeReadMaximumAdvertisingDataLength(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeReadMaximumAdvertisingDataLengthView::Create(
          bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(
      bluetooth::hci::LeReadMaximumAdvertisingDataLengthCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS,
          kLeMaximumAdvertisingDataLength));
}

void DualModeController::LeReadNumberOfSupportedAdvertisingSets(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeReadNumberOfSupportedAdvertisingSetsView::Create(
          bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  send_event_(
      bluetooth::hci::LeReadNumberOfSupportedAdvertisingSetsCompleteBuilder::
          Create(kNumCommandPackets, ErrorCode::SUCCESS,
                 properties_.le_num_supported_advertising_sets));
}

void DualModeController::LeRemoveAdvertisingSet(CommandView command) {
  auto command_view = bluetooth::hci::LeRemoveAdvertisingSetView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  auto status = link_layer_controller_.LeRemoveAdvertisingSet(
      command_view.GetAdvertisingHandle());
  send_event_(bluetooth::hci::LeRemoveAdvertisingSetCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeClearAdvertisingSets(CommandView command) {
  auto command_view = bluetooth::hci::LeClearAdvertisingSetsView::Create(
      bluetooth::hci::LeAdvertisingCommandView::Create(command));
  ASSERT(command_view.IsValid());
  auto status = link_layer_controller_.LeClearAdvertisingSets();
  send_event_(bluetooth::hci::LeClearAdvertisingSetsCompleteBuilder::Create(
      kNumCommandPackets, status));
}

void DualModeController::LeExtendedScanParams(CommandView command) {
  auto command_view = bluetooth::hci::LeExtendedScanParamsView::Create(
      bluetooth::hci::LeScanningCommandView::Create(command));
  ASSERT(command_view.IsValid());
  SendCommandCompleteUnknownOpCodeEvent(OpCode::LE_EXTENDED_SCAN_PARAMS);
}

void DualModeController::LeStartEncryption(CommandView command) {
  auto command_view = bluetooth::hci::LeStartEncryptionView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  ErrorCode status = link_layer_controller_.LeEnableEncryption(
      command_view.GetConnectionHandle(), command_view.GetRand(),
      command_view.GetEdiv(), command_view.GetLtk());

  send_event_(bluetooth::hci::LeStartEncryptionStatusBuilder::Create(
      status, kNumCommandPackets));
}

void DualModeController::LeLongTermKeyRequestReply(CommandView command) {
  auto command_view = bluetooth::hci::LeLongTermKeyRequestReplyView::Create(
      bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();
  ErrorCode status = link_layer_controller_.LeLongTermKeyRequestReply(
      handle, command_view.GetLongTermKey());

  send_event_(bluetooth::hci::LeLongTermKeyRequestReplyCompleteBuilder::Create(
      kNumCommandPackets, status, handle));
}

void DualModeController::LeLongTermKeyRequestNegativeReply(
    CommandView command) {
  auto command_view =
      bluetooth::hci::LeLongTermKeyRequestNegativeReplyView::Create(
          bluetooth::hci::LeSecurityCommandView::Create(command));
  ASSERT(command_view.IsValid());

  uint16_t handle = command_view.GetConnectionHandle();
  ErrorCode status =
      link_layer_controller_.LeLongTermKeyRequestNegativeReply(handle);

  send_event_(
      bluetooth::hci::LeLongTermKeyRequestNegativeReplyCompleteBuilder::Create(
          kNumCommandPackets, status, handle));
}

void DualModeController::ReadClassOfDevice(CommandView command) {
  auto command_view = bluetooth::hci::ReadClassOfDeviceView::Create(
      bluetooth::hci::DiscoveryCommandView::Create(command));
  ASSERT(command_view.IsValid());

  send_event_(bluetooth::hci::ReadClassOfDeviceCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      link_layer_controller_.GetClassOfDevice()));
}

void DualModeController::ReadVoiceSetting(CommandView command) {
  auto command_view = bluetooth::hci::ReadVoiceSettingView::Create(command);
  ASSERT(command_view.IsValid());

  send_event_(bluetooth::hci::ReadVoiceSettingCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS,
      link_layer_controller_.GetVoiceSetting()));
}

void DualModeController::ReadConnectionAcceptTimeout(CommandView command) {
  auto command_view = bluetooth::hci::ReadConnectionAcceptTimeoutView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  send_event_(
      bluetooth::hci::ReadConnectionAcceptTimeoutCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS,
          link_layer_controller_.GetConnectionAcceptTimeout()));
}

void DualModeController::WriteConnectionAcceptTimeout(CommandView command) {
  auto command_view = bluetooth::hci::WriteConnectionAcceptTimeoutView::Create(
      bluetooth::hci::ConnectionManagementCommandView::Create(
          bluetooth::hci::AclCommandView::Create(command)));
  ASSERT(command_view.IsValid());

  link_layer_controller_.SetConnectionAcceptTimeout(
      command_view.GetConnAcceptTimeout());

  send_event_(
      bluetooth::hci::WriteConnectionAcceptTimeoutCompleteBuilder::Create(
          kNumCommandPackets, ErrorCode::SUCCESS));
}

void DualModeController::ReadLoopbackMode(CommandView command) {
  auto command_view = bluetooth::hci::ReadLoopbackModeView::Create(command);
  ASSERT(command_view.IsValid());
  send_event_(bluetooth::hci::ReadLoopbackModeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS, loopback_mode_));
}

void DualModeController::WriteLoopbackMode(CommandView command) {
  auto command_view = bluetooth::hci::WriteLoopbackModeView::Create(command);
  ASSERT(command_view.IsValid());
  loopback_mode_ = command_view.GetLoopbackMode();
  // ACL channel
  uint16_t acl_handle = 0x123;
  send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS, acl_handle, GetAddress(),
      bluetooth::hci::LinkType::ACL, bluetooth::hci::Enable::DISABLED));
  // SCO channel
  uint16_t sco_handle = 0x345;
  send_event_(bluetooth::hci::ConnectionCompleteBuilder::Create(
      ErrorCode::SUCCESS, sco_handle, GetAddress(),
      bluetooth::hci::LinkType::SCO, bluetooth::hci::Enable::DISABLED));
  send_event_(bluetooth::hci::WriteLoopbackModeCompleteBuilder::Create(
      kNumCommandPackets, ErrorCode::SUCCESS));
}

// Note: the list does not contain all defined opcodes.
// Notable exceptions:
// - Vendor commands
// - Read Local Supported Commands command
const std::unordered_map<OpCode, OpCodeIndex>
    DualModeController::hci_command_op_code_to_index_{
        // LINK_CONTROL
        {OpCode::INQUIRY, OpCodeIndex::INQUIRY},
        {OpCode::INQUIRY_CANCEL, OpCodeIndex::INQUIRY_CANCEL},
        {OpCode::PERIODIC_INQUIRY_MODE, OpCodeIndex::PERIODIC_INQUIRY_MODE},
        {OpCode::EXIT_PERIODIC_INQUIRY_MODE,
         OpCodeIndex::EXIT_PERIODIC_INQUIRY_MODE},
        {OpCode::CREATE_CONNECTION, OpCodeIndex::CREATE_CONNECTION},
        {OpCode::DISCONNECT, OpCodeIndex::DISCONNECT},
        {OpCode::ADD_SCO_CONNECTION, OpCodeIndex::ADD_SCO_CONNECTION},
        {OpCode::CREATE_CONNECTION_CANCEL,
         OpCodeIndex::CREATE_CONNECTION_CANCEL},
        {OpCode::ACCEPT_CONNECTION_REQUEST,
         OpCodeIndex::ACCEPT_CONNECTION_REQUEST},
        {OpCode::REJECT_CONNECTION_REQUEST,
         OpCodeIndex::REJECT_CONNECTION_REQUEST},
        {OpCode::LINK_KEY_REQUEST_REPLY, OpCodeIndex::LINK_KEY_REQUEST_REPLY},
        {OpCode::LINK_KEY_REQUEST_NEGATIVE_REPLY,
         OpCodeIndex::LINK_KEY_REQUEST_NEGATIVE_REPLY},
        {OpCode::PIN_CODE_REQUEST_REPLY, OpCodeIndex::PIN_CODE_REQUEST_REPLY},
        {OpCode::PIN_CODE_REQUEST_NEGATIVE_REPLY,
         OpCodeIndex::PIN_CODE_REQUEST_NEGATIVE_REPLY},
        {OpCode::CHANGE_CONNECTION_PACKET_TYPE,
         OpCodeIndex::CHANGE_CONNECTION_PACKET_TYPE},
        {OpCode::AUTHENTICATION_REQUESTED,
         OpCodeIndex::AUTHENTICATION_REQUESTED},
        {OpCode::SET_CONNECTION_ENCRYPTION,
         OpCodeIndex::SET_CONNECTION_ENCRYPTION},
        {OpCode::CHANGE_CONNECTION_LINK_KEY,
         OpCodeIndex::CHANGE_CONNECTION_LINK_KEY},
        {OpCode::CENTRAL_LINK_KEY, OpCodeIndex::CENTRAL_LINK_KEY},
        {OpCode::REMOTE_NAME_REQUEST, OpCodeIndex::REMOTE_NAME_REQUEST},
        {OpCode::REMOTE_NAME_REQUEST_CANCEL,
         OpCodeIndex::REMOTE_NAME_REQUEST_CANCEL},
        {OpCode::READ_REMOTE_SUPPORTED_FEATURES,
         OpCodeIndex::READ_REMOTE_SUPPORTED_FEATURES},
        {OpCode::READ_REMOTE_EXTENDED_FEATURES,
         OpCodeIndex::READ_REMOTE_EXTENDED_FEATURES},
        {OpCode::READ_REMOTE_VERSION_INFORMATION,
         OpCodeIndex::READ_REMOTE_VERSION_INFORMATION},
        {OpCode::READ_CLOCK_OFFSET, OpCodeIndex::READ_CLOCK_OFFSET},
        {OpCode::READ_LMP_HANDLE, OpCodeIndex::READ_LMP_HANDLE},
        {OpCode::SETUP_SYNCHRONOUS_CONNECTION,
         OpCodeIndex::SETUP_SYNCHRONOUS_CONNECTION},
        {OpCode::ACCEPT_SYNCHRONOUS_CONNECTION,
         OpCodeIndex::ACCEPT_SYNCHRONOUS_CONNECTION},
        {OpCode::REJECT_SYNCHRONOUS_CONNECTION,
         OpCodeIndex::REJECT_SYNCHRONOUS_CONNECTION},
        {OpCode::IO_CAPABILITY_REQUEST_REPLY,
         OpCodeIndex::IO_CAPABILITY_REQUEST_REPLY},
        {OpCode::USER_CONFIRMATION_REQUEST_REPLY,
         OpCodeIndex::USER_CONFIRMATION_REQUEST_REPLY},
        {OpCode::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY,
         OpCodeIndex::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY},
        {OpCode::USER_PASSKEY_REQUEST_REPLY,
         OpCodeIndex::USER_PASSKEY_REQUEST_REPLY},
        {OpCode::USER_PASSKEY_REQUEST_NEGATIVE_REPLY,
         OpCodeIndex::USER_PASSKEY_REQUEST_NEGATIVE_REPLY},
        {OpCode::REMOTE_OOB_DATA_REQUEST_REPLY,
         OpCodeIndex::REMOTE_OOB_DATA_REQUEST_REPLY},
        {OpCode::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY,
         OpCodeIndex::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY},
        {OpCode::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY,
         OpCodeIndex::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY},
        {OpCode::ENHANCED_SETUP_SYNCHRONOUS_CONNECTION,
         OpCodeIndex::ENHANCED_SETUP_SYNCHRONOUS_CONNECTION},
        {OpCode::ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION,
         OpCodeIndex::ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION},
        {OpCode::TRUNCATED_PAGE, OpCodeIndex::TRUNCATED_PAGE},
        {OpCode::TRUNCATED_PAGE_CANCEL, OpCodeIndex::TRUNCATED_PAGE_CANCEL},
        {OpCode::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST,
         OpCodeIndex::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST},
        {OpCode::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE,
         OpCodeIndex::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE},
        {OpCode::START_SYNCHRONIZATION_TRAIN,
         OpCodeIndex::START_SYNCHRONIZATION_TRAIN},
        {OpCode::RECEIVE_SYNCHRONIZATION_TRAIN,
         OpCodeIndex::RECEIVE_SYNCHRONIZATION_TRAIN},
        {OpCode::REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY,
         OpCodeIndex::REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY},

        // LINK_POLICY
        {OpCode::HOLD_MODE, OpCodeIndex::HOLD_MODE},
        {OpCode::SNIFF_MODE, OpCodeIndex::SNIFF_MODE},
        {OpCode::EXIT_SNIFF_MODE, OpCodeIndex::EXIT_SNIFF_MODE},
        {OpCode::QOS_SETUP, OpCodeIndex::QOS_SETUP},
        {OpCode::ROLE_DISCOVERY, OpCodeIndex::ROLE_DISCOVERY},
        {OpCode::SWITCH_ROLE, OpCodeIndex::SWITCH_ROLE},
        {OpCode::READ_LINK_POLICY_SETTINGS,
         OpCodeIndex::READ_LINK_POLICY_SETTINGS},
        {OpCode::WRITE_LINK_POLICY_SETTINGS,
         OpCodeIndex::WRITE_LINK_POLICY_SETTINGS},
        {OpCode::READ_DEFAULT_LINK_POLICY_SETTINGS,
         OpCodeIndex::READ_DEFAULT_LINK_POLICY_SETTINGS},
        {OpCode::WRITE_DEFAULT_LINK_POLICY_SETTINGS,
         OpCodeIndex::WRITE_DEFAULT_LINK_POLICY_SETTINGS},
        {OpCode::FLOW_SPECIFICATION, OpCodeIndex::FLOW_SPECIFICATION},
        {OpCode::SNIFF_SUBRATING, OpCodeIndex::SNIFF_SUBRATING},

        // CONTROLLER_AND_BASEBAND
        {OpCode::SET_EVENT_MASK, OpCodeIndex::SET_EVENT_MASK},
        {OpCode::RESET, OpCodeIndex::RESET},
        {OpCode::SET_EVENT_FILTER, OpCodeIndex::SET_EVENT_FILTER},
        {OpCode::FLUSH, OpCodeIndex::FLUSH},
        {OpCode::READ_PIN_TYPE, OpCodeIndex::READ_PIN_TYPE},
        {OpCode::WRITE_PIN_TYPE, OpCodeIndex::WRITE_PIN_TYPE},
        {OpCode::READ_STORED_LINK_KEY, OpCodeIndex::READ_STORED_LINK_KEY},
        {OpCode::WRITE_STORED_LINK_KEY, OpCodeIndex::WRITE_STORED_LINK_KEY},
        {OpCode::DELETE_STORED_LINK_KEY, OpCodeIndex::DELETE_STORED_LINK_KEY},
        {OpCode::WRITE_LOCAL_NAME, OpCodeIndex::WRITE_LOCAL_NAME},
        {OpCode::READ_LOCAL_NAME, OpCodeIndex::READ_LOCAL_NAME},
        {OpCode::READ_CONNECTION_ACCEPT_TIMEOUT,
         OpCodeIndex::READ_CONNECTION_ACCEPT_TIMEOUT},
        {OpCode::WRITE_CONNECTION_ACCEPT_TIMEOUT,
         OpCodeIndex::WRITE_CONNECTION_ACCEPT_TIMEOUT},
        {OpCode::READ_PAGE_TIMEOUT, OpCodeIndex::READ_PAGE_TIMEOUT},
        {OpCode::WRITE_PAGE_TIMEOUT, OpCodeIndex::WRITE_PAGE_TIMEOUT},
        {OpCode::READ_SCAN_ENABLE, OpCodeIndex::READ_SCAN_ENABLE},
        {OpCode::WRITE_SCAN_ENABLE, OpCodeIndex::WRITE_SCAN_ENABLE},
        {OpCode::READ_PAGE_SCAN_ACTIVITY, OpCodeIndex::READ_PAGE_SCAN_ACTIVITY},
        {OpCode::WRITE_PAGE_SCAN_ACTIVITY,
         OpCodeIndex::WRITE_PAGE_SCAN_ACTIVITY},
        {OpCode::READ_INQUIRY_SCAN_ACTIVITY,
         OpCodeIndex::READ_INQUIRY_SCAN_ACTIVITY},
        {OpCode::WRITE_INQUIRY_SCAN_ACTIVITY,
         OpCodeIndex::WRITE_INQUIRY_SCAN_ACTIVITY},
        {OpCode::READ_AUTHENTICATION_ENABLE,
         OpCodeIndex::READ_AUTHENTICATION_ENABLE},
        {OpCode::WRITE_AUTHENTICATION_ENABLE,
         OpCodeIndex::WRITE_AUTHENTICATION_ENABLE},
        {OpCode::READ_CLASS_OF_DEVICE, OpCodeIndex::READ_CLASS_OF_DEVICE},
        {OpCode::WRITE_CLASS_OF_DEVICE, OpCodeIndex::WRITE_CLASS_OF_DEVICE},
        {OpCode::READ_VOICE_SETTING, OpCodeIndex::READ_VOICE_SETTING},
        {OpCode::WRITE_VOICE_SETTING, OpCodeIndex::WRITE_VOICE_SETTING},
        {OpCode::READ_AUTOMATIC_FLUSH_TIMEOUT,
         OpCodeIndex::READ_AUTOMATIC_FLUSH_TIMEOUT},
        {OpCode::WRITE_AUTOMATIC_FLUSH_TIMEOUT,
         OpCodeIndex::WRITE_AUTOMATIC_FLUSH_TIMEOUT},
        {OpCode::READ_NUM_BROADCAST_RETRANSMITS,
         OpCodeIndex::READ_NUM_BROADCAST_RETRANSMITS},
        {OpCode::WRITE_NUM_BROADCAST_RETRANSMITS,
         OpCodeIndex::WRITE_NUM_BROADCAST_RETRANSMITS},
        {OpCode::READ_HOLD_MODE_ACTIVITY, OpCodeIndex::READ_HOLD_MODE_ACTIVITY},
        {OpCode::WRITE_HOLD_MODE_ACTIVITY,
         OpCodeIndex::WRITE_HOLD_MODE_ACTIVITY},
        {OpCode::READ_TRANSMIT_POWER_LEVEL,
         OpCodeIndex::READ_TRANSMIT_POWER_LEVEL},
        {OpCode::READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE,
         OpCodeIndex::READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE},
        {OpCode::WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE,
         OpCodeIndex::WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE},
        {OpCode::SET_CONTROLLER_TO_HOST_FLOW_CONTROL,
         OpCodeIndex::SET_CONTROLLER_TO_HOST_FLOW_CONTROL},
        {OpCode::HOST_BUFFER_SIZE, OpCodeIndex::HOST_BUFFER_SIZE},
        {OpCode::HOST_NUMBER_OF_COMPLETED_PACKETS,
         OpCodeIndex::HOST_NUMBER_OF_COMPLETED_PACKETS},
        {OpCode::READ_LINK_SUPERVISION_TIMEOUT,
         OpCodeIndex::READ_LINK_SUPERVISION_TIMEOUT},
        {OpCode::WRITE_LINK_SUPERVISION_TIMEOUT,
         OpCodeIndex::WRITE_LINK_SUPERVISION_TIMEOUT},
        {OpCode::READ_NUMBER_OF_SUPPORTED_IAC,
         OpCodeIndex::READ_NUMBER_OF_SUPPORTED_IAC},
        {OpCode::READ_CURRENT_IAC_LAP, OpCodeIndex::READ_CURRENT_IAC_LAP},
        {OpCode::WRITE_CURRENT_IAC_LAP, OpCodeIndex::WRITE_CURRENT_IAC_LAP},
        {OpCode::SET_AFH_HOST_CHANNEL_CLASSIFICATION,
         OpCodeIndex::SET_AFH_HOST_CHANNEL_CLASSIFICATION},
        {OpCode::READ_INQUIRY_SCAN_TYPE, OpCodeIndex::READ_INQUIRY_SCAN_TYPE},
        {OpCode::WRITE_INQUIRY_SCAN_TYPE, OpCodeIndex::WRITE_INQUIRY_SCAN_TYPE},
        {OpCode::READ_INQUIRY_MODE, OpCodeIndex::READ_INQUIRY_MODE},
        {OpCode::WRITE_INQUIRY_MODE, OpCodeIndex::WRITE_INQUIRY_MODE},
        {OpCode::READ_PAGE_SCAN_TYPE, OpCodeIndex::READ_PAGE_SCAN_TYPE},
        {OpCode::WRITE_PAGE_SCAN_TYPE, OpCodeIndex::WRITE_PAGE_SCAN_TYPE},
        {OpCode::READ_AFH_CHANNEL_ASSESSMENT_MODE,
         OpCodeIndex::READ_AFH_CHANNEL_ASSESSMENT_MODE},
        {OpCode::WRITE_AFH_CHANNEL_ASSESSMENT_MODE,
         OpCodeIndex::WRITE_AFH_CHANNEL_ASSESSMENT_MODE},
        {OpCode::READ_EXTENDED_INQUIRY_RESPONSE,
         OpCodeIndex::READ_EXTENDED_INQUIRY_RESPONSE},
        {OpCode::WRITE_EXTENDED_INQUIRY_RESPONSE,
         OpCodeIndex::WRITE_EXTENDED_INQUIRY_RESPONSE},
        {OpCode::REFRESH_ENCRYPTION_KEY, OpCodeIndex::REFRESH_ENCRYPTION_KEY},
        {OpCode::READ_SIMPLE_PAIRING_MODE,
         OpCodeIndex::READ_SIMPLE_PAIRING_MODE},
        {OpCode::WRITE_SIMPLE_PAIRING_MODE,
         OpCodeIndex::WRITE_SIMPLE_PAIRING_MODE},
        {OpCode::READ_LOCAL_OOB_DATA, OpCodeIndex::READ_LOCAL_OOB_DATA},
        {OpCode::READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL,
         OpCodeIndex::READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL},
        {OpCode::WRITE_INQUIRY_TRANSMIT_POWER_LEVEL,
         OpCodeIndex::WRITE_INQUIRY_TRANSMIT_POWER_LEVEL},
        {OpCode::READ_DEFAULT_ERRONEOUS_DATA_REPORTING,
         OpCodeIndex::READ_DEFAULT_ERRONEOUS_DATA_REPORTING},
        {OpCode::WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING,
         OpCodeIndex::WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING},
        {OpCode::ENHANCED_FLUSH, OpCodeIndex::ENHANCED_FLUSH},
        {OpCode::SEND_KEYPRESS_NOTIFICATION,
         OpCodeIndex::SEND_KEYPRESS_NOTIFICATION},
        {OpCode::SET_EVENT_MASK_PAGE_2, OpCodeIndex::SET_EVENT_MASK_PAGE_2},
        {OpCode::READ_FLOW_CONTROL_MODE, OpCodeIndex::READ_FLOW_CONTROL_MODE},
        {OpCode::WRITE_FLOW_CONTROL_MODE, OpCodeIndex::WRITE_FLOW_CONTROL_MODE},
        {OpCode::READ_ENHANCED_TRANSMIT_POWER_LEVEL,
         OpCodeIndex::READ_ENHANCED_TRANSMIT_POWER_LEVEL},
        {OpCode::READ_LE_HOST_SUPPORT, OpCodeIndex::READ_LE_HOST_SUPPORT},
        {OpCode::WRITE_LE_HOST_SUPPORT, OpCodeIndex::WRITE_LE_HOST_SUPPORT},
        {OpCode::SET_MWS_CHANNEL_PARAMETERS,
         OpCodeIndex::SET_MWS_CHANNEL_PARAMETERS},
        {OpCode::SET_EXTERNAL_FRAME_CONFIGURATION,
         OpCodeIndex::SET_EXTERNAL_FRAME_CONFIGURATION},
        {OpCode::SET_MWS_SIGNALING, OpCodeIndex::SET_MWS_SIGNALING},
        {OpCode::SET_MWS_TRANSPORT_LAYER, OpCodeIndex::SET_MWS_TRANSPORT_LAYER},
        {OpCode::SET_MWS_SCAN_FREQUENCY_TABLE,
         OpCodeIndex::SET_MWS_SCAN_FREQUENCY_TABLE},
        {OpCode::SET_MWS_PATTERN_CONFIGURATION,
         OpCodeIndex::SET_MWS_PATTERN_CONFIGURATION},
        {OpCode::SET_RESERVED_LT_ADDR, OpCodeIndex::SET_RESERVED_LT_ADDR},
        {OpCode::DELETE_RESERVED_LT_ADDR, OpCodeIndex::DELETE_RESERVED_LT_ADDR},
        {OpCode::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA,
         OpCodeIndex::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA},
        {OpCode::READ_SYNCHRONIZATION_TRAIN_PARAMETERS,
         OpCodeIndex::READ_SYNCHRONIZATION_TRAIN_PARAMETERS},
        {OpCode::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS,
         OpCodeIndex::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS},
        {OpCode::READ_SECURE_CONNECTIONS_HOST_SUPPORT,
         OpCodeIndex::READ_SECURE_CONNECTIONS_HOST_SUPPORT},
        {OpCode::WRITE_SECURE_CONNECTIONS_HOST_SUPPORT,
         OpCodeIndex::WRITE_SECURE_CONNECTIONS_HOST_SUPPORT},
        {OpCode::READ_AUTHENTICATED_PAYLOAD_TIMEOUT,
         OpCodeIndex::READ_AUTHENTICATED_PAYLOAD_TIMEOUT},
        {OpCode::WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT,
         OpCodeIndex::WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT},
        {OpCode::READ_LOCAL_OOB_EXTENDED_DATA,
         OpCodeIndex::READ_LOCAL_OOB_EXTENDED_DATA},
        {OpCode::READ_EXTENDED_PAGE_TIMEOUT,
         OpCodeIndex::READ_EXTENDED_PAGE_TIMEOUT},
        {OpCode::WRITE_EXTENDED_PAGE_TIMEOUT,
         OpCodeIndex::WRITE_EXTENDED_PAGE_TIMEOUT},
        {OpCode::READ_EXTENDED_INQUIRY_LENGTH,
         OpCodeIndex::READ_EXTENDED_INQUIRY_LENGTH},
        {OpCode::WRITE_EXTENDED_INQUIRY_LENGTH,
         OpCodeIndex::WRITE_EXTENDED_INQUIRY_LENGTH},
        {OpCode::SET_ECOSYSTEM_BASE_INTERVAL,
         OpCodeIndex::SET_ECOSYSTEM_BASE_INTERVAL},
        {OpCode::CONFIGURE_DATA_PATH, OpCodeIndex::CONFIGURE_DATA_PATH},
        {OpCode::SET_MIN_ENCRYPTION_KEY_SIZE,
         OpCodeIndex::SET_MIN_ENCRYPTION_KEY_SIZE},

        // INFORMATIONAL_PARAMETERS
        {OpCode::READ_LOCAL_VERSION_INFORMATION,
         OpCodeIndex::READ_LOCAL_VERSION_INFORMATION},
        {OpCode::READ_LOCAL_SUPPORTED_FEATURES,
         OpCodeIndex::READ_LOCAL_SUPPORTED_FEATURES},
        {OpCode::READ_LOCAL_EXTENDED_FEATURES,
         OpCodeIndex::READ_LOCAL_EXTENDED_FEATURES},
        {OpCode::READ_BUFFER_SIZE, OpCodeIndex::READ_BUFFER_SIZE},
        {OpCode::READ_BD_ADDR, OpCodeIndex::READ_BD_ADDR},
        {OpCode::READ_DATA_BLOCK_SIZE, OpCodeIndex::READ_DATA_BLOCK_SIZE},
        {OpCode::READ_LOCAL_SUPPORTED_CODECS_V1,
         OpCodeIndex::READ_LOCAL_SUPPORTED_CODECS_V1},
        {OpCode::READ_LOCAL_SIMPLE_PAIRING_OPTIONS,
         OpCodeIndex::READ_LOCAL_SIMPLE_PAIRING_OPTIONS},
        {OpCode::READ_LOCAL_SUPPORTED_CODECS_V2,
         OpCodeIndex::READ_LOCAL_SUPPORTED_CODECS_V2},
        {OpCode::READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES,
         OpCodeIndex::READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES},
        {OpCode::READ_LOCAL_SUPPORTED_CONTROLLER_DELAY,
         OpCodeIndex::READ_LOCAL_SUPPORTED_CONTROLLER_DELAY},

        // STATUS_PARAMETERS
        {OpCode::READ_FAILED_CONTACT_COUNTER,
         OpCodeIndex::READ_FAILED_CONTACT_COUNTER},
        {OpCode::RESET_FAILED_CONTACT_COUNTER,
         OpCodeIndex::RESET_FAILED_CONTACT_COUNTER},
        {OpCode::READ_LINK_QUALITY, OpCodeIndex::READ_LINK_QUALITY},
        {OpCode::READ_RSSI, OpCodeIndex::READ_RSSI},
        {OpCode::READ_AFH_CHANNEL_MAP, OpCodeIndex::READ_AFH_CHANNEL_MAP},
        {OpCode::READ_CLOCK, OpCodeIndex::READ_CLOCK},
        {OpCode::READ_ENCRYPTION_KEY_SIZE,
         OpCodeIndex::READ_ENCRYPTION_KEY_SIZE},
        {OpCode::GET_MWS_TRANSPORT_LAYER_CONFIGURATION,
         OpCodeIndex::GET_MWS_TRANSPORT_LAYER_CONFIGURATION},
        {OpCode::SET_TRIGGERED_CLOCK_CAPTURE,
         OpCodeIndex::SET_TRIGGERED_CLOCK_CAPTURE},

        // TESTING
        {OpCode::READ_LOOPBACK_MODE, OpCodeIndex::READ_LOOPBACK_MODE},
        {OpCode::WRITE_LOOPBACK_MODE, OpCodeIndex::WRITE_LOOPBACK_MODE},
        {OpCode::ENABLE_DEVICE_UNDER_TEST_MODE,
         OpCodeIndex::ENABLE_DEVICE_UNDER_TEST_MODE},
        {OpCode::WRITE_SIMPLE_PAIRING_DEBUG_MODE,
         OpCodeIndex::WRITE_SIMPLE_PAIRING_DEBUG_MODE},
        {OpCode::WRITE_SECURE_CONNECTIONS_TEST_MODE,
         OpCodeIndex::WRITE_SECURE_CONNECTIONS_TEST_MODE},

        // LE_CONTROLLER
        {OpCode::LE_SET_EVENT_MASK, OpCodeIndex::LE_SET_EVENT_MASK},
        {OpCode::LE_READ_BUFFER_SIZE_V1, OpCodeIndex::LE_READ_BUFFER_SIZE_V1},
        {OpCode::LE_READ_LOCAL_SUPPORTED_FEATURES,
         OpCodeIndex::LE_READ_LOCAL_SUPPORTED_FEATURES},
        {OpCode::LE_SET_RANDOM_ADDRESS, OpCodeIndex::LE_SET_RANDOM_ADDRESS},
        {OpCode::LE_SET_ADVERTISING_PARAMETERS,
         OpCodeIndex::LE_SET_ADVERTISING_PARAMETERS},
        {OpCode::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER,
         OpCodeIndex::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER},
        {OpCode::LE_SET_ADVERTISING_DATA, OpCodeIndex::LE_SET_ADVERTISING_DATA},
        {OpCode::LE_SET_SCAN_RESPONSE_DATA,
         OpCodeIndex::LE_SET_SCAN_RESPONSE_DATA},
        {OpCode::LE_SET_ADVERTISING_ENABLE,
         OpCodeIndex::LE_SET_ADVERTISING_ENABLE},
        {OpCode::LE_SET_SCAN_PARAMETERS, OpCodeIndex::LE_SET_SCAN_PARAMETERS},
        {OpCode::LE_SET_SCAN_ENABLE, OpCodeIndex::LE_SET_SCAN_ENABLE},
        {OpCode::LE_CREATE_CONNECTION, OpCodeIndex::LE_CREATE_CONNECTION},
        {OpCode::LE_CREATE_CONNECTION_CANCEL,
         OpCodeIndex::LE_CREATE_CONNECTION_CANCEL},
        {OpCode::LE_READ_FILTER_ACCEPT_LIST_SIZE,
         OpCodeIndex::LE_READ_FILTER_ACCEPT_LIST_SIZE},
        {OpCode::LE_CLEAR_FILTER_ACCEPT_LIST,
         OpCodeIndex::LE_CLEAR_FILTER_ACCEPT_LIST},
        {OpCode::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST,
         OpCodeIndex::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST},
        {OpCode::LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST,
         OpCodeIndex::LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST},
        {OpCode::LE_CONNECTION_UPDATE, OpCodeIndex::LE_CONNECTION_UPDATE},
        {OpCode::LE_SET_HOST_CHANNEL_CLASSIFICATION,
         OpCodeIndex::LE_SET_HOST_CHANNEL_CLASSIFICATION},
        {OpCode::LE_READ_CHANNEL_MAP, OpCodeIndex::LE_READ_CHANNEL_MAP},
        {OpCode::LE_READ_REMOTE_FEATURES, OpCodeIndex::LE_READ_REMOTE_FEATURES},
        {OpCode::LE_ENCRYPT, OpCodeIndex::LE_ENCRYPT},
        {OpCode::LE_RAND, OpCodeIndex::LE_RAND},
        {OpCode::LE_START_ENCRYPTION, OpCodeIndex::LE_START_ENCRYPTION},
        {OpCode::LE_LONG_TERM_KEY_REQUEST_REPLY,
         OpCodeIndex::LE_LONG_TERM_KEY_REQUEST_REPLY},
        {OpCode::LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY,
         OpCodeIndex::LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY},
        {OpCode::LE_READ_SUPPORTED_STATES,
         OpCodeIndex::LE_READ_SUPPORTED_STATES},
        {OpCode::LE_RECEIVER_TEST_V1, OpCodeIndex::LE_RECEIVER_TEST_V1},
        {OpCode::LE_TRANSMITTER_TEST_V1, OpCodeIndex::LE_TRANSMITTER_TEST_V1},
        {OpCode::LE_TEST_END, OpCodeIndex::LE_TEST_END},
        {OpCode::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY,
         OpCodeIndex::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY},
        {OpCode::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY,
         OpCodeIndex::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY},
        {OpCode::LE_SET_DATA_LENGTH, OpCodeIndex::LE_SET_DATA_LENGTH},
        {OpCode::LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH,
         OpCodeIndex::LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH},
        {OpCode::LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH,
         OpCodeIndex::LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH},
        {OpCode::LE_READ_LOCAL_P_256_PUBLIC_KEY,
         OpCodeIndex::LE_READ_LOCAL_P_256_PUBLIC_KEY},
        {OpCode::LE_GENERATE_DHKEY_V1, OpCodeIndex::LE_GENERATE_DHKEY_V1},
        {OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST,
         OpCodeIndex::LE_ADD_DEVICE_TO_RESOLVING_LIST},
        {OpCode::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST,
         OpCodeIndex::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST},
        {OpCode::LE_CLEAR_RESOLVING_LIST, OpCodeIndex::LE_CLEAR_RESOLVING_LIST},
        {OpCode::LE_READ_RESOLVING_LIST_SIZE,
         OpCodeIndex::LE_READ_RESOLVING_LIST_SIZE},
        {OpCode::LE_READ_PEER_RESOLVABLE_ADDRESS,
         OpCodeIndex::LE_READ_PEER_RESOLVABLE_ADDRESS},
        {OpCode::LE_READ_LOCAL_RESOLVABLE_ADDRESS,
         OpCodeIndex::LE_READ_LOCAL_RESOLVABLE_ADDRESS},
        {OpCode::LE_SET_ADDRESS_RESOLUTION_ENABLE,
         OpCodeIndex::LE_SET_ADDRESS_RESOLUTION_ENABLE},
        {OpCode::LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT,
         OpCodeIndex::LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT},
        {OpCode::LE_READ_MAXIMUM_DATA_LENGTH,
         OpCodeIndex::LE_READ_MAXIMUM_DATA_LENGTH},
        {OpCode::LE_READ_PHY, OpCodeIndex::LE_READ_PHY},
        {OpCode::LE_SET_DEFAULT_PHY, OpCodeIndex::LE_SET_DEFAULT_PHY},
        {OpCode::LE_SET_PHY, OpCodeIndex::LE_SET_PHY},
        {OpCode::LE_RECEIVER_TEST_V2, OpCodeIndex::LE_RECEIVER_TEST_V2},
        {OpCode::LE_TRANSMITTER_TEST_V2, OpCodeIndex::LE_TRANSMITTER_TEST_V2},
        {OpCode::LE_SET_ADVERTISING_SET_RANDOM_ADDRESS,
         OpCodeIndex::LE_SET_ADVERTISING_SET_RANDOM_ADDRESS},
        {OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
         OpCodeIndex::LE_SET_EXTENDED_ADVERTISING_PARAMETERS},
        {OpCode::LE_SET_EXTENDED_ADVERTISING_DATA,
         OpCodeIndex::LE_SET_EXTENDED_ADVERTISING_DATA},
        {OpCode::LE_SET_EXTENDED_SCAN_RESPONSE_DATA,
         OpCodeIndex::LE_SET_EXTENDED_SCAN_RESPONSE_DATA},
        {OpCode::LE_SET_EXTENDED_ADVERTISING_ENABLE,
         OpCodeIndex::LE_SET_EXTENDED_ADVERTISING_ENABLE},
        {OpCode::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH,
         OpCodeIndex::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH},
        {OpCode::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS,
         OpCodeIndex::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS},
        {OpCode::LE_REMOVE_ADVERTISING_SET,
         OpCodeIndex::LE_REMOVE_ADVERTISING_SET},
        {OpCode::LE_CLEAR_ADVERTISING_SETS,
         OpCodeIndex::LE_CLEAR_ADVERTISING_SETS},
        {OpCode::LE_SET_PERIODIC_ADVERTISING_PARAM,
         OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_PARAM},
        {OpCode::LE_SET_PERIODIC_ADVERTISING_DATA,
         OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_DATA},
        {OpCode::LE_SET_PERIODIC_ADVERTISING_ENABLE,
         OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_ENABLE},
        {OpCode::LE_SET_EXTENDED_SCAN_PARAMETERS,
         OpCodeIndex::LE_SET_EXTENDED_SCAN_PARAMETERS},
        {OpCode::LE_SET_EXTENDED_SCAN_ENABLE,
         OpCodeIndex::LE_SET_EXTENDED_SCAN_ENABLE},
        {OpCode::LE_EXTENDED_CREATE_CONNECTION,
         OpCodeIndex::LE_EXTENDED_CREATE_CONNECTION},
        {OpCode::LE_PERIODIC_ADVERTISING_CREATE_SYNC,
         OpCodeIndex::LE_PERIODIC_ADVERTISING_CREATE_SYNC},
        {OpCode::LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL,
         OpCodeIndex::LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL},
        {OpCode::LE_PERIODIC_ADVERTISING_TERMINATE_SYNC,
         OpCodeIndex::LE_PERIODIC_ADVERTISING_TERMINATE_SYNC},
        {OpCode::LE_ADD_DEVICE_TO_PERIODIC_ADVERTISING_LIST,
         OpCodeIndex::LE_ADD_DEVICE_TO_PERIODIC_ADVERTISING_LIST},
        {OpCode::LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISING_LIST,
         OpCodeIndex::LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISING_LIST},
        {OpCode::LE_CLEAR_PERIODIC_ADVERTISING_LIST,
         OpCodeIndex::LE_CLEAR_PERIODIC_ADVERTISING_LIST},
        {OpCode::LE_READ_PERIODIC_ADVERTISING_LIST_SIZE,
         OpCodeIndex::LE_READ_PERIODIC_ADVERTISING_LIST_SIZE},
        {OpCode::LE_READ_TRANSMIT_POWER, OpCodeIndex::LE_READ_TRANSMIT_POWER},
        {OpCode::LE_READ_RF_PATH_COMPENSATION_POWER,
         OpCodeIndex::LE_READ_RF_PATH_COMPENSATION_POWER},
        {OpCode::LE_WRITE_RF_PATH_COMPENSATION_POWER,
         OpCodeIndex::LE_WRITE_RF_PATH_COMPENSATION_POWER},
        {OpCode::LE_SET_PRIVACY_MODE, OpCodeIndex::LE_SET_PRIVACY_MODE},
        {OpCode::LE_RECEIVER_TEST_V3, OpCodeIndex::LE_RECEIVER_TEST_V3},
        {OpCode::LE_TRANSMITTER_TEST_V3, OpCodeIndex::LE_TRANSMITTER_TEST_V3},
        {OpCode::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS,
         OpCodeIndex::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS},
        {OpCode::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE,
         OpCodeIndex::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE},
        {OpCode::LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE,
         OpCodeIndex::LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE},
        {OpCode::LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS,
         OpCodeIndex::LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS},
        {OpCode::LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS,
         OpCodeIndex::LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS},
        {OpCode::LE_CONNECTION_CTE_REQUEST_ENABLE,
         OpCodeIndex::LE_CONNECTION_CTE_REQUEST_ENABLE},
        {OpCode::LE_CONNECTION_CTE_RESPONSE_ENABLE,
         OpCodeIndex::LE_CONNECTION_CTE_RESPONSE_ENABLE},
        {OpCode::LE_READ_ANTENNA_INFORMATION,
         OpCodeIndex::LE_READ_ANTENNA_INFORMATION},
        {OpCode::LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE,
         OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE},
        {OpCode::LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
         OpCodeIndex::LE_PERIODIC_ADVERTISING_SYNC_TRANSFER},
        {OpCode::LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER,
         OpCodeIndex::LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER},
        {OpCode::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
         OpCodeIndex::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS},
        {OpCode::LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
         OpCodeIndex::
             LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS},
        {OpCode::LE_GENERATE_DHKEY_V2, OpCodeIndex::LE_GENERATE_DHKEY_V2},
        {OpCode::LE_MODIFY_SLEEP_CLOCK_ACCURACY,
         OpCodeIndex::LE_MODIFY_SLEEP_CLOCK_ACCURACY},
        {OpCode::LE_READ_BUFFER_SIZE_V2, OpCodeIndex::LE_READ_BUFFER_SIZE_V2},
        {OpCode::LE_READ_ISO_TX_SYNC, OpCodeIndex::LE_READ_ISO_TX_SYNC},
        {OpCode::LE_SET_CIG_PARAMETERS, OpCodeIndex::LE_SET_CIG_PARAMETERS},
        {OpCode::LE_SET_CIG_PARAMETERS_TEST,
         OpCodeIndex::LE_SET_CIG_PARAMETERS_TEST},
        {OpCode::LE_CREATE_CIS, OpCodeIndex::LE_CREATE_CIS},
        {OpCode::LE_REMOVE_CIG, OpCodeIndex::LE_REMOVE_CIG},
        {OpCode::LE_ACCEPT_CIS_REQUEST, OpCodeIndex::LE_ACCEPT_CIS_REQUEST},
        {OpCode::LE_REJECT_CIS_REQUEST, OpCodeIndex::LE_REJECT_CIS_REQUEST},
        {OpCode::LE_CREATE_BIG, OpCodeIndex::LE_CREATE_BIG},
        {OpCode::LE_CREATE_BIG_TEST, OpCodeIndex::LE_CREATE_BIG_TEST},
        {OpCode::LE_TERMINATE_BIG, OpCodeIndex::LE_TERMINATE_BIG},
        {OpCode::LE_BIG_CREATE_SYNC, OpCodeIndex::LE_BIG_CREATE_SYNC},
        {OpCode::LE_BIG_TERMINATE_SYNC, OpCodeIndex::LE_BIG_TERMINATE_SYNC},
        {OpCode::LE_REQUEST_PEER_SCA, OpCodeIndex::LE_REQUEST_PEER_SCA},
        {OpCode::LE_SETUP_ISO_DATA_PATH, OpCodeIndex::LE_SETUP_ISO_DATA_PATH},
        {OpCode::LE_REMOVE_ISO_DATA_PATH, OpCodeIndex::LE_REMOVE_ISO_DATA_PATH},
        {OpCode::LE_ISO_TRANSMIT_TEST, OpCodeIndex::LE_ISO_TRANSMIT_TEST},
        {OpCode::LE_ISO_RECEIVE_TEST, OpCodeIndex::LE_ISO_RECEIVE_TEST},
        {OpCode::LE_ISO_READ_TEST_COUNTERS,
         OpCodeIndex::LE_ISO_READ_TEST_COUNTERS},
        {OpCode::LE_ISO_TEST_END, OpCodeIndex::LE_ISO_TEST_END},
        {OpCode::LE_SET_HOST_FEATURE, OpCodeIndex::LE_SET_HOST_FEATURE},
        {OpCode::LE_READ_ISO_LINK_QUALITY,
         OpCodeIndex::LE_READ_ISO_LINK_QUALITY},
        {OpCode::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL,
         OpCodeIndex::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL},
        {OpCode::LE_READ_REMOTE_TRANSMIT_POWER_LEVEL,
         OpCodeIndex::LE_READ_REMOTE_TRANSMIT_POWER_LEVEL},
        {OpCode::LE_SET_PATH_LOSS_REPORTING_PARAMETERS,
         OpCodeIndex::LE_SET_PATH_LOSS_REPORTING_PARAMETERS},
        {OpCode::LE_SET_PATH_LOSS_REPORTING_ENABLE,
         OpCodeIndex::LE_SET_PATH_LOSS_REPORTING_ENABLE},
        {OpCode::LE_SET_TRANSMIT_POWER_REPORTING_ENABLE,
         OpCodeIndex::LE_SET_TRANSMIT_POWER_REPORTING_ENABLE},
        {OpCode::LE_TRANSMITTER_TEST_V4, OpCodeIndex::LE_TRANSMITTER_TEST_V4},
        {OpCode::LE_SET_DATA_RELATED_ADDRESS_CHANGES,
         OpCodeIndex::LE_SET_DATA_RELATED_ADDRESS_CHANGES},
        {OpCode::LE_SET_DEFAULT_SUBRATE, OpCodeIndex::LE_SET_DEFAULT_SUBRATE},
        {OpCode::LE_SUBRATE_REQUEST, OpCodeIndex::LE_SUBRATE_REQUEST},
    };

const std::unordered_map<OpCode, DualModeController::CommandHandler>
    DualModeController::hci_command_handlers_{
        // LINK_CONTROL
        {OpCode::INQUIRY, &DualModeController::Inquiry},
        {OpCode::INQUIRY_CANCEL, &DualModeController::InquiryCancel},
        //{OpCode::PERIODIC_INQUIRY_MODE,
        //&DualModeController::PeriodicInquiryMode},
        //{OpCode::EXIT_PERIODIC_INQUIRY_MODE,
        //&DualModeController::ExitPeriodicInquiryMode},
        {OpCode::CREATE_CONNECTION, &DualModeController::CreateConnection},
        {OpCode::DISCONNECT, &DualModeController::Disconnect},
        {OpCode::ADD_SCO_CONNECTION, &DualModeController::AddScoConnection},
        {OpCode::CREATE_CONNECTION_CANCEL,
         &DualModeController::CreateConnectionCancel},
        {OpCode::ACCEPT_CONNECTION_REQUEST,
         &DualModeController::AcceptConnectionRequest},
        {OpCode::REJECT_CONNECTION_REQUEST,
         &DualModeController::RejectConnectionRequest},
        {OpCode::LINK_KEY_REQUEST_REPLY,
         &DualModeController::LinkKeyRequestReply},
        {OpCode::LINK_KEY_REQUEST_NEGATIVE_REPLY,
         &DualModeController::LinkKeyRequestNegativeReply},
        {OpCode::PIN_CODE_REQUEST_REPLY,
         &DualModeController::PinCodeRequestReply},
        {OpCode::PIN_CODE_REQUEST_NEGATIVE_REPLY,
         &DualModeController::PinCodeRequestNegativeReply},
        {OpCode::CHANGE_CONNECTION_PACKET_TYPE,
         &DualModeController::ChangeConnectionPacketType},
        {OpCode::AUTHENTICATION_REQUESTED,
         &DualModeController::AuthenticationRequested},
        {OpCode::SET_CONNECTION_ENCRYPTION,
         &DualModeController::SetConnectionEncryption},
        {OpCode::CHANGE_CONNECTION_LINK_KEY,
         &DualModeController::ChangeConnectionLinkKey},
        {OpCode::CENTRAL_LINK_KEY, &DualModeController::CentralLinkKey},
        {OpCode::REMOTE_NAME_REQUEST, &DualModeController::RemoteNameRequest},
        //{OpCode::REMOTE_NAME_REQUEST_CANCEL,
        //&DualModeController::RemoteNameRequestCancel},
        {OpCode::READ_REMOTE_SUPPORTED_FEATURES,
         &DualModeController::ReadRemoteSupportedFeatures},
        {OpCode::READ_REMOTE_EXTENDED_FEATURES,
         &DualModeController::ReadRemoteExtendedFeatures},
        {OpCode::READ_REMOTE_VERSION_INFORMATION,
         &DualModeController::ReadRemoteVersionInformation},
        {OpCode::READ_CLOCK_OFFSET, &DualModeController::ReadClockOffset},
        //{OpCode::READ_LMP_HANDLE, &DualModeController::ReadLmpHandle},
        {OpCode::SETUP_SYNCHRONOUS_CONNECTION,
         &DualModeController::SetupSynchronousConnection},
        {OpCode::ACCEPT_SYNCHRONOUS_CONNECTION,
         &DualModeController::AcceptSynchronousConnection},
        {OpCode::REJECT_SYNCHRONOUS_CONNECTION,
         &DualModeController::RejectSynchronousConnection},
        {OpCode::IO_CAPABILITY_REQUEST_REPLY,
         &DualModeController::IoCapabilityRequestReply},
        {OpCode::USER_CONFIRMATION_REQUEST_REPLY,
         &DualModeController::UserConfirmationRequestReply},
        {OpCode::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY,
         &DualModeController::UserConfirmationRequestNegativeReply},
        {OpCode::USER_PASSKEY_REQUEST_REPLY,
         &DualModeController::UserPasskeyRequestReply},
        {OpCode::USER_PASSKEY_REQUEST_NEGATIVE_REPLY,
         &DualModeController::UserPasskeyRequestNegativeReply},
        {OpCode::REMOTE_OOB_DATA_REQUEST_REPLY,
         &DualModeController::RemoteOobDataRequestReply},
        {OpCode::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY,
         &DualModeController::RemoteOobDataRequestNegativeReply},
        {OpCode::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY,
         &DualModeController::IoCapabilityRequestNegativeReply},
        {OpCode::ENHANCED_SETUP_SYNCHRONOUS_CONNECTION,
         &DualModeController::EnhancedSetupSynchronousConnection},
        {OpCode::ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION,
         &DualModeController::EnhancedAcceptSynchronousConnection},
        //{OpCode::TRUNCATED_PAGE, &DualModeController::TruncatedPage},
        //{OpCode::TRUNCATED_PAGE_CANCEL,
        //&DualModeController::TruncatedPageCancel},
        //{OpCode::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST,
        //&DualModeController::SetConnectionlessPeripheralBroadcast},
        //{OpCode::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE,
        //&DualModeController::SetConnectionlessPeripheralBroadcastReceive},
        //{OpCode::START_SYNCHRONIZATION_TRAIN,
        //&DualModeController::StartSynchronizationTrain},
        //{OpCode::RECEIVE_SYNCHRONIZATION_TRAIN,
        //&DualModeController::ReceiveSynchronizationTrain},
        {OpCode::REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY,
         &DualModeController::RemoteOobExtendedDataRequestReply},

        // LINK_POLICY
        {OpCode::HOLD_MODE, &DualModeController::HoldMode},
        {OpCode::SNIFF_MODE, &DualModeController::SniffMode},
        {OpCode::EXIT_SNIFF_MODE, &DualModeController::ExitSniffMode},
        {OpCode::QOS_SETUP, &DualModeController::QosSetup},
        {OpCode::ROLE_DISCOVERY, &DualModeController::RoleDiscovery},
        {OpCode::SWITCH_ROLE, &DualModeController::SwitchRole},
        {OpCode::READ_LINK_POLICY_SETTINGS,
         &DualModeController::ReadLinkPolicySettings},
        {OpCode::WRITE_LINK_POLICY_SETTINGS,
         &DualModeController::WriteLinkPolicySettings},
        {OpCode::READ_DEFAULT_LINK_POLICY_SETTINGS,
         &DualModeController::ReadDefaultLinkPolicySettings},
        {OpCode::WRITE_DEFAULT_LINK_POLICY_SETTINGS,
         &DualModeController::WriteDefaultLinkPolicySettings},
        {OpCode::FLOW_SPECIFICATION, &DualModeController::FlowSpecification},
        {OpCode::SNIFF_SUBRATING, &DualModeController::SniffSubrating},

        // CONTROLLER_AND_BASEBAND
        {OpCode::SET_EVENT_MASK, &DualModeController::SetEventMask},
        {OpCode::RESET, &DualModeController::Reset},
        {OpCode::SET_EVENT_FILTER, &DualModeController::SetEventFilter},
        //{OpCode::FLUSH, &DualModeController::Flush},
        //{OpCode::READ_PIN_TYPE, &DualModeController::ReadPinType},
        //{OpCode::WRITE_PIN_TYPE, &DualModeController::WritePinType},
        //{OpCode::READ_STORED_LINK_KEY,
        //&DualModeController::ReadStoredLinkKey},
        //{OpCode::WRITE_STORED_LINK_KEY,
        //&DualModeController::WriteStoredLinkKey},
        {OpCode::DELETE_STORED_LINK_KEY,
         &DualModeController::DeleteStoredLinkKey},
        {OpCode::WRITE_LOCAL_NAME, &DualModeController::WriteLocalName},
        {OpCode::READ_LOCAL_NAME, &DualModeController::ReadLocalName},
        {OpCode::READ_CONNECTION_ACCEPT_TIMEOUT,
         &DualModeController::ReadConnectionAcceptTimeout},
        {OpCode::WRITE_CONNECTION_ACCEPT_TIMEOUT,
         &DualModeController::WriteConnectionAcceptTimeout},
        {OpCode::READ_PAGE_TIMEOUT, &DualModeController::ReadPageTimeout},
        {OpCode::WRITE_PAGE_TIMEOUT, &DualModeController::WritePageTimeout},
        {OpCode::READ_SCAN_ENABLE, &DualModeController::ReadScanEnable},
        {OpCode::WRITE_SCAN_ENABLE, &DualModeController::WriteScanEnable},
        {OpCode::READ_PAGE_SCAN_ACTIVITY,
         &DualModeController::ReadPageScanActivity},
        {OpCode::WRITE_PAGE_SCAN_ACTIVITY,
         &DualModeController::WritePageScanActivity},
        {OpCode::READ_INQUIRY_SCAN_ACTIVITY,
         &DualModeController::ReadInquiryScanActivity},
        {OpCode::WRITE_INQUIRY_SCAN_ACTIVITY,
         &DualModeController::WriteInquiryScanActivity},
        {OpCode::READ_AUTHENTICATION_ENABLE,
         &DualModeController::ReadAuthenticationEnable},
        {OpCode::WRITE_AUTHENTICATION_ENABLE,
         &DualModeController::WriteAuthenticationEnable},
        {OpCode::READ_CLASS_OF_DEVICE, &DualModeController::ReadClassOfDevice},
        {OpCode::WRITE_CLASS_OF_DEVICE,
         &DualModeController::WriteClassOfDevice},
        {OpCode::READ_VOICE_SETTING, &DualModeController::ReadVoiceSetting},
        {OpCode::WRITE_VOICE_SETTING, &DualModeController::WriteVoiceSetting},
        //{OpCode::READ_AUTOMATIC_FLUSH_TIMEOUT,
        //&DualModeController::ReadAutomaticFlushTimeout},
        //{OpCode::WRITE_AUTOMATIC_FLUSH_TIMEOUT,
        //&DualModeController::WriteAutomaticFlushTimeout},
        //{OpCode::READ_NUM_BROADCAST_RETRANSMITS,
        //&DualModeController::ReadNumBroadcastRetransmits},
        //{OpCode::WRITE_NUM_BROADCAST_RETRANSMITS,
        //&DualModeController::WriteNumBroadcastRetransmits},
        //{OpCode::READ_HOLD_MODE_ACTIVITY,
        //&DualModeController::ReadHoldModeActivity},
        //{OpCode::WRITE_HOLD_MODE_ACTIVITY,
        //&DualModeController::WriteHoldModeActivity},
        //{OpCode::READ_TRANSMIT_POWER_LEVEL,
        //&DualModeController::ReadTransmitPowerLevel},
        {OpCode::READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE,
         &DualModeController::ReadSynchronousFlowControlEnable},
        {OpCode::WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE,
         &DualModeController::WriteSynchronousFlowControlEnable},
        //{OpCode::SET_CONTROLLER_TO_HOST_FLOW_CONTROL,
        //&DualModeController::SetControllerToHostFlowControl},
        {OpCode::HOST_BUFFER_SIZE, &DualModeController::HostBufferSize},
        //{OpCode::HOST_NUMBER_OF_COMPLETED_PACKETS,
        //&DualModeController::HostNumberOfCompletedPackets},
        //{OpCode::READ_LINK_SUPERVISION_TIMEOUT,
        //&DualModeController::ReadLinkSupervisionTimeout},
        {OpCode::WRITE_LINK_SUPERVISION_TIMEOUT,
         &DualModeController::WriteLinkSupervisionTimeout},
        {OpCode::READ_NUMBER_OF_SUPPORTED_IAC,
         &DualModeController::ReadNumberOfSupportedIac},
        {OpCode::READ_CURRENT_IAC_LAP, &DualModeController::ReadCurrentIacLap},
        {OpCode::WRITE_CURRENT_IAC_LAP,
         &DualModeController::WriteCurrentIacLap},
        //{OpCode::SET_AFH_HOST_CHANNEL_CLASSIFICATION,
        //&DualModeController::SetAfhHostChannelClassification},
        {OpCode::READ_INQUIRY_SCAN_TYPE,
         &DualModeController::ReadInquiryScanType},
        {OpCode::WRITE_INQUIRY_SCAN_TYPE,
         &DualModeController::WriteInquiryScanType},
        {OpCode::READ_INQUIRY_MODE, &DualModeController::ReadInquiryMode},
        {OpCode::WRITE_INQUIRY_MODE, &DualModeController::WriteInquiryMode},
        {OpCode::READ_PAGE_SCAN_TYPE, &DualModeController::ReadPageScanType},
        {OpCode::WRITE_PAGE_SCAN_TYPE, &DualModeController::WritePageScanType},
        //{OpCode::READ_AFH_CHANNEL_ASSESSMENT_MODE,
        //&DualModeController::ReadAfhChannelAssessmentMode},
        //{OpCode::WRITE_AFH_CHANNEL_ASSESSMENT_MODE,
        //&DualModeController::WriteAfhChannelAssessmentMode},
        //{OpCode::READ_EXTENDED_INQUIRY_RESPONSE,
        //&DualModeController::ReadExtendedInquiryResponse},
        {OpCode::WRITE_EXTENDED_INQUIRY_RESPONSE,
         &DualModeController::WriteExtendedInquiryResponse},
        {OpCode::REFRESH_ENCRYPTION_KEY,
         &DualModeController::RefreshEncryptionKey},
        //{OpCode::READ_SIMPLE_PAIRING_MODE,
        //&DualModeController::ReadSimplePairingMode},
        {OpCode::WRITE_SIMPLE_PAIRING_MODE,
         &DualModeController::WriteSimplePairingMode},
        {OpCode::READ_LOCAL_OOB_DATA, &DualModeController::ReadLocalOobData},
        {OpCode::READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL,
         &DualModeController::ReadInquiryResponseTransmitPowerLevel},
        //{OpCode::WRITE_INQUIRY_TRANSMIT_POWER_LEVEL,
        //&DualModeController::WriteInquiryTransmitPowerLevel},
        //{OpCode::READ_DEFAULT_ERRONEOUS_DATA_REPORTING,
        //&DualModeController::ReadDefaultErroneousDataReporting},
        //{OpCode::WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING,
        //&DualModeController::WriteDefaultErroneousDataReporting},
        {OpCode::ENHANCED_FLUSH, &DualModeController::EnhancedFlush},
        {OpCode::SEND_KEYPRESS_NOTIFICATION,
         &DualModeController::SendKeypressNotification},
        {OpCode::SET_EVENT_MASK_PAGE_2, &DualModeController::SetEventMaskPage2},
        //{OpCode::READ_FLOW_CONTROL_MODE,
        //&DualModeController::ReadFlowControlMode},
        //{OpCode::WRITE_FLOW_CONTROL_MODE,
        //&DualModeController::WriteFlowControlMode},
        //{OpCode::READ_ENHANCED_TRANSMIT_POWER_LEVEL,
        //&DualModeController::ReadEnhancedTransmitPowerLevel},
        //{OpCode::READ_LE_HOST_SUPPORT,
        //&DualModeController::ReadLeHostSupport},
        {OpCode::WRITE_LE_HOST_SUPPORT,
         &DualModeController::WriteLeHostSupport},
        //{OpCode::SET_MWS_CHANNEL_PARAMETERS,
        //&DualModeController::SetMwsChannelParameters},
        //{OpCode::SET_EXTERNAL_FRAME_CONFIGURATION,
        //&DualModeController::SetExternalFrameConfiguration},
        //{OpCode::SET_MWS_SIGNALING, &DualModeController::SetMwsSignaling},
        //{OpCode::SET_MWS_TRANSPORT_LAYER,
        //&DualModeController::SetMwsTransportLayer},
        //{OpCode::SET_MWS_SCAN_FREQUENCY_TABLE,
        //&DualModeController::SetMwsScanFrequencyTable},
        //{OpCode::SET_MWS_PATTERN_CONFIGURATION,
        //&DualModeController::SetMwsPatternConfiguration},
        //{OpCode::SET_RESERVED_LT_ADDR,
        //&DualModeController::SetReservedLtAddr},
        //{OpCode::DELETE_RESERVED_LT_ADDR,
        //&DualModeController::DeleteReservedLtAddr},
        //{OpCode::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA,
        //&DualModeController::SetConnectionlessPeripheralBroadcastData},
        //{OpCode::READ_SYNCHRONIZATION_TRAIN_PARAMETERS,
        //&DualModeController::ReadSynchronizationTrainParameters},
        //{OpCode::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS,
        //&DualModeController::WriteSynchronizationTrainParameters},
        //{OpCode::READ_SECURE_CONNECTIONS_HOST_SUPPORT,
        //&DualModeController::ReadSecureConnectionsHostSupport},
        {OpCode::WRITE_SECURE_CONNECTIONS_HOST_SUPPORT,
         &DualModeController::WriteSecureConnectionsHostSupport},
        //{OpCode::READ_AUTHENTICATED_PAYLOAD_TIMEOUT,
        //&DualModeController::ReadAuthenticatedPayloadTimeout},
        //{OpCode::WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT,
        //&DualModeController::WriteAuthenticatedPayloadTimeout},
        {OpCode::READ_LOCAL_OOB_EXTENDED_DATA,
         &DualModeController::ReadLocalOobExtendedData},
        //{OpCode::READ_EXTENDED_PAGE_TIMEOUT,
        //&DualModeController::ReadExtendedPageTimeout},
        //{OpCode::WRITE_EXTENDED_PAGE_TIMEOUT,
        //&DualModeController::WriteExtendedPageTimeout},
        //{OpCode::READ_EXTENDED_INQUIRY_LENGTH,
        //&DualModeController::ReadExtendedInquiryLength},
        //{OpCode::WRITE_EXTENDED_INQUIRY_LENGTH,
        //&DualModeController::WriteExtendedInquiryLength},
        //{OpCode::SET_ECOSYSTEM_BASE_INTERVAL,
        //&DualModeController::SetEcosystemBaseInterval},
        //{OpCode::CONFIGURE_DATA_PATH, &DualModeController::ConfigureDataPath},
        //{OpCode::SET_MIN_ENCRYPTION_KEY_SIZE,
        //&DualModeController::SetMinEncryptionKeySize},

        // INFORMATIONAL_PARAMETERS
        {OpCode::READ_LOCAL_VERSION_INFORMATION,
         &DualModeController::ReadLocalVersionInformation},
        {OpCode::READ_LOCAL_SUPPORTED_COMMANDS,
         &DualModeController::ReadLocalSupportedCommands},
        {OpCode::READ_LOCAL_SUPPORTED_FEATURES,
         &DualModeController::ReadLocalSupportedFeatures},
        {OpCode::READ_LOCAL_EXTENDED_FEATURES,
         &DualModeController::ReadLocalExtendedFeatures},
        {OpCode::READ_BUFFER_SIZE, &DualModeController::ReadBufferSize},
        {OpCode::READ_BD_ADDR, &DualModeController::ReadBdAddr},
        //{OpCode::READ_DATA_BLOCK_SIZE,
        //&DualModeController::ReadDataBlockSize},
        {OpCode::READ_LOCAL_SUPPORTED_CODECS_V1,
         &DualModeController::ReadLocalSupportedCodecsV1},
        //{OpCode::READ_LOCAL_SIMPLE_PAIRING_OPTIONS,
        //&DualModeController::ReadLocalSimplePairingOptions},
        //{OpCode::READ_LOCAL_SUPPORTED_CODECS_V2,
        //&DualModeController::ReadLocalSupportedCodecsV2},
        //{OpCode::READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES,
        //&DualModeController::ReadLocalSupportedCodecCapabilities},
        //{OpCode::READ_LOCAL_SUPPORTED_CONTROLLER_DELAY,
        //&DualModeController::ReadLocalSupportedControllerDelay},

        // STATUS_PARAMETERS
        //{OpCode::READ_FAILED_CONTACT_COUNTER,
        //&DualModeController::ReadFailedContactCounter},
        //{OpCode::RESET_FAILED_CONTACT_COUNTER,
        //&DualModeController::ResetFailedContactCounter},
        //{OpCode::READ_LINK_QUALITY, &DualModeController::ReadLinkQuality},
        {OpCode::READ_RSSI, &DualModeController::ReadRssi},
        //{OpCode::READ_AFH_CHANNEL_MAP,
        //&DualModeController::ReadAfhChannelMap},
        //{OpCode::READ_CLOCK, &DualModeController::ReadClock},
        {OpCode::READ_ENCRYPTION_KEY_SIZE,
         &DualModeController::ReadEncryptionKeySize},
        //{OpCode::GET_MWS_TRANSPORT_LAYER_CONFIGURATION,
        //&DualModeController::GetMwsTransportLayerConfiguration},
        //{OpCode::SET_TRIGGERED_CLOCK_CAPTURE,
        //&DualModeController::SetTriggeredClockCapture},

        // TESTING
        {OpCode::READ_LOOPBACK_MODE, &DualModeController::ReadLoopbackMode},
        {OpCode::WRITE_LOOPBACK_MODE, &DualModeController::WriteLoopbackMode},
        //{OpCode::ENABLE_DEVICE_UNDER_TEST_MODE,
        //&DualModeController::EnableDeviceUnderTestMode},
        //{OpCode::WRITE_SIMPLE_PAIRING_DEBUG_MODE,
        //&DualModeController::WriteSimplePairingDebugMode},
        //{OpCode::WRITE_SECURE_CONNECTIONS_TEST_MODE,
        //&DualModeController::WriteSecureConnectionsTestMode},

        // LE_CONTROLLER
        {OpCode::LE_SET_EVENT_MASK, &DualModeController::LeSetEventMask},
        {OpCode::LE_READ_BUFFER_SIZE_V1,
         &DualModeController::LeReadBufferSizeV1},
        {OpCode::LE_READ_LOCAL_SUPPORTED_FEATURES,
         &DualModeController::LeReadLocalSupportedFeatures},
        {OpCode::LE_SET_RANDOM_ADDRESS,
         &DualModeController::LeSetRandomAddress},
        {OpCode::LE_SET_ADVERTISING_PARAMETERS,
         &DualModeController::LeSetAdvertisingParameters},
        {OpCode::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER,
         &DualModeController::LeReadAdvertisingPhysicalChannelTxPower},
        {OpCode::LE_SET_ADVERTISING_DATA,
         &DualModeController::LeSetAdvertisingData},
        {OpCode::LE_SET_SCAN_RESPONSE_DATA,
         &DualModeController::LeSetScanResponseData},
        {OpCode::LE_SET_ADVERTISING_ENABLE,
         &DualModeController::LeSetAdvertisingEnable},
        {OpCode::LE_SET_SCAN_PARAMETERS,
         &DualModeController::LeSetScanParameters},
        {OpCode::LE_SET_SCAN_ENABLE, &DualModeController::LeSetScanEnable},
        {OpCode::LE_CREATE_CONNECTION, &DualModeController::LeCreateConnection},
        {OpCode::LE_CREATE_CONNECTION_CANCEL,
         &DualModeController::LeCreateConnectionCancel},
        {OpCode::LE_READ_FILTER_ACCEPT_LIST_SIZE,
         &DualModeController::LeReadFilterAcceptListSize},
        {OpCode::LE_CLEAR_FILTER_ACCEPT_LIST,
         &DualModeController::LeClearFilterAcceptList},
        {OpCode::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST,
         &DualModeController::LeAddDeviceToFilterAcceptList},
        {OpCode::LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST,
         &DualModeController::LeRemoveDeviceFromFilterAcceptList},
        {OpCode::LE_CONNECTION_UPDATE, &DualModeController::LeConnectionUpdate},
        //{OpCode::LE_SET_HOST_CHANNEL_CLASSIFICATION,
        //&DualModeController::LeSetHostChannelClassification},
        //{OpCode::LE_READ_CHANNEL_MAP, &DualModeController::LeReadChannelMap},
        {OpCode::LE_READ_REMOTE_FEATURES,
         &DualModeController::LeReadRemoteFeatures},
        {OpCode::LE_ENCRYPT, &DualModeController::LeEncrypt},
        {OpCode::LE_RAND, &DualModeController::LeRand},
        {OpCode::LE_START_ENCRYPTION, &DualModeController::LeStartEncryption},
        {OpCode::LE_LONG_TERM_KEY_REQUEST_REPLY,
         &DualModeController::LeLongTermKeyRequestReply},
        {OpCode::LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY,
         &DualModeController::LeLongTermKeyRequestNegativeReply},
        {OpCode::LE_READ_SUPPORTED_STATES,
         &DualModeController::LeReadSupportedStates},
        //{OpCode::LE_RECEIVER_TEST_V1, &DualModeController::LeReceiverTestV1},
        //{OpCode::LE_TRANSMITTER_TEST_V1,
        //&DualModeController::LeTransmitterTestV1},
        //{OpCode::LE_TEST_END, &DualModeController::LeTestEnd},
        {OpCode::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY,
         &DualModeController::LeRemoteConnectionParameterRequestReply},
        {OpCode::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY,
         &DualModeController::LeRemoteConnectionParameterRequestNegativeReply},
        //{OpCode::LE_SET_DATA_LENGTH, &DualModeController::LeSetDataLength},
        {OpCode::LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH,
         &DualModeController::LeReadSuggestedDefaultDataLength},
        {OpCode::LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH,
         &DualModeController::LeWriteSuggestedDefaultDataLength},
        //{OpCode::LE_READ_LOCAL_P_256_PUBLIC_KEY,
        //&DualModeController::LeReadLocalP256PublicKey},
        //{OpCode::LE_GENERATE_DHKEY_V1,
        //&DualModeController::LeGenerateDhkeyV1},
        {OpCode::LE_ADD_DEVICE_TO_RESOLVING_LIST,
         &DualModeController::LeAddDeviceToResolvingList},
        {OpCode::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST,
         &DualModeController::LeRemoveDeviceFromResolvingList},
        {OpCode::LE_CLEAR_RESOLVING_LIST,
         &DualModeController::LeClearResolvingList},
        {OpCode::LE_READ_RESOLVING_LIST_SIZE,
         &DualModeController::LeReadResolvingListSize},
        //{OpCode::LE_READ_PEER_RESOLVABLE_ADDRESS,
        //&DualModeController::LeReadPeerResolvableAddress},
        //{OpCode::LE_READ_LOCAL_RESOLVABLE_ADDRESS,
        //&DualModeController::LeReadLocalResolvableAddress},
        {OpCode::LE_SET_ADDRESS_RESOLUTION_ENABLE,
         &DualModeController::LeSetAddressResolutionEnable},
        {OpCode::LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT,
         &DualModeController::LeSetResolvablePrivateAddressTimeout},
        {OpCode::LE_READ_MAXIMUM_DATA_LENGTH,
         &DualModeController::LeReadMaximumDataLength},
        {OpCode::LE_READ_PHY, &DualModeController::LeReadPhy},
        {OpCode::LE_SET_DEFAULT_PHY, &DualModeController::LeSetDefaultPhy},
        {OpCode::LE_SET_PHY, &DualModeController::LeSetPhy},
        //{OpCode::LE_RECEIVER_TEST_V2, &DualModeController::LeReceiverTestV2},
        //{OpCode::LE_TRANSMITTER_TEST_V2,
        //&DualModeController::LeTransmitterTestV2},
        {OpCode::LE_SET_ADVERTISING_SET_RANDOM_ADDRESS,
         &DualModeController::LeSetAdvertisingSetRandomAddress},
        {OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
         &DualModeController::LeSetExtendedAdvertisingParameters},
        {OpCode::LE_SET_EXTENDED_ADVERTISING_DATA,
         &DualModeController::LeSetExtendedAdvertisingData},
        {OpCode::LE_SET_EXTENDED_SCAN_RESPONSE_DATA,
         &DualModeController::LeSetExtendedScanResponseData},
        {OpCode::LE_SET_EXTENDED_ADVERTISING_ENABLE,
         &DualModeController::LeSetExtendedAdvertisingEnable},
        {OpCode::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH,
         &DualModeController::LeReadMaximumAdvertisingDataLength},
        {OpCode::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS,
         &DualModeController::LeReadNumberOfSupportedAdvertisingSets},
        {OpCode::LE_REMOVE_ADVERTISING_SET,
         &DualModeController::LeRemoveAdvertisingSet},
        {OpCode::LE_CLEAR_ADVERTISING_SETS,
         &DualModeController::LeClearAdvertisingSets},
        //{OpCode::LE_SET_PERIODIC_ADVERTISING_PARAM,
        //&DualModeController::LeSetPeriodicAdvertisingParam},
        //{OpCode::LE_SET_PERIODIC_ADVERTISING_DATA,
        //&DualModeController::LeSetPeriodicAdvertisingData},
        //{OpCode::LE_SET_PERIODIC_ADVERTISING_ENABLE,
        //&DualModeController::LeSetPeriodicAdvertisingEnable},
        {OpCode::LE_SET_EXTENDED_SCAN_PARAMETERS,
         &DualModeController::LeSetExtendedScanParameters},
        {OpCode::LE_SET_EXTENDED_SCAN_ENABLE,
         &DualModeController::LeSetExtendedScanEnable},
        {OpCode::LE_EXTENDED_CREATE_CONNECTION,
         &DualModeController::LeExtendedCreateConnection},
        //{OpCode::LE_PERIODIC_ADVERTISING_CREATE_SYNC,
        //&DualModeController::LePeriodicAdvertisingCreateSync},
        //{OpCode::LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL,
        //&DualModeController::LePeriodicAdvertisingCreateSyncCancel},
        //{OpCode::LE_PERIODIC_ADVERTISING_TERMINATE_SYNC,
        //&DualModeController::LePeriodicAdvertisingTerminateSync},
        //{OpCode::LE_ADD_DEVICE_TO_PERIODIC_ADVERTISING_LIST,
        //&DualModeController::LeAddDeviceToPeriodicAdvertisingList},
        //{OpCode::LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISING_LIST,
        //&DualModeController::LeRemoveDeviceFromPeriodicAdvertisingList},
        //{OpCode::LE_CLEAR_PERIODIC_ADVERTISING_LIST,
        //&DualModeController::LeClearPeriodicAdvertisingList},
        //{OpCode::LE_READ_PERIODIC_ADVERTISING_LIST_SIZE,
        //&DualModeController::LeReadPeriodicAdvertisingListSize},
        //{OpCode::LE_READ_TRANSMIT_POWER,
        //&DualModeController::LeReadTransmitPower},
        //{OpCode::LE_READ_RF_PATH_COMPENSATION_POWER,
        //&DualModeController::LeReadRfPathCompensationPower},
        //{OpCode::LE_WRITE_RF_PATH_COMPENSATION_POWER,
        //&DualModeController::LeWriteRfPathCompensationPower},
        {OpCode::LE_SET_PRIVACY_MODE, &DualModeController::LeSetPrivacyMode},
        //{OpCode::LE_RECEIVER_TEST_V3, &DualModeController::LeReceiverTestV3},
        //{OpCode::LE_TRANSMITTER_TEST_V3,
        //&DualModeController::LeTransmitterTestV3},
        //{OpCode::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS,
        //&DualModeController::LeSetConnectionlessCteTransmitParameters},
        //{OpCode::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE,
        //&DualModeController::LeSetConnectionlessCteTransmitEnable},
        //{OpCode::LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE,
        //&DualModeController::LeSetConnectionlessIqSamplingEnable},
        //{OpCode::LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS,
        //&DualModeController::LeSetConnectionCteReceiveParameters},
        //{OpCode::LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS,
        //&DualModeController::LeSetConnectionCteTransmitParameters},
        //{OpCode::LE_CONNECTION_CTE_REQUEST_ENABLE,
        //&DualModeController::LeConnectionCteRequestEnable},
        //{OpCode::LE_CONNECTION_CTE_RESPONSE_ENABLE,
        //&DualModeController::LeConnectionCteResponseEnable},
        //{OpCode::LE_READ_ANTENNA_INFORMATION,
        //&DualModeController::LeReadAntennaInformation},
        //{OpCode::LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE,
        //&DualModeController::LeSetPeriodicAdvertisingReceiveEnable},
        //{OpCode::LE_PERIODIC_ADVERTISING_SYNC_TRANSFER,
        //&DualModeController::LePeriodicAdvertisingSyncTransfer},
        //{OpCode::LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER,
        //&DualModeController::LePeriodicAdvertisingSetInfoTransfer},
        //{OpCode::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
        //&DualModeController::LeSetPeriodicAdvertisingSyncTransferParameters},
        //{OpCode::LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
        //&DualModeController::LeSetDefaultPeriodicAdvertisingSyncTransferParameters},
        //{OpCode::LE_GENERATE_DHKEY_V2,
        //&DualModeController::LeGenerateDhkeyV2},
        //{OpCode::LE_MODIFY_SLEEP_CLOCK_ACCURACY,
        //&DualModeController::LeModifySleepClockAccuracy},
        {OpCode::LE_READ_BUFFER_SIZE_V2,
         &DualModeController::LeReadBufferSizeV2},
        {OpCode::LE_READ_ISO_TX_SYNC, &DualModeController::LeReadIsoTxSync},
        {OpCode::LE_SET_CIG_PARAMETERS,
         &DualModeController::LeSetCigParameters},
        //{OpCode::LE_SET_CIG_PARAMETERS_TEST,
        //&DualModeController::LeSetCigParametersTest},
        {OpCode::LE_CREATE_CIS, &DualModeController::LeCreateCis},
        {OpCode::LE_REMOVE_CIG, &DualModeController::LeRemoveCig},
        {OpCode::LE_ACCEPT_CIS_REQUEST,
         &DualModeController::LeAcceptCisRequest},
        {OpCode::LE_REJECT_CIS_REQUEST,
         &DualModeController::LeRejectCisRequest},
        {OpCode::LE_CREATE_BIG, &DualModeController::LeCreateBig},
        //{OpCode::LE_CREATE_BIG_TEST, &DualModeController::LeCreateBigTest},
        {OpCode::LE_TERMINATE_BIG, &DualModeController::LeTerminateBig},
        {OpCode::LE_BIG_CREATE_SYNC, &DualModeController::LeBigCreateSync},
        {OpCode::LE_BIG_TERMINATE_SYNC,
         &DualModeController::LeBigTerminateSync},
        {OpCode::LE_REQUEST_PEER_SCA, &DualModeController::LeRequestPeerSca},
        {OpCode::LE_SETUP_ISO_DATA_PATH,
         &DualModeController::LeSetupIsoDataPath},
        {OpCode::LE_REMOVE_ISO_DATA_PATH,
         &DualModeController::LeRemoveIsoDataPath},
        //{OpCode::LE_ISO_TRANSMIT_TEST,
        //&DualModeController::LeIsoTransmitTest},
        //{OpCode::LE_ISO_RECEIVE_TEST, &DualModeController::LeIsoReceiveTest},
        //{OpCode::LE_ISO_READ_TEST_COUNTERS,
        //&DualModeController::LeIsoReadTestCounters},
        //{OpCode::LE_ISO_TEST_END, &DualModeController::LeIsoTestEnd},
        {OpCode::LE_SET_HOST_FEATURE, &DualModeController::LeSetHostFeature},
        //{OpCode::LE_READ_ISO_LINK_QUALITY,
        //&DualModeController::LeReadIsoLinkQuality},
        //{OpCode::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL,
        //&DualModeController::LeEnhancedReadTransmitPowerLevel},
        //{OpCode::LE_READ_REMOTE_TRANSMIT_POWER_LEVEL,
        //&DualModeController::LeReadRemoteTransmitPowerLevel},
        //{OpCode::LE_SET_PATH_LOSS_REPORTING_PARAMETERS,
        //&DualModeController::LeSetPathLossReportingParameters},
        //{OpCode::LE_SET_PATH_LOSS_REPORTING_ENABLE,
        //&DualModeController::LeSetPathLossReportingEnable},
        //{OpCode::LE_SET_TRANSMIT_POWER_REPORTING_ENABLE,
        //&DualModeController::LeSetTransmitPowerReportingEnable},
        //{OpCode::LE_TRANSMITTER_TEST_V4,
        //&DualModeController::LeTransmitterTestV4},
        //{OpCode::LE_SET_DATA_RELATED_ADDRESS_CHANGES,
        //&DualModeController::LeSetDataRelatedAddressChanges},
        //{OpCode::LE_SET_DEFAULT_SUBRATE,
        //&DualModeController::LeSetDefaultSubrate},
        //{OpCode::LE_SUBRATE_REQUEST, &DualModeController::LeSubrateRequest},

        // VENDOR
        {OpCode(CSR_VENDOR), &DualModeController::CsrVendorCommand},
        {OpCode::LE_MULTI_ADVT, &DualModeController::LeMultiAdv},
        {OpCode::LE_ADV_FILTER, &DualModeController::LeAdvertisingFilter},
        {OpCode::LE_EXTENDED_SCAN_PARAMS,
         &DualModeController::LeExtendedScanParams},
        {OpCode::LE_ENERGY_INFO, &DualModeController::LeEnergyInfo},
        {OpCode::LE_GET_VENDOR_CAPABILITIES,
         &DualModeController::LeGetVendorCapabilities}};

}  // namespace rootcanal
