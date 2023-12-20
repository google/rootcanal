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

#pragma once

#include <unistd.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include "hci/address.h"
#include "model/controller/controller_properties.h"
#include "model/controller/link_layer_controller.h"
#include "model/controller/vendor_commands/csr.h"
#include "model/devices/device.h"
#include "packets/hci_packets.h"
#include "packets/link_layer_packets.h"
#include "phy.h"

namespace rootcanal {

using ::bluetooth::hci::Address;
using ::bluetooth::hci::CommandView;

// Emulates a dual mode BR/EDR + LE controller by maintaining the link layer
// state machine detailed in the Bluetooth Core Specification Version 4.2,
// Volume 6, Part B, Section 1.1 (page 30). Provides methods corresponding to
// commands sent by the HCI. These methods will be registered as callbacks from
// a controller instance with the HciHandler. To implement a new Bluetooth
// command, simply add the method declaration below, with return type void and a
// single const std::vector<uint8_t>& argument. After implementing the
// method, simply register it with the HciHandler using the SET_HANDLER macro in
// the controller's default constructor. Be sure to name your method after the
// corresponding Bluetooth command in the Core Specification with the prefix
// "Hci" to distinguish it as a controller command.
class DualModeController : public Device {
 public:
  DualModeController(ControllerProperties properties = ControllerProperties());
  DualModeController(DualModeController&&) = delete;
  DualModeController(const DualModeController&) = delete;
  ~DualModeController() = default;

  DualModeController& operator=(const DualModeController&) = delete;

  // Overwrite the configuration.
  void SetProperties(ControllerProperties properties);

  // Device methods.
  std::string GetTypeString() const override;

  void ReceiveLinkLayerPacket(model::packets::LinkLayerPacketView incoming,
                              Phy::Type type, int8_t rssi) override;

  void Tick() override;
  void Close() override;

  // Route commands and data from the stack.
  void HandleAcl(std::shared_ptr<std::vector<uint8_t>> acl_packet);
  void HandleCommand(std::shared_ptr<std::vector<uint8_t>> command_packet);
  void HandleSco(std::shared_ptr<std::vector<uint8_t>> sco_packet);
  void HandleIso(std::shared_ptr<std::vector<uint8_t>> iso_packet);

  // Set the callbacks for sending packets to the HCI.
  void RegisterEventChannel(
      const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
          send_event);

  void RegisterAclChannel(
      const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
          send_acl);

  void RegisterScoChannel(
      const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
          send_sco);

  void RegisterIsoChannel(
      const std::function<void(std::shared_ptr<std::vector<uint8_t>>)>&
          send_iso);

  // Controller commands. For error codes, see the Bluetooth Core Specification,
  // Version 4.2, Volume 2, Part D (page 370).

  // Link Control Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.1

  // 7.1.1
  void Inquiry(CommandView command);

  // 7.1.2
  void InquiryCancel(CommandView command);

  // 7.1.5
  void CreateConnection(CommandView command);

  // 7.1.6
  void Disconnect(CommandView command);

  // Deprecated
  void AddScoConnection(CommandView command);

  // 7.1.7
  void CreateConnectionCancel(CommandView command);

  // 7.1.8
  void AcceptConnectionRequest(CommandView command);

  // 7.1.9
  void RejectConnectionRequest(CommandView command);

  // 7.1.14
  void ChangeConnectionPacketType(CommandView command);

  // 7.1.17
  void ChangeConnectionLinkKey(CommandView command);

  // 7.1.18
  void CentralLinkKey(CommandView command);

  // 7.1.19
  void RemoteNameRequest(CommandView command);

  // 7.1.21
  void ReadRemoteSupportedFeatures(CommandView command);

  // 7.1.22
  void ReadRemoteExtendedFeatures(CommandView command);

  // 7.1.23
  void ReadRemoteVersionInformation(CommandView command);

  // 7.1.24
  void ReadClockOffset(CommandView command);

  // 7.1.26
  void SetupSynchronousConnection(CommandView command);

  // 7.1.27
  void AcceptSynchronousConnection(CommandView command);

  // 7.1.28
  void RejectSynchronousConnection(CommandView command);

  // 7.1.45
  void EnhancedSetupSynchronousConnection(CommandView command);

  // 7.1.46
  void EnhancedAcceptSynchronousConnection(CommandView command);

  // Link Policy Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.2

  // 7.2.1
  void HoldMode(CommandView command);

  // 7.2.2
  void SniffMode(CommandView command);

  // 7.2.3
  void ExitSniffMode(CommandView command);

  // 7.2.6
  void QosSetup(CommandView command);

  // 7.2.7
  void RoleDiscovery(CommandView command);

  // 7.2.8
  void SwitchRole(CommandView command);

  // 7.2.9
  void ReadLinkPolicySettings(CommandView command);

  // 7.2.10
  void WriteLinkPolicySettings(CommandView command);

  // 7.2.11
  void ReadDefaultLinkPolicySettings(CommandView command);

  // 7.2.12
  void WriteDefaultLinkPolicySettings(CommandView command);

  // 7.2.13
  void FlowSpecification(CommandView command);

  // 7.2.14
  void SniffSubrating(CommandView command);

  // Link Controller Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.3

  // 7.3.1
  void SetEventMask(CommandView command);

  // 7.3.2
  void Reset(CommandView command);

  // 7.3.3
  void SetEventFilter(CommandView command);

  // 7.3.10
  void DeleteStoredLinkKey(CommandView command);

  // 7.3.11
  void WriteLocalName(CommandView command);

  // 7.3.12
  void ReadLocalName(CommandView command);

  // 7.3.13 - 7.3.14
  void ReadConnectionAcceptTimeout(CommandView command);
  void WriteConnectionAcceptTimeout(CommandView command);

  // 7.3.15 - 7.3.16
  void ReadPageTimeout(CommandView command);
  void WritePageTimeout(CommandView command);

  // 7.3.17 - 7.3.18
  void ReadScanEnable(CommandView command);
  void WriteScanEnable(CommandView command);

  // 7.3.19 - 7.3.20
  void ReadPageScanActivity(CommandView command);
  void WritePageScanActivity(CommandView command);

  // 7.3.21 - 7.3.22
  void ReadInquiryScanActivity(CommandView command);
  void WriteInquiryScanActivity(CommandView command);

  // 7.3.23 - 7.3.24
  void ReadAuthenticationEnable(CommandView command);
  void WriteAuthenticationEnable(CommandView command);

  // 7.3.25 - 7.3.26
  void ReadClassOfDevice(CommandView command);
  void WriteClassOfDevice(CommandView command);

  // 7.3.27 - 7.3.28
  void ReadVoiceSetting(CommandView command);
  void WriteVoiceSetting(CommandView command);

  // 7.3.35
  void ReadTransmitPowerLevel(CommandView command);

  // 7.3.36 - 7.3.37
  void ReadSynchronousFlowControlEnable(CommandView command);
  void WriteSynchronousFlowControlEnable(CommandView command);

  // 7.3.39
  void HostBufferSize(CommandView command);

  // 7.3.42
  void WriteLinkSupervisionTimeout(CommandView command);

  // 7.3.43
  void ReadNumberOfSupportedIac(CommandView command);

  // 7.3.44 - 7.3.45
  void ReadCurrentIacLap(CommandView command);
  void WriteCurrentIacLap(CommandView command);

  // 7.3.47
  void ReadInquiryScanType(CommandView command);

  // 7.3.48
  void WriteInquiryScanType(CommandView command);

  // 7.3.49
  void ReadInquiryMode(CommandView command);

  // 7.3.50
  void WriteInquiryMode(CommandView command);

  // 7.3.52
  void ReadPageScanType(CommandView command);

  // 7.3.52
  void WritePageScanType(CommandView command);

  // 7.3.56
  void WriteExtendedInquiryResponse(CommandView command);

  // 7.3.57
  void RefreshEncryptionKey(CommandView command);

  // 7.3.59
  void WriteSimplePairingMode(CommandView command);

  // 7.3.60
  void ReadLocalOobData(CommandView command);

  // 7.3.61
  void ReadInquiryResponseTransmitPowerLevel(CommandView command);

  // 7.3.66
  void EnhancedFlush(CommandView command);

  // 7.3.69
  void SetEventMaskPage2(CommandView command);

  // 7.3.74
  void ReadEnhancedTransmitPowerLevel(CommandView command);

  // 7.3.79
  void WriteLeHostSupport(CommandView command);

  // 7.3.92
  void WriteSecureConnectionsHostSupport(CommandView command);

  // 7.3.95
  void ReadLocalOobExtendedData(CommandView command);

  // Informational Parameters Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.4

  // 7.4.5
  void ReadBufferSize(CommandView command);

  // 7.4.1
  void ReadLocalVersionInformation(CommandView command);

  // 7.4.6
  void ReadBdAddr(CommandView command);

  // 7.4.2
  void ReadLocalSupportedCommands(CommandView command);

  // 7.4.3
  void ReadLocalSupportedFeatures(CommandView command);

  // 7.4.4
  void ReadLocalExtendedFeatures(CommandView command);

  // 7.4.8
  void ReadLocalSupportedCodecsV1(CommandView command);

  // Status Parameters Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.5

  // 7.5.1 - 7.5.2
  void ReadFailedContactCounter(CommandView command);
  void ResetFailedContactCounter(CommandView command);

  // 7.5.4
  void ReadRssi(CommandView command);

  // 7.5.7
  void ReadEncryptionKeySize(CommandView command);

  // Test Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.7

  // 7.7.1
  void ReadLoopbackMode(CommandView command);

  // 7.7.2
  void WriteLoopbackMode(CommandView command);

  // LE Controller Commands
  // Bluetooth Core Specification Version 4.2 Volume 2 Part E 7.8

  // 7.8.1
  void LeSetEventMask(CommandView command);

  // 7.8.2 - 7.8.93
  void LeReadBufferSizeV1(CommandView command);
  void LeReadBufferSizeV2(CommandView command);

  // 7.8.3
  void LeReadLocalSupportedFeatures(CommandView command);

  // 7.8.4
  void LeSetRandomAddress(CommandView command);

  // 7.8.5 - 7.8.9
  void LeSetAdvertisingParameters(CommandView command);
  void LeReadAdvertisingPhysicalChannelTxPower(CommandView command);
  void LeSetAdvertisingData(CommandView command);
  void LeSetScanResponseData(CommandView command);
  void LeSetAdvertisingEnable(CommandView command);

  // 7.8.10 - 7.8.11
  void LeSetScanParameters(CommandView command);
  void LeSetScanEnable(CommandView command);

  // 7.8.12 - 7.8.13
  void LeCreateConnection(CommandView command);
  void LeCreateConnectionCancel(CommandView command);

  // 7.8.14 - 7.8.17
  void LeReadFilterAcceptListSize(CommandView command);
  void LeClearFilterAcceptList(CommandView command);
  void LeAddDeviceToFilterAcceptList(CommandView command);
  void LeRemoveDeviceFromFilterAcceptList(CommandView command);

  // 7.8.18
  void LeConnectionUpdate(CommandView command);

  // 7.8.21
  void LeReadRemoteFeatures(CommandView command);

  // 7.8.22
  void LeEncrypt(CommandView command);

  // 7.8.23
  void LeRand(CommandView command);

  // 7.8.24
  void LeStartEncryption(CommandView command);

  // 7.8.25 - 7.8.26
  void LeLongTermKeyRequestReply(CommandView command);
  void LeLongTermKeyRequestNegativeReply(CommandView command);

  // 7.8.27
  void LeReadSupportedStates(CommandView command);

  // 7.8.31 - 7.8.32
  void LeRemoteConnectionParameterRequestReply(CommandView command);
  void LeRemoteConnectionParameterRequestNegativeReply(CommandView command);

  // 7.8.34 - 7.8.35
  void LeReadSuggestedDefaultDataLength(CommandView command);
  void LeWriteSuggestedDefaultDataLength(CommandView command);

  // 7.8.38 - 7.8.41
  void LeAddDeviceToResolvingList(CommandView command);
  void LeRemoveDeviceFromResolvingList(CommandView command);
  void LeClearResolvingList(CommandView command);
  void LeReadResolvingListSize(CommandView command);

  // 7.8.42 - 7.8.43
  void LeReadPeerResolvableAddress(CommandView command);
  void LeReadLocalResolvableAddress(CommandView command);

  // 7.8.44 - 7.8.45
  void LeSetAddressResolutionEnable(CommandView command);
  void LeSetResolvablePrivateAddressTimeout(CommandView command);

  // 7.8.46
  void LeReadMaximumDataLength(CommandView command);

  // 7.8.47 - 7.8.49
  void LeReadPhy(CommandView command);
  void LeSetDefaultPhy(CommandView command);
  void LeSetPhy(CommandView command);

  // 7.8.52 - 7.8.60
  void LeSetAdvertisingSetRandomAddress(CommandView command);
  void LeSetExtendedAdvertisingParameters(CommandView command);
  void LeSetExtendedAdvertisingData(CommandView command);
  void LeSetExtendedScanResponseData(CommandView command);
  void LeSetExtendedAdvertisingEnable(CommandView command);
  void LeReadMaximumAdvertisingDataLength(CommandView command);
  void LeReadNumberOfSupportedAdvertisingSets(CommandView command);
  void LeRemoveAdvertisingSet(CommandView command);
  void LeClearAdvertisingSets(CommandView command);

  // 7.8.61 - 7.8.63
  void LeSetPeriodicAdvertisingParameters(CommandView command);
  void LeSetPeriodicAdvertisingData(CommandView command);
  void LeSetPeriodicAdvertisingEnable(CommandView command);

  // 7.8.67 - 7.8.69
  void LePeriodicAdvertisingCreateSync(CommandView command);
  void LePeriodicAdvertisingCreateSyncCancel(CommandView command);
  void LePeriodicAdvertisingTerminateSync(CommandView command);

  // 7.8.70 - 7.8.73
  void LeAddDeviceToPeriodicAdvertiserList(CommandView command);
  void LeRemoveDeviceFromPeriodicAdvertiserList(CommandView command);
  void LeClearPeriodicAdvertiserList(CommandView command);
  void LeReadPeriodicAdvertiserListSize(CommandView command);

  // 7.8.64 - 7.8.65
  void LeSetExtendedScanParameters(CommandView command);
  void LeSetExtendedScanEnable(CommandView command);

  // 7.8.66
  void LeExtendedCreateConnection(CommandView command);

  // 7.8.77
  void LeSetPrivacyMode(CommandView command);

  // 7.8.108
  void LeRequestPeerSca(CommandView command);

  // 7.8.115
  void LeSetHostFeature(CommandView command);

  // Vendor-specific Commands
  void LeGetVendorCapabilities(CommandView command);
  void LeBatchScan(CommandView command);
  void LeApcf(CommandView command);
  void LeGetControllerActivityEnergyInfo(CommandView command);
  void LeExSetScanParameters(CommandView command);
  void GetControllerDebugInfo(CommandView command);

  // CSR vendor command.
  // Implement the command specific to the CSR controller
  // used specifically by the PTS tool to pass certification tests.
  void CsrVendorCommand(CommandView command);
  void CsrReadVarid(CsrVarid varid, std::vector<uint8_t>& value) const;
  void CsrWriteVarid(CsrVarid varid, std::vector<uint8_t> const& value) const;
  void CsrReadPskey(CsrPskey pskey, std::vector<uint8_t>& value) const;
  void CsrWritePskey(CsrPskey pskey, std::vector<uint8_t> const& value);

  // Command pass-through.
  void ForwardToLm(CommandView command);
  void ForwardToLl(CommandView command);

 protected:
  // Controller configuration.
  ControllerProperties properties_;

  // Link Layer state.
  LinkLayerController link_layer_controller_{address_, properties_, id_};

 private:
  // Send a HCI_Command_Complete event for the specified op_code with
  // the error code UNKNOWN_OPCODE.
  void SendCommandCompleteUnknownOpCodeEvent(
      bluetooth::hci::OpCode op_code) const;

  // Callbacks to send packets back to the HCI.
  std::function<void(std::shared_ptr<bluetooth::hci::AclBuilder>)> send_acl_;
  std::function<void(std::shared_ptr<bluetooth::hci::EventBuilder>)>
      send_event_;
  std::function<void(std::shared_ptr<bluetooth::hci::ScoBuilder>)> send_sco_;
  std::function<void(std::shared_ptr<bluetooth::hci::IsoBuilder>)> send_iso_;

  // Loopback mode (Vol 4, Part E § 7.6.1).
  // The local loopback mode is used to pass the android Vendor Test Suite
  // with RootCanal.
  bluetooth::hci::LoopbackMode loopback_mode_{LoopbackMode::NO_LOOPBACK};

  // Random value generator, always seeded with 0 to be deterministic.
  std::mt19937_64 random_generator_{};

  // Flag set to true after the HCI Reset command has been received
  // the first time.
  bool controller_reset_{false};

  // Map command opcodes to the corresponding bit index in the
  // supported command mask.
  static const std::unordered_map<OpCode, OpCodeIndex>
      hci_command_op_code_to_index_;

  // Map all implemented opcodes to the function implementing the handler
  // for the associated command. The map should be a subset of the
  // supported_command field in the properties_ object. Commands
  // that are supported but not implemented will raise a fatal assert.
  using CommandHandler =
      std::function<void(DualModeController*, bluetooth::hci::CommandView)>;
  static const std::unordered_map<OpCode, CommandHandler> hci_command_handlers_;
};

}  // namespace rootcanal
