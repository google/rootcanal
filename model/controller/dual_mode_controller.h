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
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "controller_properties.h"
#include "hci/address.h"
#include "hci/hci_packets.h"
#include "link_layer_controller.h"
#include "model/controller/vendor_commands/csr.h"
#include "model/devices/device.h"
#include "model/setup/async_manager.h"
#ifndef ROOTCANAL_LMP
#include "security_manager.h"
#endif /* !ROOTCANAL_LMP */

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
class DualModeController
    : public Device,
      public std::enable_shared_from_this<DualModeController> {
  static constexpr uint16_t kSecurityManagerNumKeys = 15;

 public:
  // Sets all of the methods to be used as callbacks in the HciHandler.
  DualModeController(const std::string& properties_filename = "",
                     uint16_t num_keys = kSecurityManagerNumKeys);

  ~DualModeController() = default;

  // Device methods.
  virtual std::string GetTypeString() const override;

  virtual void ReceiveLinkLayerPacket(
      model::packets::LinkLayerPacketView incoming, Phy::Type type,
      int8_t rssi) override;

  virtual void Tick() override;
  virtual void Close() override;

  // Route commands and data from the stack.
  void HandleAcl(std::shared_ptr<std::vector<uint8_t>> acl_packet);
  void HandleCommand(std::shared_ptr<std::vector<uint8_t>> command_packet);
  void HandleSco(std::shared_ptr<std::vector<uint8_t>> sco_packet);
  void HandleIso(std::shared_ptr<std::vector<uint8_t>> iso_packet);

  // Set the callbacks for scheduling tasks.
  void RegisterTaskScheduler(
      std::function<AsyncTaskId(std::chrono::milliseconds, TaskCallback)>
          task_scheduler);

  void RegisterPeriodicTaskScheduler(
      std::function<AsyncTaskId(std::chrono::milliseconds,
                                std::chrono::milliseconds, TaskCallback)>
          periodic_task_scheduler);

  void RegisterTaskCancel(std::function<void(AsyncTaskId)> cancel);

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

  // 7.1.10
  void LinkKeyRequestReply(CommandView command);

  // 7.1.11
  void LinkKeyRequestNegativeReply(CommandView command);

  // 7.1.12
  void PinCodeRequestReply(CommandView command);

  // 7.1.13
  void PinCodeRequestNegativeReply(CommandView command);

  // 7.1.14
  void ChangeConnectionPacketType(CommandView command);

  // 7.1.15
  void AuthenticationRequested(CommandView command);

  // 7.1.16
  void SetConnectionEncryption(CommandView command);

  // 7.1.17
  void ChangeConnectionLinkKey(CommandView command);

  // 7.1.18
  void CentralLinkKey(CommandView command);

  // 7.1.19
  void RemoteNameRequest(CommandView command);

  // 7.2.8
  void SwitchRole(CommandView command);

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

  // 7.1.29
  void IoCapabilityRequestReply(CommandView command);

  // 7.1.30
  void UserConfirmationRequestReply(CommandView command);

  // 7.1.31
  void UserConfirmationRequestNegativeReply(CommandView command);

  // 7.1.32
  void UserPasskeyRequestReply(CommandView command);

  // 7.1.33
  void UserPasskeyRequestNegativeReply(CommandView command);

  // 7.1.34
  void RemoteOobDataRequestReply(CommandView command);

  // 7.1.35
  void RemoteOobDataRequestNegativeReply(CommandView command);

  // 7.1.36
  void IoCapabilityRequestNegativeReply(CommandView command);

  // 7.1.45
  void EnhancedSetupSynchronousConnection(CommandView command);

  // 7.1.46
  void EnhancedAcceptSynchronousConnection(CommandView command);

  // 7.1.53
  void RemoteOobExtendedDataRequestReply(CommandView command);

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

  // 7.3.15
  void ReadPageTimeout(CommandView command);

  // 7.3.16
  void WritePageTimeout(CommandView command);

  // 7.3.17
  void ReadScanEnable(CommandView command);

  // 7.3.18
  void WriteScanEnable(CommandView command);

  // 7.3.19
  void ReadPageScanActivity(CommandView command);

  // 7.3.20
  void WritePageScanActivity(CommandView command);

  // 7.3.21
  void ReadInquiryScanActivity(CommandView command);

  // 7.3.22
  void WriteInquiryScanActivity(CommandView command);

  // 7.3.23
  void ReadAuthenticationEnable(CommandView command);

  // 7.3.24
  void WriteAuthenticationEnable(CommandView command);

  // 7.3.26
  void WriteClassOfDevice(CommandView command);

  // 7.3.28
  void WriteVoiceSetting(CommandView command);

  // 7.3.36
  void ReadSynchronousFlowControlEnable(CommandView command);

  // 7.3.37
  void WriteSynchronousFlowControlEnable(CommandView command);

  // 7.3.39
  void HostBufferSize(CommandView command);

  // 7.3.42
  void WriteLinkSupervisionTimeout(CommandView command);

  // 7.3.43
  void ReadNumberOfSupportedIac(CommandView command);

  // 7.3.44
  void ReadCurrentIacLap(CommandView command);

  // 7.3.45
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

  // 7.3.63
  void SendKeypressNotification(CommandView command);

  // 7.3.66
  void EnhancedFlush(CommandView command);

  // 7.3.69
  void SetEventMaskPage2(CommandView command);

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

  // 7.8.2 and 7.8.93
  void LeReadBufferSizeV1(CommandView command);
  void LeReadBufferSizeV2(CommandView command);

  // 7.8.3
  void LeReadLocalSupportedFeatures(CommandView command);

  // 7.8.4
  void LeSetRandomAddress(CommandView command);

  // 7.8.5
  void LeSetAdvertisingParameters(CommandView command);

  // 7.8.6
  void LeReadAdvertisingPhysicalChannelTxPower(CommandView command);

  // 7.8.7
  void LeSetAdvertisingData(CommandView command);

  // 7.8.8
  void LeSetScanResponseData(CommandView command);

  // 7.8.9
  void LeSetAdvertisingEnable(CommandView command);

  // 7.8.10
  void LeSetScanParameters(CommandView command);

  // 7.8.11
  void LeSetScanEnable(CommandView command);

  // 7.8.12
  void LeCreateConnection(CommandView command);

  // 7.8.13
  void LeCreateConnectionCancel(CommandView command);

  // 7.8.14
  void LeReadFilterAcceptListSize(CommandView command);

  // 7.8.15
  void LeClearFilterAcceptList(CommandView command);

  // 7.8.16
  void LeAddDeviceToFilterAcceptList(CommandView command);

  // 7.8.17
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

  // 7.8.25
  void LeLongTermKeyRequestReply(CommandView command);

  // 7.8.26
  void LeLongTermKeyRequestNegativeReply(CommandView command);

  // 7.8.27
  void LeReadSupportedStates(CommandView command);

  // 7.8.31
  void LeRemoteConnectionParameterRequestReply(CommandView command);

  // 7.8.32
  void LeRemoteConnectionParameterRequestNegativeReply(CommandView command);

  // 7.8.34
  void LeReadSuggestedDefaultDataLength(CommandView command);

  // 7.8.35
  void LeWriteSuggestedDefaultDataLength(CommandView command);

  // 7.8.38
  void LeAddDeviceToResolvingList(CommandView command);

  // 7.8.39
  void LeRemoveDeviceFromResolvingList(CommandView command);

  // 7.8.40
  void LeClearResolvingList(CommandView command);

  // 7.8.41
  void LeReadResolvingListSize(CommandView command);

  // 7.8.44
  void LeSetAddressResolutionEnable(CommandView command);

  // 7.8.45
  void LeSetResolvablePrivateAddressTimeout(CommandView command);

  // 7.8.46
  void LeReadMaximumDataLength(CommandView command);

  // 7.8.52
  void LeSetAdvertisingSetRandomAddress(CommandView command);

  // 7.8.53
  void LeSetExtendedAdvertisingParameters(CommandView command);

  // 7.8.54
  void LeSetExtendedAdvertisingData(CommandView command);

  // 7.8.55
  void LeSetExtendedScanResponseData(CommandView command);

  // 7.8.56
  void LeSetExtendedAdvertisingEnable(CommandView command);

  // 7.8.57
  void LeReadMaximumAdvertisingDataLength(CommandView command);

  // 7.8.58
  void LeReadNumberOfSupportedAdvertisingSets(CommandView command);

  // 7.8.59
  void LeRemoveAdvertisingSet(CommandView command);

  // 7.8.60
  void LeClearAdvertisingSets(CommandView command);

  // 7.8.64
  void LeSetExtendedScanParameters(CommandView command);

  // 7.8.65
  void LeSetExtendedScanEnable(CommandView command);

  // 7.8.66
  void LeExtendedCreateConnection(CommandView command);

  // 7.8.77
  void LeSetPrivacyMode(CommandView command);

  // 7.8.96 - 7.8.110
  void LeReadIsoTxSync(CommandView command);
  void LeSetCigParameters(CommandView command);
  void LeCreateCis(CommandView command);
  void LeRemoveCig(CommandView command);
  void LeAcceptCisRequest(CommandView command);
  void LeRejectCisRequest(CommandView command);
  void LeCreateBig(CommandView command);
  void LeTerminateBig(CommandView command);
  void LeBigCreateSync(CommandView command);
  void LeBigTerminateSync(CommandView command);
  void LeRequestPeerSca(CommandView command);
  void LeSetupIsoDataPath(CommandView command);
  void LeRemoveIsoDataPath(CommandView command);

  // 7.8.115
  void LeSetHostFeature(CommandView command);

  // Required commands for handshaking with hci driver
  void ReadClassOfDevice(CommandView command);
  void ReadVoiceSetting(CommandView command);
  void ReadConnectionAcceptTimeout(CommandView command);
  void WriteConnectionAcceptTimeout(CommandView command);

  // Vendor-specific Commands

  void LeGetVendorCapabilities(CommandView command);
  void LeEnergyInfo(CommandView command);
  void LeMultiAdv(CommandView command);
  void LeAdvertisingFilter(CommandView command);
  void LeExtendedScanParams(CommandView command);

  // CSR vendor command.
  // Implement the command specific to the CSR controller
  // used specifically by the PTS tool to pass certification tests.
  void CsrVendorCommand(CommandView command);
  void CsrReadVarid(CsrVarid varid, std::vector<uint8_t>& value);
  void CsrWriteVarid(CsrVarid varid, std::vector<uint8_t> const& value);
  void CsrReadPskey(CsrPskey pskey, std::vector<uint8_t>& value);
  void CsrWritePskey(CsrPskey pskey, std::vector<uint8_t> const& value);

  void SetTimerPeriod(std::chrono::milliseconds new_period);
  void StartTimer();
  void StopTimer();

 protected:
  // Controller configuration.
  ControllerProperties properties_;

  // Link Layer state.
  LinkLayerController link_layer_controller_{address_, properties_};

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
  bluetooth::hci::LoopbackMode loopback_mode_;

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

#ifndef ROOTCANAL_LMP
  SecurityManager security_manager_;
#endif /* ROOTCANAL_LMP */

  DualModeController(const DualModeController& other) = delete;
  DualModeController& operator=(const DualModeController& other) = delete;
};

}  // namespace rootcanal
