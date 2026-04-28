# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from rootcanal.packets import hci
from rootcanal.packets.hci import ErrorCode
from rootcanal.packets import ll
from rootcanal.bluetooth import Address
from test.controller_test import ControllerTest


class Test(ControllerTest):
    IUT_CS_CAPABILITIES = {
        "mode_types": 0x01,  # Mode 3
        "rtt_capability": 0x07,  # RTT_AA_ONLY_N | RTT_SOUNDING_N | RTT_RANDOM_PAYLOAD_N
        "rtt_aa_only_n": 1,
        "rtt_sounding_n": 1,
        "rtt_random_sequence_n": 1,
        "nadm_sounding_capability": 0,
        "nadm_random_capability": 0,
        "cs_sync_phy_capability": 0x01,  # LE_1M
        "num_ant": 1,
        "max_ant_path": 1,
        "role": 0x03,  # Initiator and Reflector
        "no_fae": 0,
        "channel_selection_3c": 0,
        "sounding_pct_estimate": 0,
        "num_configs": 3,
        "max_procedures_supported": 1,
        "t_sw": 10,
        "t_ip1_capability": 1,
        "t_ip2_capability": 1,
        "t_fcs_capability": 1,
        "t_pm_capability": 1,
        "tx_snr_capability": 1,
    }

    REMOTE_CS_CAPABILITIES = {
        "num_config_supported": 1,
        "max_consecutive_procedures_supported": 1,
        "num_antennae_supported": 1,
        "max_antenna_paths_supported": 1,
        "roles_supported": 0x02,  # Reflector
        "modes_supported": 0x01,  # Mode 3
        "rtt_capability": 0x01,
        "rtt_aa_only_n": 10,
        "rtt_sounding_n": 0,
        "rtt_random_sequence_n": 0,
        "nadm_sounding_capability": 0,
        "nadm_random_capability": 0,
        "cs_sync_phys_supported": 0x01,
        "subfeatures_supported": 0,
        "t_ip1_times_supported": 0,
        "t_ip2_times_supported": 0,
        "t_fcs_times_supported": 0,
        "t_pm_times_supported": 0,
        "t_sw_time_supported": 10,
        "tx_snr_capability": 0,
    }

    LOCAL_CS_CAPABILITIES = {
        "mode_types": 0x01,  # Mode 3
        "rtt_capability": 0x01,  # RTT AA Only N
        "rtt_aa_only_n": 10,
        "rtt_sounding_n": 0,
        "rtt_random_sequence_n": 0,
        "nadm_sounding_capability": 0,
        "nadm_random_capability": 0,
        "cs_sync_phy_capability": 0x01,  # LE 1M PHY
        "num_ant": 1,
        "max_ant_path": 1,
        "role": 0x02,  # Reflector
        "no_fae": 0,
        "channel_selection_3c": 1,
        "sounding_pct_estimate": 0,
        "num_configs": 1,
        "max_procedures_supported": 1,
        "t_sw": 10,
        "t_ip1_capability": 0,
        "t_ip2_capability": 0,
        "t_fcs_capability": 0,
        "t_pm_capability": 0,
        "tx_snr_capability": 0,
    }

    # LL/CS/PER/INI/BV-02-C [Initiate Capabilities Exchange, Peripheral, Initiator]
    async def test(self):
        """
        Test the CS Capabilities Exchange procedure initiated by the local controller.

        This test verifies the following sequence from the specification:
        1. The Upper Tester sends an HCI_LE_CS_Read_Local_Supported_Capabilities command.
        2. The IUT sends a successful HCI_Command_Complete event.
        3. The Upper Tester sends an HCI_LE_CS_Create_Config command.
        4. The IUT sends an HCI_Command_Status event (Status != 0, skipping to Step 10).
        10. Disconnect and reconnect the ACL connection.
        11. The Upper Tester sends an HCI_LE_CS_Read_Remote_Supported_Capabilities command.
        12. The IUT sends a successful HCI_Command_Status event.
        13. The IUT sends an LL_CS_CAPABILITIES_REQ PDU to the Lower Tester with RTT_AA_Only_N > 0
            and all other capabilities properly set (Pass Verdict condition).
        14. The Upper Tester sends an HCI_LE_CS_Create_Config command with valid parameters.
        15C.1 The IUT sends an HCI_Command_Status with Status > 0 (COMMAND_DISALLOWED).
        16. The Lower Tester sends an LL_CS_CAPABILITIES_RSP PDU to the IUT.
        17. The IUT sends an HCI_LE_CS_Read_Remote_Supported_Capabilities_Complete event.
        """
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller

        # Enable Channel Sounding Host Support.
        await self.enable_channel_sounding_host_support()

        # Prelude: Establish an ACL connection with the IUT.
        acl_connection_handle = await self.establish_le_connection_peripheral(
            peer_address
        )

        # 1. The Upper Tester sends an
        # HCI_LE_CS_Read_Local_Supported_Capabilities command to the IUT.
        controller.send_cmd(hci.LeCsReadLocalSupportedCapabilities())

        # 2. The IUT sends a successful HCI_Command_Complete event to the Upper Tester.
        await self.expect_cmd_complete(hci.LeCsReadLocalSupportedCapabilitiesComplete)

        # 3. The Upper Tester sends an HCI_LE_CS_Create_Config command to the
        # IUT with valid parameters.
        controller.send_cmd(
            hci.LeCsCreateConfig(
                connection_handle=acl_connection_handle,
                config_id=0,
                create_context=hci.CsCreateContext.BOTH_LOCAL_AND_REMOTE_CONTROLLER,
                main_mode_type=hci.CsMainModeType.MODE_2,
                sub_mode_type=hci.CsSubModeType.MODE_1,
                min_main_mode_steps=2,
                max_main_mode_steps=5,
                main_mode_repetition=0,
                mode_0_steps=1,
                role=hci.CsRole.INITIATOR,
                rtt_type=hci.CsRttType.RTT_AA_ONLY,
                cs_sync_phy=hci.CsSyncPhy.LE_1M_PHY,
                channel_map=[
                    0x00,
                    0xFC,
                    0xFF,
                    0x7F,
                    0xFC,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0x1F,
                ],
                channel_map_repetition=1,
                channel_selection_type=hci.CsChannelSelectionType.TYPE_3C,
                ch3c_shape=hci.CsCh3cShape.HAT_SHAPE,
                ch3c_jump=2,
                reserved=0,
            )
        )

        # 4. The IUT sends an HCI_Command_Status event to the Upper Tester. If
        # Status is not 0, skip to Step 10.
        await self.expect_evt(
            hci.LeCsCreateConfigStatus(
                status=ErrorCode.COMMAND_DISALLOWED, num_hci_command_packets=1
            )
        )

        # 10. The IUT and the Lower Tester disconnect and reconnect the ACL
        # connection using the Initial Conditions.
        controller.send_cmd(
            hci.Disconnect(
                connection_handle=acl_connection_handle,
                reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST,
            )
        )
        await self.expect_evt(
            hci.DisconnectStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1)
        )

        await self.expect_ll(
            ll.Disconnect(
                source_address=controller.address,
                destination_address=peer_address,
                reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST,
            )
        )

        await self.expect_evt(
            hci.DisconnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST,
            )
        )

        # Reconnect
        acl_connection_handle = await self.establish_le_connection_peripheral(
            peer_address
        )

        # 11. The Upper Tester sends an
        # HCI_LE_CS_Read_Remote_Supported_Capabilities command to the IUT.
        controller.send_cmd(
            hci.LeCsReadRemoteSupportedCapabilities(
                connection_handle=acl_connection_handle
            )
        )

        # 12. The IUT sends a successful HCI_Command_Status event to the Upper Tester.
        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 13. The IUT sends an LL_CS_CAPABILITIES_REQ PDU to the Lower Tester
        # with RTT_AA_Only_N > 0.
        await self.expect_ll(
            ll.LlCsCapabilitiesReq(
                source_address=controller.address,
                destination_address=peer_address,
                **self.IUT_CS_CAPABILITIES,
            )
        )

        # 14. The Upper Tester sends an HCI_LE_CS_Create_Config command to the
        # IUT with valid parameters.
        controller.send_cmd(
            hci.LeCsCreateConfig(
                connection_handle=acl_connection_handle,
                config_id=0,
                create_context=hci.CsCreateContext.BOTH_LOCAL_AND_REMOTE_CONTROLLER,
                main_mode_type=hci.CsMainModeType.MODE_2,
                sub_mode_type=hci.CsSubModeType.MODE_1,
                min_main_mode_steps=2,
                max_main_mode_steps=5,
                main_mode_repetition=0,
                mode_0_steps=1,
                role=hci.CsRole.INITIATOR,
                rtt_type=hci.CsRttType.RTT_AA_ONLY,
                cs_sync_phy=hci.CsSyncPhy.LE_1M_PHY,
                channel_map=[
                    0x00,
                    0xFC,
                    0xFF,
                    0x7F,
                    0xFC,
                    0xFF,
                    0xFF,
                    0xFF,
                    0xFF,
                    0x1F,
                ],
                channel_map_repetition=1,
                channel_selection_type=hci.CsChannelSelectionType.TYPE_3C,
                ch3c_shape=hci.CsCh3cShape.HAT_SHAPE,
                ch3c_jump=2,
                reserved=0,
            )
        )

        # 15C.1 The IUT sends an HCI_Command_Status with Status > 0. Steps 18–20 are skipped.
        await self.expect_evt(
            hci.LeCsCreateConfigStatus(
                status=ErrorCode.COMMAND_DISALLOWED, num_hci_command_packets=1
            )
        )

        # 16. The Lower Tester sends an LL_CS_CAPABILITIES_RSP PDU to the IUT.
        controller.send_ll(
            ll.LlCsCapabilitiesRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                **self.LOCAL_CS_CAPABILITIES,
            )
        )

        # 17. The IUT sends an
        # HCI_LE_CS_Read_Remote_Supported_Capabilities_Complete event to the
        # Upper Tester.
        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                **self.REMOTE_CS_CAPABILITIES,
            )
        )
