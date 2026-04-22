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

import hci_packets as hci
from hci_packets import ErrorCode
import link_layer_packets as ll
from py.bluetooth import Address
from py.controller import ControllerTest

class Test(ControllerTest):
    REMOTE_CS_CAPABILITIES = {
        "num_config_supported": 4,
        "max_consecutive_procedures_supported": 1,
        "num_antennae_supported": 1,
        "max_antenna_paths_supported": 1,
        "roles_supported": 0x01,  # Initiator
        "modes_supported": 0x01,
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

    LL_CS_CONFIG_REQ_PARAMS = {
        "channel_map_repetition": 1,
        "main_mode_type": 1,
        "sub_mode_type": 0xFF,
        "min_main_mode_steps": 0,
        "max_main_mode_steps": 0,
        "main_mode_repetition": 0,
        "mode_0_steps": 3,
        "cs_sync_phy": 1,
        "rtt_type": 0,
        "role": 1,  # IUT is Reflector
        "channel_selection_type": 1,
        "ch3c_shape": 0,
        "ch3c_jump": 2,
        "t_ip1": 0,
        "t_ip2": 0,
        "t_fcs": 0,
        "t_pm": 0,
    }

    LE_CS_CREATE_CONFIG_PARAMS = {
        "main_mode_type": hci.CsMainModeType.MODE_1,
        "sub_mode_type": hci.CsSubModeType.UNUSED,
        "min_main_mode_steps": 0,
        "max_main_mode_steps": 0,
        "main_mode_repetition": 0,
        "mode_0_steps": 3,
        "role": hci.CsRole.REFLECTOR,
        "rtt_type": hci.CsRttType.RTT_AA_ONLY,
        "cs_sync_phy": hci.CsSyncPhy.LE_1M_PHY,
        "channel_map_repetition": 1,
        "channel_selection_type": hci.CsChannelSelectionType.TYPE_3C,
        "ch3c_shape": hci.CsCh3cShape.HAT_SHAPE,
        "ch3c_jump": 2,
        "reserved": 0,
    }

    LE_CS_CONFIG_COMPLETE_PARAMS = {
        "action": hci.CsAction.CONFIG_CREATED,
        "t_ip1_time": 0,
        "t_ip2_time": 0,
        "t_fcs_time": 0,
        "t_pm_time": 0,
        **LE_CS_CREATE_CONFIG_PARAMS
    }

    # LL/CS/PER/REF/BV-36-C [Remove CS Configuration]
    async def test(self):
        """
        Test removing a CS configuration.
        """
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller
        config_id = 0

        # Enable Channel Sounding Host Support.
        await self.enable_channel_sounding_host_support()

        # Initial Conditions: Establish an ACL connection with the IUT (Peripheral)
        acl_connection_handle = await self.establish_le_connection_peripheral(
            peer_address
        )

        # Encrypt the connection
        await self.le_start_encryption(acl_connection_handle, peer_address)

        # Exchange CS capabilities (Lower Tester is Central/Initiator)
        controller.send_cmd(
            hci.LeCsWriteCachedRemoteSupportedCapabilities(
                connection_handle=acl_connection_handle,
                **self.REMOTE_CS_CAPABILITIES,
            )
        )
        await self.expect_evt(
            hci.LeCsWriteCachedRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
                connection_handle=acl_connection_handle,
            )
        )

        # Set Default Settings: IUT is Reflector
        controller.send_cmd(
            hci.LeCsSetDefaultSettings(
                connection_handle=acl_connection_handle,
                role_enable=0x02,  # Reflector
                cs_sync_antenna_selection=0x01,  # ANTENNA_1
                max_tx_power=10,
            )
        )
        await self.expect_evt(
            hci.LeCsSetDefaultSettingsComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
                connection_handle=acl_connection_handle,
            )
        )

        # CS Security Enable: Lower Tester (Central) initiates
        controller.send_ll(
            ll.LlCsSecurityEnableReq(
                source_address=peer_address,
                destination_address=controller.address,
                cs_iv_c=0x1234567890ABCDEF,
                cs_in_c=0x12345678,
                cs_pv_c=0xFEDCBA0987654321,
            )
        )

        await self.expect_ll(
            ll.LlCsSecurityEnableRsp(
                source_address=controller.address,
                destination_address=peer_address,
                status=ErrorCode.SUCCESS,
                cs_iv_p=self.Any,
                cs_in_p=self.Any,
                cs_pv_p=self.Any,
            )
        )

        await self.expect_evt(
            hci.LeCsSecurityEnableComplete(
                status=ErrorCode.SUCCESS, connection_handle=acl_connection_handle
            )
        )

        # Create CS Configuration
        channel_map_bytes = [0xFC, 0xFF, 0x7F, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F]

        controller.send_cmd(
            hci.LeCsCreateConfig(
                connection_handle=acl_connection_handle,
                config_id=config_id,
                create_context=hci.CsCreateContext.BOTH_LOCAL_AND_REMOTE_CONTROLLER,
                channel_map=channel_map_bytes,
                **self.LE_CS_CREATE_CONFIG_PARAMS,
            )
        )
        await self.expect_evt(
            hci.LeCsCreateConfigStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # IUT sends LL_CS_CONFIG_REQ PDU (role=1 for Reflector)
        await self.expect_ll(
            ll.LlCsConfigReq(
                source_address=controller.address,
                destination_address=peer_address,
                config_id=config_id,
                action=1,
                channel_map=channel_map_bytes,
                **self.LL_CS_CONFIG_REQ_PARAMS,
            )
        )

        # Lower Tester responds with LL_CS_CONFIG_RSP
        controller.send_ll(
            ll.LlCsConfigRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                config_id=config_id,
            )
        )

        # IUT sends HCI_LE_CS_Config_Complete event
        await self.expect_evt(
            hci.LeCsConfigComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                config_id=config_id,
                channel_map=channel_map_bytes,
                **self.LE_CS_CONFIG_COMPLETE_PARAMS,
            )
        )

        # End of initial conditions

        # 1. The Upper Tester sends an HCI_LE_CS_Set_Procedure_Parameters
        controller.send_cmd(
            hci.LeCsSetProcedureParameters(
                connection_handle=acl_connection_handle,
                config_id=config_id,
                max_procedure_len=0x07D0,
                min_procedure_interval=0x32,
                max_procedure_interval=0x32,
                max_procedure_count=2,
                min_subevent_len=2500,
                max_subevent_len=2500,
                tone_antenna_config_selection=0,
                phy=hci.CsPhy.LE_1M_PHY,
                tx_power_delta=0,
                preferred_peer_antenna=hci.CsPreferredPeerAntenna.USE_FIRST_ORDERED_ANTENNA_ELEMENT,
                snr_control_initiator=hci.CsSnrControl.NOT_APPLIED,
                snr_control_reflector=hci.CsSnrControl.NOT_APPLIED,
            )
        )

        await self.expect_evt(
            hci.LeCsSetProcedureParametersComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
                connection_handle=acl_connection_handle,
            )
        )

        # 2. The Upper Tester sends an HCI_LE_CS_Procedure_Enable command to the IUT
        controller.send_cmd(
            hci.LeCsProcedureEnable(
                connection_handle=acl_connection_handle,
                config_id=config_id,
                procedure_enable=hci.Enable.ENABLED,
            )
        )

        await self.expect_evt(
            hci.LeCsProcedureEnableStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 3. The IUT sends an LL_CS_REQ PDU to the Lower Tester.
        await self.expect_ll(
            ll.LlCsReq(
                source_address=controller.address,
                destination_address=peer_address,
                config_id=config_id,
                conn_event_count=self.Any,
                offset_min=self.Any,
                offset_max=self.Any,
                max_procedure_len=0x07D0,
                event_interval=self.Any,
                subevents_per_event=1,
                subevent_interval=0,
                subevent_len=2500,
                procedure_interval=0x32,
                procedure_count=2,
                aci=0,
                preferred_peer_ant=0x01,
                phy=1,
                pwr_delta=0,
                tx_snr_i=5,
                tx_snr_r=5,
            )
        )

        # 4. Alternative 4B (IUT is Peripheral):
        # 4B.1 The Lower Tester sends an LL_CS_IND PDU to the IUT.
        controller.send_ll(
            ll.LlCsInd(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                config_id=config_id,
                conn_event_count=0,
                offset=0,
                event_interval=0,
                subevents_per_event=1,
                subevent_interval=0,
                subevent_len=2500,
                aci=0,
                phy=1,
                pwr_delta=0,
            )
        )

        # 5. The IUT sends an HCI_LE_CS_Procedure_Enable_Complete event
        await self.expect_evt(
            hci.LeCsProcedureEnableComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                config_id=config_id,
                state=hci.Enable.ENABLED,
                tone_antenna_config_selection=self.Any,
                selected_tx_power=self.Any,
                subevent_len=self.Any,
                subevents_per_event=self.Any,
                subevent_interval=self.Any,
                event_interval=self.Any,
                procedure_interval=self.Any,
                procedure_count=self.Any,
                max_procedure_len=self.Any,
            )
        )

        # 6. Channel sounding execution (skipped)
        # 7. Subevent result (skipped)

        # 8. The Upper Tester sends an HCI_LE_CS_Remove_Config command
        controller.send_cmd(
            hci.LeCsRemoveConfig(
                connection_handle=acl_connection_handle,
                config_id=config_id,
            )
        )

        await self.expect_evt(
            hci.LeCsRemoveConfigStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 9. The IUT sends an LL_CS_CONFIG_REQ PDU with Action set to 0b00
        # (Remove)
        await self.expect_ll(
            ll.LlCsConfigReq(
                source_address=controller.address,
                destination_address=peer_address,
                config_id=config_id,
                action=0, # Remove
                channel_map=self.Any,
                channel_map_repetition=self.Any,
                main_mode_type=self.Any,
                sub_mode_type=self.Any,
                min_main_mode_steps=self.Any,
                max_main_mode_steps=self.Any,
                main_mode_repetition=self.Any,
                mode_0_steps=self.Any,
                cs_sync_phy=self.Any,
                rtt_type=self.Any,
                role=self.Any,
                channel_selection_type=self.Any,
                ch3c_shape=self.Any,
                ch3c_jump=self.Any,
                t_ip1=self.Any,
                t_ip2=self.Any,
                t_fcs=self.Any,
                t_pm=self.Any,
            )
        )

        # 10. The Lower Tester sends an LL_CS_CONFIG_RSP PDU
        controller.send_ll(
            ll.LlCsConfigRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                config_id=config_id,
            )
        )

        # 11. The IUT sends an HCI_LE_CS_Config_Complete event with Action set
        # to 0x00
        await self.expect_evt(
            hci.LeCsConfigComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                config_id=config_id,
                action=hci.CsAction.CONFIG_REMOVED,
                main_mode_type=self.Any,
                sub_mode_type=self.Any,
                min_main_mode_steps=self.Any,
                max_main_mode_steps=self.Any,
                main_mode_repetition=self.Any,
                mode_0_steps=self.Any,
                role=self.Any,
                rtt_type=self.Any,
                cs_sync_phy=self.Any,
                channel_map=self.Any,
                channel_map_repetition=self.Any,
                channel_selection_type=self.Any,
                ch3c_shape=self.Any,
                ch3c_jump=self.Any,
                reserved=self.Any,
                t_ip1_time=self.Any,
                t_ip2_time=self.Any,
                t_fcs_time=self.Any,
                t_pm_time=self.Any,
            )
        )

        # 12. The Upper Tester sends an HCI_LE_CS_Procedure_Enable command
        controller.send_cmd(
            hci.LeCsProcedureEnable(
                connection_handle=acl_connection_handle,
                config_id=config_id,
                procedure_enable=hci.Enable.ENABLED,
            )
        )

        # 13B.1 The IUT sends an HCI_Command_Status event with Status set to
        # 0x12
        await self.expect_evt(
            hci.LeCsProcedureEnableStatus(
                status=ErrorCode.INVALID_HCI_COMMAND_PARAMETERS,
                num_hci_command_packets=1,
            )
        )
