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
    REMOTE_CS_CAPABILITIES = {
        "num_config_supported": 4,
        "max_consecutive_procedures_supported": 1,
        "num_antennae_supported": 1,
        "max_antenna_paths_supported": 1,
        "roles_supported": 0x01,  # Initiator (since IUT is Reflector)
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

    # LL/CS/CEN/REF/BV-24-C [Channel Sounding Config Channel Classification Update]
    async def test(self):
        """
        Test the CS Config Channel Classification Update.
        """
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller
        config_id = 0

        # Enable Channel Sounding Host Support.
        await self.enable_channel_sounding_host_support()

        # Initial Conditions: Establish an ACL connection with the IUT, set capabilities/FAE,
        # encrypt, and complete CS Security Start.
        acl_connection_handle = await self.establish_le_connection_central(peer_address)

        # Exchange CS capabilities.
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

        await self.le_start_encryption(acl_connection_handle, peer_address)

        # CS Security Enable: Lower Tester (Central) initiates
        controller.send_cmd(
            hci.LeCsSecurityEnable(connection_handle=acl_connection_handle)
        )
        await self.expect_evt(
            hci.LeCsSecurityEnableStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        await self.expect_ll(
            ll.LlCsSecurityEnableReq(
                source_address=controller.address,
                destination_address=peer_address,
                cs_iv_c=self.Any,
                cs_in_c=self.Any,
                cs_pv_c=self.Any,
            )
        )

        controller.send_ll(
            ll.LlCsSecurityEnableRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                cs_iv_p=0x1234567890ABCDEF,
                cs_in_p=0x12345678,
                cs_pv_p=0xFEDCBA0987654321,
            )
        )

        await self.expect_evt(
            hci.LeCsSecurityEnableComplete(
                status=ErrorCode.SUCCESS, connection_handle=acl_connection_handle
            )
        )

        # Set Default Settings
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


        # 1. The Upper Tester sends an HCI_LE_CS_Create_Config command to the IUT
        # with Config_ID set to 0, parameters specified in Section 4.14.2.2, and
        # Role as specified in Table 4.14-33.
        channel_map_bytes = [0xFC, 0xFF, 0x7F, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F]

        controller.send_cmd(
            hci.LeCsCreateConfig(
                connection_handle=acl_connection_handle,
                config_id=config_id,
                create_context=hci.CsCreateContext.BOTH_LOCAL_AND_REMOTE_CONTROLLER,
                main_mode_type=hci.CsMainModeType.MODE_2,
                sub_mode_type=hci.CsSubModeType.MODE_1,
                min_main_mode_steps=3,
                max_main_mode_steps=5,
                main_mode_repetition=1,
                mode_0_steps=1,
                role=hci.CsRole.REFLECTOR,
                rtt_type=hci.CsRttType.RTT_AA_ONLY,
                cs_sync_phy=hci.CsSyncPhy.LE_1M_PHY,
                channel_map=channel_map_bytes,
                channel_map_repetition=1,
                channel_selection_type=hci.CsChannelSelectionType.TYPE_3C,
                ch3c_shape=hci.CsCh3cShape.HAT_SHAPE,
                ch3c_jump=2,
                reserved=0,
            )
        )

        # 2. The IUT sends a successful HCI_Command_Status event to the Upper Tester.
        await self.expect_evt(
            hci.LeCsCreateConfigStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 3. The IUT sends an LL_CS_CONFIG_REQ PDU to the Lower Tester with
        # valid parameters and Role as specified in Table 4.14-33 and Config_ID
        # set to 0.
        await self.expect_ll(
            ll.LlCsConfigReq(
                source_address=controller.address,
                destination_address=peer_address,
                config_id=config_id,
                action=1,
                channel_map=channel_map_bytes,
                channel_map_repetition=1,
                main_mode_type=2,
                sub_mode_type=1,
                min_main_mode_steps=3,
                max_main_mode_steps=5,
                main_mode_repetition=1,
                mode_0_steps=1,
                cs_sync_phy=1,
                rtt_type=0,
                role=1,
                channel_selection_type=1,
                ch3c_shape=0,
                ch3c_jump=2,
                t_ip1=0,
                t_ip2=0,
                t_fcs=0,
                t_pm=0,
            )
        )

        # 4. The Lower Tester sends an LL_CS_CONFIG_RSP PDU to the IUT.
        controller.send_ll(
            ll.LlCsConfigRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                config_id=config_id,
            )
        )

        # 5. The IUT sends an HCI_LE_CS_Config_Complete event to the Upper Tester
        await self.expect_evt(
            hci.LeCsConfigComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                config_id=config_id,
                action=hci.CsAction.CONFIG_CREATED,
                main_mode_type=hci.CsMainModeType.MODE_2,
                sub_mode_type=hci.CsSubModeType.MODE_1,
                min_main_mode_steps=3,
                max_main_mode_steps=5,
                main_mode_repetition=1,
                mode_0_steps=1,
                role=hci.CsRole.REFLECTOR,
                rtt_type=hci.CsRttType.RTT_AA_ONLY,
                cs_sync_phy=hci.CsSyncPhy.LE_1M_PHY,
                channel_map=channel_map_bytes,
                channel_map_repetition=1,
                channel_selection_type=hci.CsChannelSelectionType.TYPE_3C,
                ch3c_shape=hci.CsCh3cShape.HAT_SHAPE,
                ch3c_jump=2,
                reserved=0,
                t_ip1_time=0,
                t_ip2_time=0,
                t_fcs_time=0,
                t_pm_time=0,
            )
        )

        # 6. The Upper Tester sends an HCI_LE_CS_Set_Channel_Classification
        # command to the IUT with the Channel_Classification odd bits set to 1.
        # Odd bits set to 1, while respecting reserved bits.
        new_channel_classification = [0xAA] * 10
        new_channel_classification[0] &= ~0x03  # 0xA8
        new_channel_classification[2] &= ~0x80  # 0x2A
        new_channel_classification[3] &= ~0x03  # 0xA8
        new_channel_classification[9] &= ~0xE0  # 0x0A

        controller.send_cmd(
            hci.LeCsSetChannelClassification(
                channel_classification=new_channel_classification,
            )
        )

        # 7. The IUT sends a successful HCI_Command_Complete event to the Upper Tester.
        await self.expect_evt(
            hci.LeCsSetChannelClassificationComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
            )
        )

        # 8. Anytime between Steps 7 and 12, the IUT sends an LL_CS_CHANNEL_MAP_IND PDU to the
        # Lower Tester with the odd bits set in ChM.
        await self.expect_ll(
            ll.LlCsChannelMapInd(
                source_address=controller.address,
                destination_address=peer_address,
                channel_map=new_channel_classification,
                instant=self.Any,
            )
        )

        # 9. The Upper Tester sends an HCI_LE_CS_Set_Default_Settings command to the IUT with
        # Role_Enable set to the role in Table 4.14-33 and receives a successful HCI_Command_Complete
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

        # 10. The Upper Tester sends an HCI_LE_CS_Set_Procedure_Parameters with Config_ID set to the
        # value from Step 1
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

        # 11. The Upper Tester sends an HCI_LE_CS_Procedure_Enable to the IUT
        # with Config_ID set to the value from Step 1 and Enable set to 0x01 and
        # receives a successful HCI_Command_Status event.
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

        # 12. The IUT sends an LL_CS_REQ PDU to the Lower Tester with Config_ID
        # set to the value from Step 11.
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

        # 13A.1 The Lower Tester sends an LL_CS_RSP PDU to the IUT with
        # Config_ID set to the value from Step 12.
        controller.send_ll(
            ll.LlCsRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                config_id=config_id,
                conn_event_count=0,
                offset_min=0,
                offset_max=0,
                event_interval=0,
                subevents_per_event=1,
                subevent_interval=0,
                subevent_len=2500,
                aci=0,
                phy=1,
                pwr_delta=0,
            )
        )

        # 13A.2 The IUT sends an LL_CS_IND PDU to the Lower Tester with
        # Config_ID set to the value from Step 12.
        await self.expect_ll(
            ll.LlCsInd(
                source_address=controller.address,
                destination_address=peer_address,
                status=ErrorCode.SUCCESS,
                config_id=config_id,
                conn_event_count=self.Any,
                offset=self.Any,
                event_interval=0,
                subevents_per_event=1,
                subevent_interval=0,
                subevent_len=2500,
                aci=0,
                phy=1,
                pwr_delta=0,
            )
        )

        # 14. The IUT sends an HCI_LE_CS_Procedure_Enable_Complete event to the
        # Upper Tester with Config_ID set to the value from Step 12.
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

        # Calculation for Subevent Results:
        # 1. Total Number of Steps: The config sets max_main_mode_steps=5.
        # However, le_controller.cc enforces a minimum of 48 steps.
        # 2. Size of a Single Result Step: The step data size is 9 bytes since main_mode_type=2.
        # Adding the mode (1 byte), channel (1 byte), and length (1 byte) makes each step 12 bytes.
        # 3. Payload Splitting (255 byte max):
        #    - First Event (LeCsSubeventResult): Header size is 16 bytes.
        #    - Max steps that fit = int((255 - 16) / 12) = 19.
        #    - Second Event (LeCsSubeventResultContinue): Header size is 9 bytes.
        #    - Max steps that fit = int((255 - 9) / 12) = 20.
        #    - Remaining = 48 - 19 = 29.
        #    - Third Event (LeCsSubeventResultContinue): Only 9 steps remain (29 - 20).
        # This full block of 3 events is expected twice because max_procedure_count=2.
        for _ in range(2):
            await self.expect_evt(
                hci.LeCsSubeventResult(
                    connection_handle=acl_connection_handle,
                    config_id=config_id,
                    start_acl_conn_event_counter=self.Any,
                    procedure_counter=self.Any,
                    frequency_compensation=self.Any,
                    reference_power_level=self.Any,
                    procedure_done_status=hci.CsProcedureDoneStatus.PARTIAL_RESULTS,
                    subevent_done_status=hci.CsSubeventDoneStatus.PARTIAL_RESULTS,
                    procedure_abort_reason=hci.ProcedureAbortReason.NO_ABORT,
                    subevent_abort_reason=hci.SubeventAbortReason.NO_ABORT,
                    num_antenna_paths=self.Any,
                    cs_step=self.Any,
                )
            )

            await self.expect_evt(
                hci.LeCsSubeventResultContinue(
                    connection_handle=acl_connection_handle,
                    config_id=config_id,
                    procedure_done_status=hci.CsProcedureDoneStatus.PARTIAL_RESULTS,
                    subevent_done_status=hci.CsSubeventDoneStatus.PARTIAL_RESULTS,
                    procedure_abort_reason=hci.ProcedureAbortReason.NO_ABORT,
                    subevent_abort_reason=hci.SubeventAbortReason.NO_ABORT,
                    num_antenna_paths=self.Any,
                    cs_step=self.Any,
                )
            )

            await self.expect_evt(
                hci.LeCsSubeventResultContinue(
                    connection_handle=acl_connection_handle,
                    config_id=config_id,
                    procedure_done_status=hci.CsProcedureDoneStatus.ALL_RESULTS_COMPLETE,
                    subevent_done_status=hci.CsSubeventDoneStatus.ALL_RESULTS_COMPLETE,
                    procedure_abort_reason=hci.ProcedureAbortReason.NO_ABORT,
                    subevent_abort_reason=hci.SubeventAbortReason.NO_ABORT,
                    num_antenna_paths=self.Any,
                    cs_step=self.Any,
                )
            )
