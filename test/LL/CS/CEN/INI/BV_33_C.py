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

import random

from rootcanal.bluetooth import Address
from rootcanal.packets import hci
from rootcanal.packets import ll
from rootcanal.packets.hci import ErrorCode
from test.controller_test import ControllerTest


class Test(ControllerTest):
    # LL/CS/CEN/INI/BV-33-C [CS Procedure Cancellation, Central, Initiator]

    REMOTE_CS_CAPABILITIES = {
        "num_config_supported": 3,
        "max_consecutive_procedures_supported": 4, # Different than 1
        "num_antennae_supported": 1,
        "max_antenna_paths_supported": 1,
        "roles_supported": 0x02,  # Reflector
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

    async def test(self):
        """
        Test the CS Procedure Cancellation initiated by the local controller.
        """
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller

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

        # Complete CS Security Start and Set Default Settings
        controller.send_cmd(
            hci.LeCsSetDefaultSettings(
                connection_handle=acl_connection_handle,
                role_enable=0x01,  # Initiator
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

        # Write cached remote FAE table.
        fae_table = [i + 1 for i in range(72)]
        controller.send_cmd(
            hci.LeCsWriteCachedRemoteFaeTable(
                connection_handle=acl_connection_handle,
                remote_fae_table=fae_table,
            )
        )
        await self.expect_evt(
            hci.LeCsWriteCachedRemoteFaeTableComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
                connection_handle=acl_connection_handle,
            )
        )

        # CS Configuration Procedure
        channel_map_bytes = [0xFC, 0xFF, 0x7F, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F]
        controller.send_cmd(
            hci.LeCsCreateConfig(
                connection_handle=acl_connection_handle,
                config_id=2,
                create_context=hci.CsCreateContext.BOTH_LOCAL_AND_REMOTE_CONTROLLER,
                main_mode_type=hci.CsMainModeType.MODE_1,
                sub_mode_type=hci.CsSubModeType.UNUSED,
                min_main_mode_steps=0,
                max_main_mode_steps=0,
                main_mode_repetition=0,
                mode_0_steps=3,
                role=hci.CsRole.INITIATOR,
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
        await self.expect_evt(
            hci.LeCsCreateConfigStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        await self.expect_ll(
            ll.LlCsConfigReq(
                source_address=controller.address,
                destination_address=peer_address,
                config_id=2,
                action=1,
                channel_map=channel_map_bytes,
                channel_map_repetition=1,
                main_mode_type=1,
                sub_mode_type=0xFF,
                min_main_mode_steps=0,
                max_main_mode_steps=0,
                main_mode_repetition=0,
                mode_0_steps=3,
                cs_sync_phy=1,
                rtt_type=0,
                role=0,
                channel_selection_type=1,
                ch3c_shape=0,
                ch3c_jump=2,
                t_ip1=0,
                t_ip2=0,
                t_fcs=0,
                t_pm=0,
            )
        )

        controller.send_ll(
            ll.LlCsConfigRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                config_id=2,
            )
        )

        await self.expect_evt(
            hci.LeCsConfigComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                config_id=2,
                action=hci.CsAction.CONFIG_CREATED,
                main_mode_type=hci.CsMainModeType.MODE_1,
                sub_mode_type=hci.CsSubModeType.UNUSED,
                min_main_mode_steps=0,
                max_main_mode_steps=0,
                main_mode_repetition=0,
                mode_0_steps=3,
                role=hci.CsRole.INITIATOR,
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

        # Set Procedure Parameters
        controller.send_cmd(
            hci.LeCsSetProcedureParameters(
                connection_handle=acl_connection_handle,
                config_id=2,
                max_procedure_len=0x07D0,
                min_procedure_interval=0x32,
                max_procedure_interval=0x32,
                max_procedure_count=4, # N_Procedure assigned to 4
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

        # Enable procedure
        # N_Procedure assigned to 4
        n_procedure = 4

        # Repeat Steps 1-7 three times, but in Step 4, the Lower Tester sends the
        # LL_CS_TERMINATE_REQ during a random procedure repetition.
        for iteration in range(4):
            lt_terminates = (iteration > 0) # Repetition 1, 2, 3 (0-indexed) will have LT terminate

            # Step 1: Lower Tester sends an LL_CS_REQ PDU
            controller.send_ll(
                ll.LlCsReq(
                    source_address=peer_address,
                    destination_address=controller.address,
                    config_id=2,
                    conn_event_count=0,
                    offset_min=0,
                    offset_max=0,
                    max_procedure_len=0x07D0,
                    event_interval=0,
                    subevents_per_event=1,
                    subevent_interval=0,
                    subevent_len=2500,
                    procedure_interval=0x32,
                    procedure_count=n_procedure,
                    aci=0,
                    preferred_peer_ant=0x01,
                    phy=1,
                    pwr_delta=0,
                    tx_snr_i=5,
                    tx_snr_r=5,
                )
            )

            # Step 2: Alternative 2A (IUT is Central): IUT sends an LL_CS_IND PDU
            await self.expect_ll(
                ll.LlCsInd(
                    source_address=controller.address,
                    destination_address=peer_address,
                    status=ErrorCode.SUCCESS,
                    config_id=2,
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

            # Expect the enable complete event!
            await self.expect_evt(
                hci.LeCsProcedureEnableComplete(
                    status=ErrorCode.SUCCESS,
                    connection_handle=acl_connection_handle,
                    config_id=2,
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

            # Step 3: Mode-0 and Mode-1 CS_SYNC procedures
            # Rootcanal will generate subevent results
            # For mode 1 (9 bytes per step) and minimum 48 steps,
            # they are split into exactly 2 HCI events (26 steps, then 22 steps).
            await self.expect_evt(hci.LeCsSubeventResult)
            await self.expect_evt(hci.LeCsSubeventResultContinue)

            if not lt_terminates:
                # Step 4 & 5: UT cancels procedure in the middle
                # We send cancel command during procedure
                controller.send_cmd(
                    hci.LeCsProcedureEnable(
                        connection_handle=acl_connection_handle,
                        config_id=2,
                        procedure_enable=hci.Enable.DISABLED,
                    )
                )
                await self.expect_evt(
                    hci.LeCsProcedureEnableStatus(
                        status=ErrorCode.SUCCESS, num_hci_command_packets=1
                    )
                )

                # Step 6: IUT sends LL_CS_TERMINATE_REQ
                await self.expect_ll(
                    ll.LlCsTerminateReq(
                        source_address=controller.address,
                        destination_address=peer_address,
                        config_id=2,
                        procedure_count=self.Any,
                        error_code=ErrorCode.SUCCESS,
                    )
                )

                # LT responds with LL_CS_TERMINATE_RSP
                controller.send_ll(
                    ll.LlCsTerminateRsp(
                        source_address=peer_address,
                        destination_address=controller.address,
                        config_id=2,
                        procedure_count=0,
                        error_code=ErrorCode.SUCCESS,
                    )
                )
            else:
                # Step 8 case: LT sends LL_CS_TERMINATE_REQ during a random procedure repetition.
                # We simulate this by sending it from LT instead of UT cancellation
                controller.send_ll(
                    ll.LlCsTerminateReq(
                        source_address=peer_address,
                        destination_address=controller.address,
                        config_id=2,
                        procedure_count=random.randint(1, n_procedure),
                        error_code=ErrorCode.SUCCESS,
                    )
                )

                # IUT responds with LL_CS_TERMINATE_RSP
                await self.expect_ll(
                    ll.LlCsTerminateRsp(
                        source_address=controller.address,
                        destination_address=peer_address,
                        config_id=2,
                        procedure_count=self.Any,
                        error_code=ErrorCode.SUCCESS,
                    )
                )

            # Step 7: IUT finishes current procedure and sends complete event
            await self.expect_evt(
                hci.LeCsProcedureEnableComplete(
                    status=ErrorCode.SUCCESS,
                    connection_handle=acl_connection_handle,
                    config_id=2,
                    state=hci.Enable.DISABLED,
                    tone_antenna_config_selection=0,
                    selected_tx_power=0,
                    subevent_len=0,
                    subevents_per_event=0,
                    subevent_interval=0,
                    event_interval=0,
                    procedure_interval=0,
                    procedure_count=0,
                    max_procedure_len=0,
                )
            )
