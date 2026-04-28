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

    # LL/CS/CEN/INI/BI-04-C [Channel Sounding Config Request - Deleted Config]
    async def test(self):
        """
        Test the CS Config Request with a deleted config.
        """
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller
        config_id = 0

        # Enable Channel Sounding Host Support.
        await self.enable_channel_sounding_host_support()

        # Initial Conditions:
        # Establish an ACL connection with the IUT, set capabilities/FAE,
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

        # Set Default Settings
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
        # IUT is Central here! The Upper Tester sends an
        # HCI_LE_CS_Security_Enable command
        controller.send_cmd(
            hci.LeCsSecurityEnable(connection_handle=acl_connection_handle)
        )
        await self.expect_evt(
            hci.LeCsSecurityEnableStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 9. The IUT sends an LL_CS_SEC_REQ PDU
        await self.expect_ll(
            ll.LlCsSecurityEnableReq(
                source_address=controller.address,
                destination_address=peer_address,
                cs_iv_c=self.Any,
                cs_in_c=self.Any,
                cs_pv_c=self.Any,
            )
        )

        # 10. The Lower Tester sends an LL_CS_SEC_RSP PDU
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

        # 11. The IUT sends a successful HCI_LE_CS_Security_Enable_Complete
        # event
        await self.expect_evt(
            hci.LeCsSecurityEnableComplete(
                status=ErrorCode.SUCCESS, connection_handle=acl_connection_handle
            )
        )

        # 1. The Upper Tester sends an HCI_LE_CS_Create_Config command to the IUT
        # with Config_ID set to 0, parameters specified in Section 4.14.2.2, and
        # Role as specified in Table 4.14-19.
        channel_map_bytes = [0xFC, 0xFF, 0x7F, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F]

        controller.send_cmd(
            hci.LeCsCreateConfig(
                connection_handle=acl_connection_handle,
                config_id=config_id,
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

        # 2. The IUT sends a successful HCI_Command_Status event to the Upper
        # Tester.
        await self.expect_evt(
            hci.LeCsCreateConfigStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 3. The IUT sends an LL_CS_CONFIG_REQ PDU to the Lower Tester with
        # valid parameters and Role as specified in Table 4.14-19 and Config_ID
        # set to 0.
        await self.expect_ll(
            ll.LlCsConfigReq(
                source_address=controller.address,
                destination_address=peer_address,
                config_id=config_id,
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

        # 4. The Lower Tester sends an LL_REJECT_EXT_IND PDU to the IUT with
        # ErrorCode = 0x1E. Wait, in the actual test framework, we should send
        # an LL_CS_CONFIG_RSP with status = 0x1E
        controller.send_ll(
            ll.LlCsConfigRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.INVALID_LMP_OR_LL_PARAMETERS,  # 0x1E
                config_id=config_id,
            )
        )

        # 5. The IUT sends an HCI_LE_CS_Config_Complete event to the Upper
        # Tester with Status = 0x1E.
        await self.expect_evt(
            hci.LeCsConfigComplete(
                status=ErrorCode.INVALID_LMP_OR_LL_PARAMETERS,  # 0x1E
                connection_handle=acl_connection_handle,
                config_id=config_id,
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

        # 6. The Lower Tester sends an LL_CS_REQ PDU to the IUT with Config_ID
        # set to 0.
        controller.send_ll(
            ll.LlCsReq(
                source_address=peer_address,
                destination_address=controller.address,
                config_id=config_id,
                conn_event_count=0,
                offset_min=0,
                offset_max=0,
                max_procedure_len=0x07D0,
                event_interval=0,
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

        # 7. The IUT sends an LL_REJECT_EXT_IND PDU to the Lower Tester with
        # ErrorCode set to 0x1E. Equivalent to LL_CS_RSP with status = 0x1E
        # (INVALID_LMP_OR_LL_PARAMETERS)
        await self.expect_ll(
            ll.LlCsRsp(
                source_address=controller.address,
                destination_address=peer_address,
                status=ErrorCode.INVALID_LMP_OR_LL_PARAMETERS,  # 0x1E
                config_id=config_id,
                conn_event_count=0,
                offset_min=0,
                offset_max=0,
                event_interval=0,
                subevents_per_event=0,
                subevent_interval=0,
                subevent_len=0,
                aci=0,
                phy=0,
                pwr_delta=0,
            )
        )
