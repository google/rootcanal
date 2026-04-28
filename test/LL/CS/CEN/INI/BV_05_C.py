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

    # LL/CS/CEN/INI/BV-05-C [Channel Sounding Configuration, Central]
    async def test(self):
        """
        Test the CS Procedure Start and Stop initiated by the local controller.
        """
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller

        # Enable Channel Sounding Host Support.
        await self.enable_channel_sounding_host_support()

        # Initial Conditions: Establish an ACL connection with the IUT
        acl_connection_handle = await self.establish_le_connection_central(peer_address)

        # Encrypt the connection
        await self.le_start_encryption(acl_connection_handle, peer_address)

        channel_map_bytes = [0xFC, 0xFF, 0x7F, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F]

        for config_id in range(4):
            # 1. The Lower Tester sends an LL_CS_CAPABILITIES_REQ PDU to the IUT.
            controller.send_ll(
                ll.LlCsCapabilitiesReq(
                    source_address=peer_address,
                    destination_address=controller.address,
                    **self.LOCAL_CS_CAPABILITIES,
                )
            )

            # 2. The IUT sends an LL_CS_CAPABILITIES_RSP PDU to the Lower Tester.
            await self.expect_ll(
                ll.LlCsCapabilitiesRsp(
                    source_address=controller.address,
                    destination_address=peer_address,
                    status=ErrorCode.SUCCESS,
                    **self.IUT_CS_CAPABILITIES,
                )
            )

            # 3. The IUT sends an HCI_CS_Read_Remote_Capabilities_Complete event
            # to the Upper Tester.
            await self.expect_evt(
                hci.LeCsReadRemoteSupportedCapabilitiesComplete(
                    status=ErrorCode.SUCCESS,
                    connection_handle=acl_connection_handle,
                    **self.REMOTE_CS_CAPABILITIES,
                )
            )

            # 4. The Upper Tester sends an HCI_LE_CS_Set_Default_Settings
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

            # 5. The Lower Tester sends an LL_CS_CONFIG_REQ PDU
            controller.send_ll(
                ll.LlCsConfigReq(
                    source_address=peer_address,
                    destination_address=controller.address,
                    config_id=config_id,
                    action=1,  # Create
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
                    role=1,  # Reflector for peer
                    channel_selection_type=1,
                    ch3c_shape=0,
                    ch3c_jump=2,
                    t_ip1=0,
                    t_ip2=0,
                    t_fcs=0,
                    t_pm=0,
                )
            )

            # 6. The IUT sends an LL_CS_CONFIG_RSP PDU to the Lower Tester
            await self.expect_ll(
                ll.LlCsConfigRsp(
                    source_address=controller.address,
                    destination_address=peer_address,
                    status=ErrorCode.SUCCESS,
                    config_id=config_id,
                )
            )

            # 7. The IUT sends an HCI_LE_CS_Config_Complete event to the Upper Tester
            await self.expect_evt(
                hci.LeCsConfigComplete(
                    status=ErrorCode.SUCCESS,
                    connection_handle=acl_connection_handle,
                    config_id=config_id,
                    action=hci.CsAction.CONFIG_CREATED,
                    main_mode_type=hci.CsMainModeType.MODE_1,
                    sub_mode_type=hci.CsSubModeType.UNUSED,
                    min_main_mode_steps=0,
                    max_main_mode_steps=0,
                    main_mode_repetition=0,
                    mode_0_steps=3,
                    role=hci.CsRole.INITIATOR,  # local role
                    rtt_type=hci.CsRttType.RTT_AA_ONLY,
                    cs_sync_phy=hci.CsSyncPhy.LE_1M_PHY,
                    channel_map=channel_map_bytes,
                    channel_map_repetition=1,
                    channel_selection_type=hci.CsChannelSelectionType.TYPE_3C,
                    ch3c_shape=hci.CsCh3cShape.HAT_SHAPE,
                    ch3c_jump=0,
                    reserved=2,
                    t_ip1_time=0,
                    t_ip2_time=0,
                    t_fcs_time=0,
                    t_pm_time=0,
                )
            )

            # 8A.1 The Upper Tester sends an HCI_LE_CS_Security_Enable command
            controller.send_cmd(
                hci.LeCsSecurityEnable(connection_handle=acl_connection_handle)
            )
            await self.expect_evt(
                hci.LeCsSecurityEnableStatus(
                    status=ErrorCode.SUCCESS, num_hci_command_packets=1
                )
            )

            # 8A.2 The IUT sends an LL_CS_SEC_REQ PDU to the Lower Tester
            await self.expect_ll(
                ll.LlCsSecurityEnableReq(
                    source_address=controller.address,
                    destination_address=peer_address,
                    cs_iv_c=self.Any,
                    cs_in_c=self.Any,
                    cs_pv_c=self.Any,
                )
            )

            # 8A.3 The Lower Tester sends an LL_CS_SEC_RSP PDU to the IUT
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

            # 9. The IUT sends an HCI_LE_CS_Security_Enable_Complete event
            await self.expect_evt(
                hci.LeCsSecurityEnableComplete(
                    status=ErrorCode.SUCCESS, connection_handle=acl_connection_handle
                )
            )

            # 10. The Lower Tester sends an LL_CS_CONFIG_REQ PDU to the IUT
            controller.send_ll(
                ll.LlCsConfigReq(
                    source_address=peer_address,
                    destination_address=controller.address,
                    config_id=config_id,
                    action=1,  # Update
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
                    role=1,  # Reflector for peer
                    channel_selection_type=1,
                    ch3c_shape=0,
                    ch3c_jump=2,
                    t_ip1=0,
                    t_ip2=0,
                    t_fcs=0,
                    t_pm=0,
                )
            )

            # 11. The IUT sends an LL_CS_CONFIG_RSP PDU
            await self.expect_ll(
                ll.LlCsConfigRsp(
                    source_address=controller.address,
                    destination_address=peer_address,
                    status=ErrorCode.SUCCESS,
                    config_id=config_id,
                )
            )

            # 12. The IUT sends an HCI_LE_CS_Config_Complete event to the Upper Tester
            await self.expect_evt(
                hci.LeCsConfigComplete(
                    status=ErrorCode.SUCCESS,
                    connection_handle=acl_connection_handle,
                    config_id=config_id,
                    action=hci.CsAction.CONFIG_CREATED,
                    main_mode_type=hci.CsMainModeType.MODE_1,
                    sub_mode_type=hci.CsSubModeType.UNUSED,
                    min_main_mode_steps=0,
                    max_main_mode_steps=0,
                    main_mode_repetition=0,
                    mode_0_steps=3,
                    role=hci.CsRole.INITIATOR,  # local role
                    rtt_type=hci.CsRttType.RTT_AA_ONLY,
                    cs_sync_phy=hci.CsSyncPhy.LE_1M_PHY,
                    channel_map=channel_map_bytes,
                    channel_map_repetition=1,
                    channel_selection_type=hci.CsChannelSelectionType.TYPE_3C,
                    ch3c_shape=hci.CsCh3cShape.HAT_SHAPE,
                    ch3c_jump=0,
                    reserved=2,
                    t_ip1_time=0,
                    t_ip2_time=0,
                    t_fcs_time=0,
                    t_pm_time=0,
                )
            )
