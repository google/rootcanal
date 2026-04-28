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

    async def test(self):
        """
        Test the CS Read Remote FAE Table procedure.
        """
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller

        await self.enable_channel_sounding_host_support()

        acl_connection_handle = await self.establish_le_connection_peripheral(
            peer_address
        )

        await self.le_start_encryption(acl_connection_handle, peer_address)

        # Since IUT is the Peripheral, the LT (Central) initiates the CS Security procedure
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

        # 1. The Upper Tester sends an HCI_LE_CS_Set_Default_Settings command
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

        # 2. The Upper Tester sends an HCI_LE_CS_Read_Remote_Supported_Capabilities command
        controller.send_cmd(
            hci.LeCsReadRemoteSupportedCapabilities(
                connection_handle=acl_connection_handle
            )
        )
        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 3. The IUT sends an LL_CS_CAPABILITIES_REQ PDU to the Lower Tester.
        await self.expect_ll(
            ll.LlCsCapabilitiesReq(
                source_address=controller.address,
                destination_address=peer_address,
                **self.IUT_CS_CAPABILITIES,
            )
        )

        # 4. The Lower Tester sends an LL_CS_CAPABILITIES_RSP PDU to the IUT
        # with the NO_FAE bit set to 0.
        controller.send_ll(
            ll.LlCsCapabilitiesRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                **self.LOCAL_CS_CAPABILITIES,
            )
        )

        # 5. The IUT sends a successful
        # HCI_LE_CS_Read_Remote_Supported_Capabilities_Complete event
        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                **self.REMOTE_CS_CAPABILITIES,
            )
        )

        # 6. The Upper Tester sends an HCI_LE_CS_Read_Remote_FAE_Table command
        controller.send_cmd(
            hci.LeCsReadRemoteFaeTable(
                connection_handle=acl_connection_handle,
            )
        )

        # 7. The IUT sends a successful HCI_Command_Status event
        await self.expect_evt(
            hci.LeCsReadRemoteFaeTableStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 8. The IUT sends an LL_CS_FAE_REQ PDU to the Lower Tester.
        await self.expect_ll(
            ll.LlCsFaeReq(
                source_address=controller.address,
                destination_address=peer_address,
            )
        )

        # 9. The Lower Tester sends an LL_CS_FAE_RSP PDU to the IUT with ChFAE
        # set to the Lower Tester FAE Table.
        fae_table = [i + 1 for i in range(72)]
        controller.send_ll(
            ll.LlCsFaeRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                remote_fae_table=fae_table,
            )
        )

        # 10. The IUT sends a successful HCI_LE_CS_Read_Remote_FAE_Table_Complete event
        await self.expect_evt(
            hci.LeCsReadRemoteFaeTableComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                remote_fae_table=fae_table,
            )
        )

        # 11. The Upper Tester sends an HCI_LE_CS_Write_Cached_Remote_FAE_Table command
        controller.send_cmd(
            hci.LeCsWriteCachedRemoteFaeTable(
                connection_handle=acl_connection_handle,
                remote_fae_table=fae_table,
            )
        )

        # 12. The IUT sends an HCI_Command_Complete event to the Upper Tester
        # with Status set to 0x0C (Command Disallowed)
        await self.expect_evt(
            hci.LeCsWriteCachedRemoteFaeTableComplete(
                status=ErrorCode.COMMAND_DISALLOWED,
                num_hci_command_packets=1,
                connection_handle=acl_connection_handle,
            )
        )

        # 13. The IUT and the Lower Tester disconnect the connection.
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

        # 14. The IUT and the Lower Tester reconnect with an encrypted connection.
        acl_connection_handle = await self.establish_le_connection_peripheral(
            peer_address
        )
        await self.le_start_encryption(acl_connection_handle, peer_address)

        # 15. The IUT and the Lower Tester have completed the CS security procedure.
        # Since IUT is the Peripheral, the LT (Central) initiates the CS Security procedure
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

        # 16. The Upper Tester sends an HCI_LE_CS_Set_Default_Settings command
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

        # 17. The Upper Tester sends an HCI_LE_CS_Read_Remote_Supported_Capabilities command
        controller.send_cmd(
            hci.LeCsReadRemoteSupportedCapabilities(
                connection_handle=acl_connection_handle
            )
        )
        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 18. The IUT sends an LL_CS_CAPABILITIES_REQ PDU to the Lower Tester.
        await self.expect_ll(
            ll.LlCsCapabilitiesReq(
                source_address=controller.address,
                destination_address=peer_address,
                **self.IUT_CS_CAPABILITIES,
            )
        )

        # 19. The Lower Tester sends an LL_CS_CAPABILITIES_RSP PDU to the IUT
        # with the NO_FAE bit set to 0.
        controller.send_ll(
            ll.LlCsCapabilitiesRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                **self.LOCAL_CS_CAPABILITIES,
            )
        )

        # 20. The IUT sends a successful
        # HCI_LE_CS_Read_Remote_Supported_Capabilities_Complete event
        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                **self.REMOTE_CS_CAPABILITIES,
            )
        )

        # 21. The Upper Tester sends an HCI_LE_CS_Write_Cached_Remote_FAE_Table command
        controller.send_cmd(
            hci.LeCsWriteCachedRemoteFaeTable(
                connection_handle=acl_connection_handle,
                remote_fae_table=fae_table,
            )
        )

        # 22. The IUT sends a successful HCI_Command_Complete event
        await self.expect_evt(
            hci.LeCsWriteCachedRemoteFaeTableComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
                connection_handle=acl_connection_handle,
            )
        )
