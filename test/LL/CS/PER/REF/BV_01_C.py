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
        "roles_supported": 0x01,  # Initiator
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

    LT_CS_CAPABILITIES = {
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
        "role": 0x01,  # Initiator
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

        await self.enable_channel_sounding_host_support()

        peer_address = Address("aa:bb:cc:dd:ee:ff")
        acl_connection_handle = await self.establish_le_connection_peripheral(
            peer_address
        )
        await self.le_start_encryption(acl_connection_handle, peer_address)

        # CS Security procedure
        # Since IUT is the Peripheral, the LT (Central) initiates the CS Security procedure
        self.controller.send_ll(
            ll.LlCsSecurityEnableReq(
                source_address=peer_address,
                destination_address=self.controller.address,
                cs_iv_c=0x1234567890ABCDEF,
                cs_in_c=0x12345678,
                cs_pv_c=0xFEDCBA0987654321,
            )
        )
        await self.expect_ll(
            ll.LlCsSecurityEnableRsp(
                source_address=self.controller.address,
                destination_address=peer_address,
                status=ErrorCode.SUCCESS,
                cs_iv_p=self.Any,
                cs_in_p=self.Any,
                cs_pv_p=self.Any,
            )
        )

        # IUT generates event to host
        await self.expect_evt(
            hci.LeCsSecurityEnableComplete(
                status=ErrorCode.SUCCESS, connection_handle=acl_connection_handle
            )
        )

        # Configured using the LL_CS_CAPABILITIES_REQ PDU
        # LT sends Capabilities Req
        self.controller.send_ll(
            ll.LlCsCapabilitiesReq(
                source_address=peer_address,
                destination_address=self.controller.address,
                **self.LT_CS_CAPABILITIES,
            )
        )

        # IUT responds with Capabilities Rsp
        await self.expect_ll(
            ll.LlCsCapabilitiesRsp(
                source_address=self.controller.address,
                destination_address=peer_address,
                status=ErrorCode.SUCCESS,
                **self.IUT_CS_CAPABILITIES,
            )
        )

        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                **self.REMOTE_CS_CAPABILITIES,
            )
        )

        # Set Default Settings
        self.controller.send_cmd(
            hci.LeCsSetDefaultSettings(
                connection_handle=acl_connection_handle,
                role_enable=0x02,  # Reflector
                cs_sync_antenna_selection=0x01,
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

        # 1. The Lower Tester sends an LL_CS_FAE_REQ PDU to the IUT.
        self.controller.send_ll(
            ll.LlCsFaeReq(
                source_address=peer_address, destination_address=self.controller.address
            )
        )

        # 2. The IUT sends a valid LL_CS_FAE_RSP PDU to the Lower Tester.
        remote_fae_table = [i + 1 for i in range(72)]
        await self.expect_ll(
            ll.LlCsFaeRsp(
                source_address=self.controller.address,
                destination_address=peer_address,
                status=ErrorCode.SUCCESS,
                remote_fae_table=remote_fae_table,
            )
        )
