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

    REMOTE_CS_CAPABILITIES_1 = {
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

    REMOTE_CS_CAPABILITIES_2 = {
        **REMOTE_CS_CAPABILITIES_1,
        "num_config_supported": 2,
        "modes_supported": 0x02,
        "rtt_aa_only_n": 20,
    }

    LOCAL_CS_CAPABILITIES = {
        "mode_types": 0x02,
        "rtt_capability": 0x01,
        "rtt_aa_only_n": 20,
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
        "num_configs": 2,
        "max_procedures_supported": 1,
        "t_sw": 10,
        "t_ip1_capability": 0,
        "t_ip2_capability": 0,
        "t_fcs_capability": 0,
        "t_pm_capability": 0,
        "tx_snr_capability": 0,
    }

    async def test_initiator_cache_behavior_write_first(self):
        """
        Test the cache behavior for remote Channel Sounding (CS) capabilities.

        This test verifies:
        1. An upper tester can explicitly write cached remote supported capabilities using
           HCI_LE_CS_Write_Cached_Remote_Supported_Capabilities before any Link Layer (LL)
           capability exchange occurs.
        2. The written cached capabilities can be successfully read back.
        """
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller

        # Enable Channel Sounding Host Support.
        await self.enable_channel_sounding_host_support()

        # Prelude: Establish an ACL connection as central with the IUT.
        acl_connection_handle = await self.establish_le_connection_central(peer_address)

        # Part 1: Test explicit WriteCache before any LL exchange
        # 1. The Upper Tester sends an
        # HCI_LE_CS_Write_Cached_Remote_Supported_Capabilities command to the
        # IUT.
        controller.send_cmd(
            hci.LeCsWriteCachedRemoteSupportedCapabilities(
                connection_handle=acl_connection_handle, **self.REMOTE_CS_CAPABILITIES_1
            )
        )

        # 2. The Upper Tester receives an
        # HCI_LE_CS_Write_Cached_Remote_Supported_Capabilities_Complete event.
        await self.expect_evt(
            hci.LeCsWriteCachedRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                num_hci_command_packets=1,
            )
        )

        # 3. The Upper Tester sends an
        # HCI_LE_CS_Read_Remote_Supported_Capabilities command to the IUT.
        controller.send_cmd(
            hci.LeCsReadRemoteSupportedCapabilities(
                connection_handle=acl_connection_handle
            )
        )

        # 4. The IUT sends back a Command Status event.
        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 5. The Upper Tester receives an
        # HCI_LE_CS_Read_Remote_Supported_Capabilities_Complete event with the
        # cached data.
        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                **self.REMOTE_CS_CAPABILITIES_1,
            )
        )

    async def test_initiator_cache_behavior_read_first(self):
        """
        Test the cache behavior for remote Channel Sounding (CS) capabilities.

        This test verifies:
        1. If an LL capability exchange procedure occurs on a new connection, the capabilities
           received from the remote device via the LL_CS_CAPABILITIES_RSP PDU populate the cache.
        2. Attempting to write the cached capabilities via HCI command fails with
           COMMAND_DISALLOWED after the LL capability exchange has already taken place.
        """
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller

        # Enable Channel Sounding Host Support.
        await self.enable_channel_sounding_host_support()

        # Prelude: Establish an ACL connection as central with the IUT.
        acl_connection_handle = await self.establish_le_connection_central(peer_address)

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

        await self.expect_ll(
            ll.LlCsCapabilitiesReq(
                source_address=controller.address,
                destination_address=peer_address,
                **self.IUT_CS_CAPABILITIES,
            )
        )

        controller.send_ll(
            ll.LlCsCapabilitiesRsp(
                source_address=peer_address,
                destination_address=controller.address,
                status=ErrorCode.SUCCESS,
                **self.LOCAL_CS_CAPABILITIES,
            )
        )

        await self.expect_evt(
            hci.LeCsReadRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=acl_connection_handle,
                **self.REMOTE_CS_CAPABILITIES_2,
            )
        )

        # Test that WriteCache fails after LL exchange
        controller.send_cmd(
            hci.LeCsWriteCachedRemoteSupportedCapabilities(
                connection_handle=acl_connection_handle, **self.REMOTE_CS_CAPABILITIES_1
            )
        )
        await self.expect_evt(
            hci.LeCsWriteCachedRemoteSupportedCapabilitiesComplete(
                status=ErrorCode.COMMAND_DISALLOWED,
                connection_handle=acl_connection_handle,
                num_hci_command_packets=1,
            )
        )
