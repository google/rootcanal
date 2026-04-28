# Copyright 2023 Google LLC
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

from dataclasses import dataclass
from rootcanal.packets import hci
from rootcanal.packets import ll
import unittest
from rootcanal.packets.hci import ErrorCode
from rootcanal.bluetooth import Address
from test.controller_test import ControllerTest
from rootcanal.controller import Phy


class Test(ControllerTest):

    # LMP/LIH/BV-142-C [Reject Role Switch Request]
    async def test(self):
        # Test parameters.
        controller = self.controller
        acl_connection_handle = None
        peer_address = Address("11:22:33:44:55:66")

        controller.send_cmd(
            hci.CreateConnection(
                bd_addr=peer_address,
                packet_type=0x7FFF,
                page_scan_repetition_mode=hci.PageScanRepetitionMode.R0,
                allow_role_switch=hci.CreateConnectionRoleSwitch.REMAIN_CENTRAL,
            )
        )

        await self.expect_evt(
            hci.CreateConnectionStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        await self.expect_ll(
            ll.Page(
                source_address=controller.address,
                destination_address=peer_address,
                allow_role_switch=False,
            )
        )

        controller.send_ll(
            ll.PageResponse(
                source_address=peer_address,
                destination_address=controller.address,
                try_role_switch=False,
            ),
            phy=Phy.BrEdr,
        )

        evt = await self.expect_evt(
            hci.ConnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                bd_addr=peer_address,
                link_type=hci.LinkType.ACL,
                encryption_enabled=hci.Enable.DISABLED,
            )
        )

        acl_connection_handle = evt.connection_handle

        controller.send_cmd(
            hci.WriteLinkPolicySettings(
                connection_handle=acl_connection_handle, link_policy_settings=0
            )
        )

        await self.expect_evt(
            hci.WriteLinkPolicySettingsComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
                connection_handle=acl_connection_handle,
            )
        )

        controller.send_ll(
            ll.RoleSwitchRequest(
                source_address=peer_address, destination_address=controller.address
            ),
            phy=Phy.BrEdr,
        )

        await self.expect_ll(
            ll.RoleSwitchResponse(
                source_address=controller.address,
                destination_address=peer_address,
                status=ErrorCode.ROLE_CHANGE_NOT_ALLOWED,
            )
        )
