# Copyright (C) 2026 Google LLC
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
from rootcanal.packets import ll
import unittest
from rootcanal.packets.hci import ErrorCode
from rootcanal.bluetooth import Address
from test.controller_test import ControllerTest
from rootcanal.controller import Phy


class Test(ControllerTest):

    # Verify that the controller instance sends PING requests
    # to keep the connection alive, and triggers a supervision
    # timeout when no PING response is received.
    async def test_connection_keeplive(self):
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller

        # Prelude: Establish an ACL connection as peripheral with the IUT.
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

        # The controller should send a PING request after a short timeout.
        await self.expect_ll(
            ll.PingRequest(
                destination_address=peer_address, source_address=controller.address
            )
        )
        controller.send_ll(
            ll.PingResponse(
                destination_address=controller.address, source_address=peer_address
            ),
            phy=Phy.BrEdr,
        )

        # The controller should send another PING request after a short timeout.
        await self.expect_ll(
            ll.PingRequest(
                destination_address=peer_address, source_address=controller.address
            )
        )

        # Without any response from the peer device, the controller should trigger
        # a link supervision timeout.
        await self.expect_ll(
            ll.Disconnect(
                destination_address=peer_address,
                source_address=controller.address,
                reason=ErrorCode.CONNECTION_TIMEOUT,
            )
        )
        await self.expect_evt(
            hci.DisconnectionComplete(
                connection_handle=acl_connection_handle,
                status=ErrorCode.SUCCESS,
                reason=ErrorCode.CONNECTION_TIMEOUT,
            )
        )
