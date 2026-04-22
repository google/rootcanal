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

import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest, Phy


class Test(ControllerTest):

    # Verify that the controller instance sends PING requests
    # to keep the connection alive, and triggers a supervision
    # timeout when no PING response is received.
    async def test_connection_keeplive(self):
        # Test parameters.
        peer_address = Address("aa:bb:cc:dd:ee:ff")
        controller = self.controller

        # Prelude: Establish an ACL connection as peripheral with the IUT.
        acl_connection_handle = await self.establish_le_connection_peripheral(
            peer_address
        )

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
            phy=Phy.LowEnergy,
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
