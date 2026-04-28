# Copyright 2025 Google LLC
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

import asyncio
from rootcanal.packets import hci
import unittest
from rootcanal.packets.hci import ErrorCode
from test.controller_test import ControllerTest


class Test(ControllerTest):

    # Verify that rootcanal correctly implements the test command
    # RootCanal Send Hci Event.
    async def test_send_hci_event(self):
        self.controller.send_cmd(
            hci.RootcanalSendHciEvent(
                event_code=hci.EventCode.VENDOR_SPECIFIC,
                payload=[0x42, 1, 2, 3],
            )
        )

        await self.expect_evt(
            hci.RootcanalCommandComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
                subop_code=hci.RootcanalOpCode.SEND_HCI_EVENT,
            )
        )

        await self.expect_evt(
            hci.VendorSpecificEvent(
                subevent_code=hci.VseSubeventCode.from_int(0x42), payload=[1, 2, 3]
            )
        )

    # Verify that rootcanal correctly implements the test command
    # RootCanal Send Acl Data.
    async def test_send_acl_data(self):
        self.controller.send_cmd(
            hci.RootcanalSendHciAclData(
                handle=0x342,
                payload=[1, 2, 3],
            )
        )

        await self.expect_evt(
            hci.RootcanalCommandComplete(
                status=ErrorCode.SUCCESS,
                num_hci_command_packets=1,
                subop_code=hci.RootcanalOpCode.SEND_HCI_ACL_DATA,
            )
        )

        await self.expect_acl(
            hci.Acl(
                handle=0x342,
                payload=[1, 2, 3],
            )
        )
