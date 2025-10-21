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
import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest, Phy


class Test(ControllerTest):

    # LMP/LIH/BV-143-C [Rejected Role Switch Request]
    async def test(self):
        # Test parameters.
        controller = self.controller
        acl_connection_handle = None
        peer_address = Address('11:22:33:44:55:66')

        controller.send_cmd(hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY))

        await self.expect_evt(
            hci.WriteScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_ll(
            ll.Page(source_address=peer_address,
                    destination_address=controller.address,
                    allow_role_switch=False),
            phy=Phy.BrEdr)

        await self.expect_evt(
            hci.ConnectionRequest(bd_addr=peer_address,
                                  link_type=hci.ConnectionRequestLinkType.ACL))

        controller.send_cmd(
            hci.AcceptConnectionRequest(bd_addr=peer_address,
                                        role=hci.AcceptConnectionRequestRole.REMAIN_PERIPHERAL))

        await self.expect_evt(
            hci.AcceptConnectionRequestStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_ll(
            ll.PageResponse(source_address=controller.address,
                            destination_address=peer_address,
                            try_role_switch=False))

        evt = await self.expect_evt(
            hci.ConnectionComplete(status=ErrorCode.SUCCESS,
                                   connection_handle=self.Any,
                                   bd_addr=peer_address,
                                   link_type=hci.LinkType.ACL,
                                   encryption_enabled=hci.Enable.DISABLED))

        acl_connection_handle = evt.connection_handle

        controller.send_cmd(
            hci.WriteLinkPolicySettings(connection_handle=acl_connection_handle,
                                        link_policy_settings=hci.LinkPolicy.ENABLE_ROLE_SWITCH))

        await self.expect_evt(
            hci.WriteLinkPolicySettingsComplete(status=ErrorCode.SUCCESS,
                                                num_hci_command_packets=1,
                                                connection_handle=acl_connection_handle))

        controller.send_cmd(hci.SwitchRole(bd_addr=peer_address, role=hci.Role.CENTRAL))

        await self.expect_evt(
            hci.SwitchRoleStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_ll(
            ll.RoleSwitchRequest(source_address=controller.address,
                                 destination_address=peer_address))

        controller.send_ll(
            ll.RoleSwitchResponse(source_address=peer_address,
                                  destination_address=controller.address,
                                  status=ErrorCode.ROLE_CHANGE_NOT_ALLOWED),
            phy=Phy.BrEdr)

        await self.expect_evt(
            hci.RoleChange(status=ErrorCode.ROLE_CHANGE_NOT_ALLOWED,
                           bd_addr=peer_address,
                           new_role=hci.Role.PERIPHERAL))

        controller.send_cmd(hci.SwitchRole(bd_addr=peer_address, role=hci.Role.PERIPHERAL))

        await self.expect_evt(
            hci.SwitchRoleStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_evt(
            hci.RoleChange(status=ErrorCode.ROLE_SWITCH_FAILED,
                           bd_addr=peer_address,
                           new_role=hci.Role.PERIPHERAL))
