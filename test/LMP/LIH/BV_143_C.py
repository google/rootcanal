from dataclasses import dataclass
import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    # LMP/LIH/BV-143-C [Rejected Role Switch Request]
    async def test(self):
        # Test parameters.
        controller = self.controller
        acl_connection_handle = 0xefe
        peer_address = Address('11:22:33:44:55:66')

        controller.send_cmd(hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY))

        await self.expect_evt(hci.WriteScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_ll(
            ll.Page(source_address=peer_address, destination_address=controller.address, allow_role_switch=False))

        await self.expect_evt(hci.ConnectionRequest(bd_addr=peer_address, link_type=hci.ConnectionRequestLinkType.ACL))

        controller.send_cmd(
            hci.AcceptConnectionRequest(bd_addr=peer_address, role=hci.AcceptConnectionRequestRole.REMAIN_PERIPHERAL))

        await self.expect_evt(hci.AcceptConnectionRequestStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_ll(
            ll.PageResponse(source_address=controller.address, destination_address=peer_address, try_role_switch=False))

        await self.expect_evt(
            hci.ConnectionComplete(status=ErrorCode.SUCCESS,
                                   connection_handle=acl_connection_handle,
                                   bd_addr=peer_address,
                                   link_type=hci.LinkType.ACL,
                                   encryption_enabled=hci.Enable.DISABLED))

        controller.send_cmd(
            hci.WriteLinkPolicySettings(connection_handle=acl_connection_handle,
                                        link_policy_settings=hci.LinkPolicy.ENABLE_ROLE_SWITCH))

        await self.expect_evt(
            hci.WriteLinkPolicySettingsComplete(status=ErrorCode.SUCCESS,
                                                num_hci_command_packets=1,
                                                connection_handle=acl_connection_handle))

        controller.send_cmd(hci.SwitchRole(bd_addr=peer_address, role=hci.Role.CENTRAL))

        await self.expect_evt(hci.SwitchRoleStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_ll(ll.RoleSwitchRequest(source_address=controller.address, destination_address=peer_address))

        controller.send_ll(
            ll.RoleSwitchResponse(source_address=peer_address,
                                  destination_address=controller.address,
                                  status=ErrorCode.ROLE_CHANGE_NOT_ALLOWED))

        await self.expect_evt(
            hci.RoleChange(status=ErrorCode.ROLE_CHANGE_NOT_ALLOWED, bd_addr=peer_address,
                           new_role=hci.Role.PERIPHERAL))

        controller.send_cmd(hci.SwitchRole(bd_addr=peer_address, role=hci.Role.PERIPHERAL))

        await self.expect_evt(hci.SwitchRoleStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_evt(
            hci.RoleChange(status=ErrorCode.ROLE_SWITCH_FAILED, bd_addr=peer_address, new_role=hci.Role.PERIPHERAL))
