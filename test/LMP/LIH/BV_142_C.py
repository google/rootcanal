from dataclasses import dataclass
import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    # LMP/LIH/BV-142-C [Reject Role Switch Request]
    async def test(self):
        # Test parameters.
        controller = self.controller
        acl_connection_handle = 0xefe
        peer_address = Address('11:22:33:44:55:66')

        controller.send_cmd(
            hci.CreateConnection(bd_addr=peer_address,
                                 packet_type=0x7fff,
                                 page_scan_repetition_mode=hci.PageScanRepetitionMode.R0,
                                 allow_role_switch=hci.CreateConnectionRoleSwitch.REMAIN_CENTRAL))

        await self.expect_evt(hci.CreateConnectionStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_ll(
            ll.Page(source_address=controller.address, destination_address=peer_address, allow_role_switch=False))

        controller.send_ll(
            ll.PageResponse(source_address=peer_address, destination_address=controller.address, try_role_switch=False))

        await self.expect_evt(
            hci.ConnectionComplete(status=ErrorCode.SUCCESS,
                                   connection_handle=acl_connection_handle,
                                   bd_addr=peer_address,
                                   link_type=hci.LinkType.ACL,
                                   encryption_enabled=hci.Enable.DISABLED))

        controller.send_cmd(hci.WriteLinkPolicySettings(connection_handle=acl_connection_handle,
                                                        link_policy_settings=0))

        await self.expect_evt(
            hci.WriteLinkPolicySettingsComplete(status=ErrorCode.SUCCESS,
                                                num_hci_command_packets=1,
                                                connection_handle=acl_connection_handle))

        controller.send_ll(ll.RoleSwitchRequest(source_address=peer_address, destination_address=controller.address))

        await self.expect_ll(
            ll.RoleSwitchResponse(source_address=controller.address,
                                  destination_address=peer_address,
                                  status=ErrorCode.ROLE_CHANGE_NOT_ALLOWED))
