from dataclasses import dataclass
from rootcanal.packets import hci
from rootcanal.packets import ll
import unittest
from rootcanal.packets.hci import ErrorCode
from rootcanal.bluetooth import Address
from test.controller_test import ControllerTest
from rootcanal.controller import Phy


class Test(ControllerTest):
    # Verify that the controller can establish a connection if the remote device
    # is initiating a connection at the same time. The local device responds to he
    # page events and accepts the connection. The local connection attempt is
    # abandoned and a Connection Complete event with status Connection Already
    # Exists is sent to the Host.

    async def test_scenario_1(self):
        controller = self.controller
        peer_address = Address("11:22:33:44:55:66")

        controller.send_cmd(
            hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY)
        )

        await self.expect_evt(
            hci.WriteScanEnableComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        controller.send_cmd(
            hci.CreateConnection(
                bd_addr=peer_address,
                packet_type=0,
                page_scan_repetition_mode=hci.PageScanRepetitionMode.R1,
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
            ll.Page(
                source_address=peer_address,
                destination_address=controller.address,
                allow_role_switch=False,
            ),
            phy=Phy.BrEdr,
        )

        await self.expect_evt(
            hci.ConnectionRequest(
                bd_addr=peer_address, link_type=hci.ConnectionRequestLinkType.ACL
            )
        )

        controller.send_cmd(
            hci.AcceptConnectionRequest(
                bd_addr=peer_address,
                role=hci.AcceptConnectionRequestRole.REMAIN_PERIPHERAL,
            )
        )

        await self.expect_evt(
            hci.AcceptConnectionRequestStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        await self.expect_ll(
            ll.PageResponse(
                source_address=controller.address,
                destination_address=peer_address,
                try_role_switch=False,
            )
        )

        await self.expect_evt(
            hci.ConnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                bd_addr=peer_address,
                link_type=hci.LinkType.ACL,
                encryption_enabled=hci.Enable.DISABLED,
            )
        )

    async def test_scenario_2(self):
        controller = self.controller
        peer_address = Address("11:22:33:44:55:66")

        controller.send_cmd(
            hci.WriteScanEnable(scan_enable=hci.ScanEnable.PAGE_SCAN_ONLY)
        )

        await self.expect_evt(
            hci.WriteScanEnableComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        controller.send_cmd(
            hci.CreateConnection(
                bd_addr=peer_address,
                packet_type=0,
                page_scan_repetition_mode=hci.PageScanRepetitionMode.R1,
                allow_role_switch=hci.CreateConnectionRoleSwitch.ALLOW_ROLE_SWITCH,
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
                allow_role_switch=True,
            )
        )

        controller.send_ll(
            ll.Page(
                source_address=peer_address,
                destination_address=controller.address,
                allow_role_switch=True,
            ),
            phy=Phy.BrEdr,
        )

        await self.expect_evt(
            hci.ConnectionRequest(
                bd_addr=peer_address, link_type=hci.ConnectionRequestLinkType.ACL
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

        controller.send_cmd(
            hci.AcceptConnectionRequest(
                bd_addr=peer_address,
                role=hci.AcceptConnectionRequestRole.REMAIN_PERIPHERAL,
            )
        )

        await self.expect_evt(
            hci.ConnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                bd_addr=peer_address,
                link_type=hci.LinkType.ACL,
                encryption_enabled=hci.Enable.DISABLED,
            )
        )

        await self.expect_evt(
            hci.AcceptConnectionRequestStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )
