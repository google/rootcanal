import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest, generate_rpa


class Test(ControllerTest):

    # LL/DDI/SCN/BV-13-C [Network Privacy – Passive Scanning, Peer IRK]
    async def test(self):
        # Test parameters.
        LL_scanner_scanInterval_MIN = 0x2000
        LL_scanner_scanInterval_MAX = 0x2000
        LL_scanner_scanWindow_MIN = 0x200
        LL_scanner_scanWindow_MAX = 0x200
        LL_scanner_Adv_Channel_Map = 0x7

        controller = self.controller
        peer_irk = bytes([1] * 16)
        peer_identity_address = Address('aa:bb:cc:dd:ee:ff')
        peer_identity_address_type = hci.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS
        peer_resolvable_address = generate_rpa(peer_irk)

        if not controller.le_features.ll_privacy:
            self.skipTest("LL privacy not supported")

        # 1. The Upper Tester populates the IUT resolving list with the peer IRK
        # and identity address.
        controller.send_cmd(
            hci.LeAddDeviceToResolvingList(peer_irk=peer_irk,
                                           local_irk=bytes([0] * 16),
                                           peer_identity_address=peer_identity_address,
                                           peer_identity_address_type=peer_identity_address_type))

        await self.expect_evt(
            hci.LeAddDeviceToResolvingListComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetResolvablePrivateAddressTimeout(rpa_timeout=0x10))

        await self.expect_evt(
            hci.LeSetResolvablePrivateAddressTimeoutComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAddressResolutionEnable(address_resolution_enable=hci.Enable.ENABLED))

        await self.expect_evt(
            hci.LeSetAddressResolutionEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. The Upper Tester enables passive scanning in the IUT.
        controller.send_cmd(
            hci.LeSetScanParameters(le_scan_type=hci.LeScanType.PASSIVE,
                                    le_scan_interval=LL_scanner_scanInterval_MAX,
                                    le_scan_window=LL_scanner_scanWindow_MAX,
                                    own_address_type=hci.OwnAddressType.RESOLVABLE_OR_PUBLIC_ADDRESS,
                                    scanning_filter_policy=hci.LeScanningFilterPolicy.ACCEPT_ALL))

        await self.expect_evt(hci.LeSetScanParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(
            hci.LeSetScanEnable(le_scan_enable=hci.Enable.ENABLED, filter_duplicates=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Configure the Lower Tester to start advertising. The Lower Tester uses
        # a resolvable private address in the AdvA field.
        # 4. The Lower Tester sends an ADV_NONCONN_IND packet each advertising event
        # using the selected advertising channel only. Repeat for at least 20
        # advertising intervals.
        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=peer_resolvable_address,
                                                     advertising_address_type=ll.AddressType.RANDOM,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_NONCONN_IND,
                                                     advertising_data=[1, 2, 3]),
                           rssi=-16)

        # 5. The Upper Tester receives at least one HCI_LE_Advertising_Report
        # reporting the advertising packets sent by the Lower Tester. The address in
        # the report is resolved by the IUT using the distributed IRK.
        await self.expect_evt(
            hci.LeAdvertisingReportRaw(responses=[
                hci.LeAdvertisingResponseRaw(event_type=hci.AdvertisingEventType.ADV_NONCONN_IND,
                                             address_type=hci.AddressType.PUBLIC_IDENTITY_ADDRESS,
                                             address=peer_identity_address,
                                             advertising_data=[1, 2, 3],
                                             rssi=0xf0)
            ]))

        # 6. The Upper Tester sends an HCI_LE_Set_Scan_Enable to the IUT to stop the
        # scanning function and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetScanEnable(le_scan_enable=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 7. The Upper Tester disables address resolution.
        controller.send_cmd(hci.LeSetAddressResolutionEnable(address_resolution_enable=hci.Enable.DISABLED))

        await self.expect_evt(
            hci.LeSetAddressResolutionEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 8. The Upper Tester enables passive scanning in the IUT.
        controller.send_cmd(
            hci.LeSetScanEnable(le_scan_enable=hci.Enable.ENABLED, filter_duplicates=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 9. The Lower Tester sends an ADV_NONCONN_IND packet each advertising event
        # using the selected advertising channel only. Repeat for at least 20
        # advertising intervals.
        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=peer_resolvable_address,
                                                     advertising_address_type=ll.AddressType.RANDOM,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_NONCONN_IND,
                                                     advertising_data=[1, 2, 3]),
                           rssi=-16)

        # 10. The IUT does not resolve the Lower Tester’s address and reports it
        # unresolved (as received in the advertising PDU) in the advertising report
        # events to the Upper Tester.
        await self.expect_evt(
            hci.LeAdvertisingReportRaw(responses=[
                hci.LeAdvertisingResponseRaw(event_type=hci.AdvertisingEventType.ADV_NONCONN_IND,
                                             address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                                             address=peer_resolvable_address,
                                             advertising_data=[1, 2, 3],
                                             rssi=0xf0)
            ]))

        # 11. The Upper Tester sends an HCI_LE_Set_Scan_Enable to the IUT to stop the
        # scanning function and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetScanEnable(le_scan_enable=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
