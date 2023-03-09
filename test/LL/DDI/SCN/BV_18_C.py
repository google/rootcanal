import asyncio
import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest, generate_rpa


class Test(ControllerTest):

    # LL/DDI/SCN/BV-18-C [Network Privacy – Active Scanning, Local IRK, Peer IRK]
    async def test(self):
        # Test parameters.
        RPA_timeout = 0x10
        LL_scanner_scanInterval_MIN = 0x2000
        LL_scanner_scanInterval_MAX = 0x2000
        LL_scanner_scanWindow_MIN = 0x200
        LL_scanner_scanWindow_MAX = 0x200
        LL_scanner_Adv_Channel_Map = 0x7

        controller = self.controller
        local_random_address = Address('aa:bb:cc:dd:ee:c0')
        peer_irk = bytes([1] * 16)
        local_irk = bytes([2] * 16)
        peer_identity_address = Address('aa:bb:cc:dd:ff:c0')
        peer_identity_address_type = hci.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS
        peer_resolvable_address = generate_rpa(peer_irk)

        if not controller.le_features.ll_privacy:
            self.skipTest("LL privacy not supported")

        # 1. Upper Tester sends an HCI_LE_Set_Random_Address to the IUT with a
        # random static address.
        controller.send_cmd(hci.LeSetRandomAddress(random_address=local_random_address))

        await self.expect_evt(hci.LeSetRandomAddressComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. Configure the Lower Tester as an advertiser using a resolvable
        # private address in the AdvA field.

        # 3. Upper Tester adds peer device identity and local IRK information
        # to resolving list.
        controller.send_cmd(
            hci.LeAddDeviceToResolvingList(peer_irk=peer_irk,
                                           local_irk=local_irk,
                                           peer_identity_address=peer_identity_address,
                                           peer_identity_address_type=peer_identity_address_type))

        await self.expect_evt(
            hci.LeAddDeviceToResolvingListComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetResolvablePrivateAddressTimeout(rpa_timeout=RPA_timeout))

        await self.expect_evt(
            hci.LeSetResolvablePrivateAddressTimeoutComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAddressResolutionEnable(address_resolution_enable=hci.Enable.ENABLED))

        await self.expect_evt(
            hci.LeSetAddressResolutionEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. Upper Tester enables active scanning with filtering policy set to
        # ‘Accept all advertising packets (0x00)’ in the IUT.
        controller.send_cmd(
            hci.LeSetScanParameters(le_scan_type=hci.LeScanType.ACTIVE,
                                    le_scan_interval=LL_scanner_scanInterval_MAX,
                                    le_scan_window=LL_scanner_scanWindow_MAX,
                                    own_address_type=hci.OwnAddressType.RESOLVABLE_OR_RANDOM_ADDRESS,
                                    scanning_filter_policy=hci.LeScanningFilterPolicy.ACCEPT_ALL))

        await self.expect_evt(hci.LeSetScanParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(
            hci.LeSetScanEnable(le_scan_enable=hci.Enable.ENABLED, filter_duplicates=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 5. The Lower Tester sends an ADV_SCAN_IND packet each advertising
        # event using the selected advertising channel only. Repeat for at
        # least 20 advertising intervals or until step 7 occurs.
        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=peer_resolvable_address,
                                                     advertising_address_type=ll.AddressType.RANDOM,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                     advertising_data=[1, 2, 3]),
                           rssi=-16)

        # 6. Lower Tester receives a SCAN_REQ packet T_IFS after any of the
        # ADV_SCAN_IND packets. The ScanA field in the SCAN_REQ packet shall
        # use the same resolvable private address.
        scan_req = await asyncio.wait_for(controller.receive_ll(), timeout=3)
        scan_req = ll.LinkLayerPacket.parse_all(scan_req)
        self.assertTrue(isinstance(scan_req, ll.LeScan))
        # TODO check that source_address is resolvable by lower tester.
        self.assertTrue(scan_req.source_address.is_resolvable())
        self.assertEqual(
            scan_req,
            ll.LeScan(source_address=scan_req.source_address,
                      destination_address=peer_resolvable_address,
                      advertising_address_type=ll.AddressType.RANDOM,
                      scanning_address_type=ll.AddressType.RANDOM))

        # 8. Interleave with step 6: Upper Tester receives an
        # HCI_LE_Advertising_Report containing the information used in the
        # ADV_SCAN_IND packets.
        await self.expect_evt(
            hci.LeAdvertisingReportRaw(responses=[
                hci.LeAdvertisingResponseRaw(event_type=hci.AdvertisingEventType.ADV_SCAN_IND,
                                             address_type=hci.AddressType.PUBLIC_IDENTITY_ADDRESS,
                                             address=peer_identity_address,
                                             advertising_data=[1, 2, 3],
                                             rssi=0xf0)
            ]))

        # 7. Lower Tester sends a SCAN_RSP packet T_IFS after the SCAN_REQ
        # packet. The AdvA field in the SCAN_RSP packet should use the
        # resolvable private address that was used in the SCAN_REQ packet.
        controller.send_ll(ll.LeScanResponse(source_address=peer_resolvable_address,
                                             advertising_address_type=ll.AddressType.RANDOM,
                                             scan_response_data=[4, 5, 6]),
                           rssi=-16)

        # 9. Interleave with step 7: Upper Tester receives an
        # HCI_LE_Advertising_Report event containing the scan response
        # information.
        await self.expect_evt(hci.LeAdvertisingReportRaw(responses=[
            hci.LeAdvertisingResponseRaw(event_type=hci.AdvertisingEventType.SCAN_RESPONSE,
                                         address_type=hci.AddressType.PUBLIC_IDENTITY_ADDRESS,
                                         address=peer_identity_address,
                                         advertising_data=[4, 5, 6],
                                         rssi=0xf0)
        ]),
                              timeout=3)
