import lib_rootcanal_python3 as rootcanal
import hci_packets as hci
import link_layer_packets as ll
import unittest
from typing import List
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):
    # Test parameters.
    LL_advertiser_advInterval_MIN = 0x200
    LL_advertiser_advInterval_MAX = 0x200
    LL_advertiser_Adv_Channel_Map = 0x7

    # LL/DDI/ADV/BV-18-C [Device Filtering: Discoverable]
    async def test(self):
        controller = self.controller
        public_peer_address = Address('aa:bb:cc:dd:ee:ff')
        random_peer_address = Address('00:bb:cc:dd:ee:ff')

        # Test preparation.
        controller.send_cmd(
            hci.LeAddDeviceToFilterAcceptList(address=public_peer_address,
                                              address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS))

        await self.expect_evt(
            hci.LeAddDeviceToFilterAcceptListComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(
            hci.LeAddDeviceToFilterAcceptList(address=random_peer_address,
                                              address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS))

        await self.expect_evt(
            hci.LeAddDeviceToFilterAcceptListComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 1. Upper Tester enables discoverable undirected advertising in the IUT, all supported advertising
        # channels, an advertising interval between the minimum and maximum advertising intervals and
        # filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow Connect Request from
        # Filter Accept List (0x03)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(
                advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                advertising_type=hci.AdvertisingType.ADV_SCAN_IND,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN_AND_CONNECT))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        scan_response_data = [ord('I'), ord('U'), ord('T')]
        controller.send_cmd(hci.LeSetScanResponseDataRaw(advertising_data=scan_response_data))

        await self.expect_evt(hci.LeSetScanResponseDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. Lower Tester address type is set to Public Address Type.
        await self.steps_3_12(peer_address=public_peer_address,
                              peer_address_type=ll.AddressType.PUBLIC,
                              scan_response_data=scan_response_data)

        # 13. Upper Tester enables discoverable undirected advertising in the IUT using public address type,
        # all supported advertising channels, an advertising interval between the minimum and maximum
        # advertising intervals and filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow
        # Connect Request from Filter Accept List (0x03)’.
        # 14. Lower Tester address type is set to Random Address Type.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(
                advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                advertising_type=hci.AdvertisingType.ADV_SCAN_IND,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN_AND_CONNECT))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 15. Repeat steps 3–12.
        await self.steps_3_12(peer_address=random_peer_address,
                              peer_address_type=ll.AddressType.RANDOM,
                              scan_response_data=scan_response_data)

        # 16. Upper Tester enables discoverable undirected advertising in the IUT using public address type,
        # all supported advertising channels, an advertising interval between the minimum and maximum
        # advertising intervals and filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow
        # Connect Request from Any (0x01)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_SCAN_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 17. Lower Tester address type is set to Public Address Type.
        # 18. Repeat steps 3–12.
        await self.steps_3_12(peer_address=public_peer_address,
                              peer_address_type=ll.AddressType.PUBLIC,
                              scan_response_data=scan_response_data)

        # 19. Upper Tester enables discoverable undirected advertising in the IUT using public address type,
        # all supported advertising channels, an advertising interval between the minimum and maximum
        # advertising intervals and filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow
        # Connect Request from Any (0x01)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_SCAN_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 20. Lower Tester address type is set to Random Address Type.
        # 21. Repeat steps 3–12.
        await self.steps_3_12(peer_address=random_peer_address,
                              peer_address_type=ll.AddressType.RANDOM,
                              scan_response_data=scan_response_data)

    async def steps_3_12(self, peer_address: Address, peer_address_type: ll.AddressType, scan_response_data: List[int]):
        # 3. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT and
        # send an SCAN_REQ packet on the selected supported advertising channel (defined as an IXIT)
        # with an address that differs from the IUT address in the least significant octet.
        controller = self.controller
        invalid_peer_address = Address([
            peer_address.address[0] ^ 0xff, peer_address.address[1], peer_address.address[2], peer_address.address[3],
            peer_address.address[4], peer_address.address[5]
        ])
        invalid_peer_address_type = (ll.AddressType.PUBLIC
                                     if peer_address_type == ll.AddressType.RANDOM else ll.AddressType.RANDOM)

        # 4. Lower Tester receives an ADV_SCAN_IND packet from the IUT and responds with an
        # SCAN_REQ packet with the selected address on the selected advertising channel T_IFS after the
        # end of an advertising packet.
        # 5. Lower Tester receives no response from the IUT.
        # 6. Repeat steps 4–5 30 times.
        for n in range(3):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=invalid_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=peer_address_type),
                               rssi=-16)

        # 7. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT and
        # send a SCAN_REQ packet on the selected supported advertising channel (defined as an IXIT)
        # with an address in the Filter Accept List in the policy applied and an incorrect address type.
        # 8. Repeat steps 4–6 30 times.
        for n in range(3):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=invalid_peer_address_type),
                               rssi=-16)

        # 9. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT and
        # send a SCAN_REQ packet on the selected supported advertising channel (defined as an IXIT)
        # with an address in the Filter Accept List in the policy applied and correct address type.
        # 10. Lower Tester receives an ADV_SCAN_IND packet from the IUT and responds with a
        # SCAN_REQ packet with an address in the Filter Accept List in the policy applied using correct
        # address type, on the selected advertising channel T_IFS after the end of an advertising packet.
        await self.expect_ll(
            ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                      advertising_address_type=ll.AddressType.PUBLIC,
                                      advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                      advertising_data=[]))

        controller.send_ll(ll.LeScan(source_address=peer_address,
                                     destination_address=controller.address,
                                     advertising_address_type=ll.AddressType.PUBLIC,
                                     scanning_address_type=peer_address_type),
                           rssi=-16)

        # 11. Lower Tester receives a SCAN_RSP packet from the IUT addressed to the Lower Tester T_IFS
        # after the end of the request packet.
        await self.expect_ll(
            ll.LeScanResponse(source_address=controller.address,
                              destination_address=peer_address,
                              advertising_address_type=ll.AddressType.PUBLIC,
                              scan_response_data=scan_response_data))

        # 12. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to disable
        # advertising and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
