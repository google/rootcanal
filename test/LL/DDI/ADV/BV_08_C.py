import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    # LL/DDI/ADV/BV-08-C [Scan Request Device Filtering]
    async def test(self):
        # Test parameters.
        LL_advertiser_advInterval_MIN = 0x200
        LL_advertiser_advInterval_MAX = 0x200
        LL_advertiser_Adv_Channel_Map = 0x7
        controller = self.controller
        public_peer_address = Address('aa:bb:cc:dd:ee:ff')
        random_peer_address = Address('00:bb:cc:dd:ee:ff')
        invalid_peer_address = Address('aa:bb:cc:dd:ee:00')

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

        # 1. Upper Tester enables undirected advertising in the IUT using public address type, all supported
        # advertising channels, an advertising interval between the minimum and maximum advertising
        # intervals and filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow Connect
        # Request from Filter Accept List (0x03)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(
                advertising_interval_min=LL_advertiser_advInterval_MIN,
                advertising_interval_max=LL_advertiser_advInterval_MAX,
                advertising_type=hci.AdvertisingType.ADV_IND,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                advertising_channel_map=LL_advertiser_Adv_Channel_Map,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN_AND_CONNECT))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. Upper Tester sends an HCI_LE_Set_Scan_Response_Data command with data set to “IUT” and
        # receives an HCI_Command_Complete event from the IUT.
        scan_response_data = [ord('I'), ord('U'), ord('T')]
        controller.send_cmd(hci.LeSetScanResponseDataRaw(advertising_data=scan_response_data))

        await self.expect_evt(hci.LeSetScanResponseDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Lower Tester address type is set to Public Address type.
        # 4. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT and
        # send a SCAN_REQ packet on the selected supported advertising channel (defined as an IXIT)
        # with an address that differs from the IUT address in the least significant octet.
        # 5. Lower Tester receives an ADV_IND packet from the IUT and responds with an SCAN_REQ
        # packet with the selected address on the selected advertising channel T_IFS after the end of an
        # advertising packet.
        # 6. Lower Tester receives no response from the IUT.
        # 7. Repeat steps 5–6 30 times.
        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=invalid_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.PUBLIC),
                               rssi=-16)

        # 8. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT and
        # send a SCAN_REQ packet on the selected supported advertising channel (defined as an IXIT)
        # with an address in the Filter Accept List in the policy applied and an incorrect address type.
        # 9. Repeat steps 5–6 30 times.
        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=public_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.RANDOM),
                               rssi=-16)

        # 10. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT and
        # send a SCAN_REQ packet on the selected supported advertising channel (defined as an IXIT)
        # with an address in the Filter Accept List in the policy applied and correct address type.
        # 11. Lower Tester receives an ADV_IND packet from the IUT and responds with an SCAN_REQ
        # packet with an address in the Filter Accept List in the policy applied using correct address type,
        # on the selected advertising channel T_IFS after the end of an advertising packet.
        # 12. Lower Tester receives a SCAN_RSP packet from the IUT addressed to the Lower Tester T_IFS
        # after the end of the request packet.
        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=public_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.PUBLIC),
                               rssi=-16)

            await self.expect_ll(
                ll.LeScanResponse(source_address=controller.address,
                                  destination_address=public_peer_address,
                                  advertising_address_type=ll.AddressType.PUBLIC,
                                  scan_response_data=scan_response_data))

        # 13. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to disable
        # advertising and receives an HCI_Command_Complete event in response.
        # Note: this step is not actually required.

        # 15. Lower Tester address type is set to Random Address type.
        # 16. Repeat steps 4–13.
        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=invalid_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.RANDOM),
                               rssi=-16)

        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=random_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.PUBLIC),
                               rssi=-16)

        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=random_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.RANDOM),
                               rssi=-16)

            await self.expect_ll(
                ll.LeScanResponse(source_address=controller.address,
                                  destination_address=random_peer_address,
                                  advertising_address_type=ll.AddressType.PUBLIC,
                                  scan_response_data=scan_response_data))

        # 17. Upper Tester enables undirected advertising in the IUT using public address type, all supported
        # advertising channels, an advertising interval between the minimum and maximum advertising
        # intervals and filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow Connect
        # Request from Any (0x01)’.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 18. Lower Tester address type is set to Public Address type.
        # 19. Repeat steps 4–13.
        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=invalid_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.PUBLIC),
                               rssi=-16)

        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=public_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.RANDOM),
                               rssi=-16)

        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=public_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.PUBLIC),
                               rssi=-16)

            await self.expect_ll(
                ll.LeScanResponse(source_address=controller.address,
                                  destination_address=public_peer_address,
                                  advertising_address_type=ll.AddressType.PUBLIC,
                                  scan_response_data=scan_response_data))

        # 20. Upper Tester enables undirected advertising in the IUT using public address type, all supported
        # advertising channels, an advertising interval between the minimum and maximum advertising
        # intervals and filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow Connect
        # Request from Any (0x01)’.
        # Note: this step is not actually required.

        # 21. Lower Tester address type is set to Random Address type.
        # 22. Repeat steps 4–13.
        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=invalid_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.RANDOM),
                               rssi=-16)

        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=random_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.PUBLIC),
                               rssi=-16)

        for n in range(2):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=random_peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.RANDOM),
                               rssi=-16)

            await self.expect_ll(
                ll.LeScanResponse(source_address=controller.address,
                                  destination_address=random_peer_address,
                                  advertising_address_type=ll.AddressType.PUBLIC,
                                  scan_response_data=scan_response_data))
