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

    # LL/DDI/ADV/BV-17-C [Scan Request: Discoverable]
    async def test(self):
        controller = self.controller

        # 1. Upper Tester enables discoverable undirected advertising in the IUT using all supported
        # advertising channels and a selected advertising interval between the minimum and maximum
        # advertising.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_SCAN_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT. The
        # Lower Tester will send an SCAN_REQ packet on a selected supported advertising channel
        # (defined as an IXIT) and using a common public device address as parameter.
        peer_address = Address('aa:bb:cc:dd:ee:ff')

        # 3. Configure Scan Response Data in the IUT using device name length of 0 as response data.
        scan_response_data = []
        controller.send_cmd(hci.LeSetScanResponseDataRaw(advertising_data=scan_response_data))

        await self.expect_evt(hci.LeSetScanResponseDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. Lower Tester sends a SCAN_REQ packet on the selected advertising channel after receiving an
        # ADV_SCAN_IND packet from IUT on the advertising channel configured in step 3. The
        # SCAN_REQ is sent T_IFS after the end of an ADV_SCAN_IND packet.
        # 5. Lower Tester receives a SCAN_RSP packet from the IUT addressed to the Lower Tester T_IFS
        # after the end of the request packet.
        # 6. Repeat steps 4–5 30 times.
        await self.steps_4_6(peer_address=peer_address, scan_response_data=scan_response_data)

        # 7. Configure Scan Response Data in the IUT using device name length of 31 as response data.
        scan_response_data = [31] + [0] * 31
        controller.send_cmd(hci.LeSetScanResponseDataRaw(advertising_data=scan_response_data))

        await self.expect_evt(hci.LeSetScanResponseDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 8. Repeat steps 4–6.
        await self.steps_4_6(peer_address=peer_address, scan_response_data=scan_response_data)

        # 9. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT. The
        # Lower Tester will send an SCAN_REQ packet on a selected supported advertising channel
        # (defined as an IXIT) and using a public device address that differs from the IUT address in the
        # most significant octet as parameter.
        peer_address = Address([
            controller.address.address[0] ^ 0xff, controller.address.address[1], controller.address.address[2],
            controller.address.address[3], controller.address.address[4], controller.address.address[5]
        ])

        # 10. Configure Scan Response Data in the IUT using device name length of 0 as response data.
        scan_response_data = []
        controller.send_cmd(hci.LeSetScanResponseDataRaw(advertising_data=scan_response_data))

        await self.expect_evt(hci.LeSetScanResponseDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 11. Repeat steps 4–6.
        await self.steps_4_6(peer_address=peer_address, scan_response_data=scan_response_data)

        # 12. Configure Scan Response Data in the IUT using device name length of 31 as response data.
        scan_response_data = [31] + [0] * 31
        controller.send_cmd(hci.LeSetScanResponseDataRaw(advertising_data=scan_response_data))

        await self.expect_evt(hci.LeSetScanResponseDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 13. Repeat steps 4–6.
        await self.steps_4_6(peer_address=peer_address, scan_response_data=scan_response_data)

        # Note: this last iteration is very redundant, not implementing it
        # to save on execution time.

        # 14. Configure Lower Tester to monitor the advertising and scan response procedures of the IUT. The
        # Lower Tester will send an SCAN_REQ packet on a selected supported advertising channel
        # (defined as an IXIT) and using a public device address with address that differs from the IUT
        # address in the most and least significant octets as parameter.

        # 15. Configure Scan Response Data in the IUT using device name length of 0 as response data.
        # 16. Repeat steps 4–6.

    async def steps_4_6(self, peer_address: Address, scan_response_data: List[int]):
        controller = self.controller

        # 4. Lower Tester sends a SCAN_REQ packet on the selected advertising channel after receiving an
        # ADV_SCAN_IND packet from IUT on the advertising channel configured in step 3. The
        # SCAN_REQ is sent T_IFS after the end of an ADV_SCAN_IND packet.
        # 5. Lower Tester receives a SCAN_RSP packet from the IUT addressed to the Lower Tester T_IFS
        # after the end of the request packet.
        # 6. Repeat steps 4–5 30 times.
        for n in range(3):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                           advertising_data=[]),
                                 timeout=5)

            controller.send_ll(
                ll.LeScan(source_address=peer_address,
                          destination_address=controller.address,
                          scanning_address_type=ll.AddressType.PUBLIC,
                          advertising_address_type=ll.AddressType.PUBLIC))

            await self.expect_ll(ll.LeScanResponse(source_address=controller.address,
                                                   destination_address=peer_address,
                                                   advertising_address_type=ll.AddressType.PUBLIC,
                                                   scan_response_data=scan_response_data),
                                 timeout=5)

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
