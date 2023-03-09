import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    # LL/DDI/ADV/BV-04-C [Advertising Data: Undirected]
    async def test(self):
        # Test parameters.
        LL_advertiser_advInterval_MIN = 0x200
        LL_advertiser_advInterval_MAX = 0x200
        LL_advertiser_Adv_Channel_Map = 0x7
        controller = self.controller

        # 1. Configure Lower Tester to monitor advertising packets from the IUT.

        # 2. Upper Tester configures undirected advertising in the IUT using a selected advertising channel
        # and a selected advertising interval between the minimum and maximum advertising intervals.
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

        # 3. Upper Tester sends an HCI_LE_Set_Advertising_Data command to the IUT and receives an
        # HCI_Command_Complete in response. The data element used in the command is the length of
        # the data field. The data length is 1 byte.
        advertising_data = [1]
        controller.send_cmd(hci.LeSetAdvertisingDataRaw(advertising_data=advertising_data))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to enable
        # advertising and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 5. Lower Tester expects the IUT to send ADV_IND packets including the data submitted in step 3
        # starting an event on the selected advertising channel.
        # 6. Expect the following event to start after advertising interval time calculating from the start of the
        # first packet.
        # 7. Repeat steps 5–6 until a number of advertising intervals (50) have been detected.
        for n in range(10):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                                           advertising_data=advertising_data),
                                 timeout=5)

        # 8. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to disable
        # advertising function and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 9. Upper Tester sends an HCI_LE_Set_Advertising_Data to configure the IUT to send advertising
        # packets without advertising data and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingDataRaw(advertising_data=[]))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 10. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to enable
        # advertising and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 11. Lower Tester expects the IUT to send ADV_IND packets including no advertising data starting an
        # event on the selected advertising channel.
        # 12. Expect the next event to start after advertising interval time calculating from the start of the first
        # packet.
        # 13. Repeat steps 11–12 until a number of advertising intervals (50) have been detected.
        for n in range(10):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                                           advertising_data=[]),
                                 timeout=5)

        # 14. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to disable
        # advertising and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 15. Upper Tester sends an HCI_LE_Set_Advertising_Data command to the IUT and receives an
        # HCI_Command_Complete in response. The data element is a number indicating the length of the
        # data field in the first octet encoded unsigned least significant bit first and the rest of the octets
        # zeroes. The data length is 31 bytes.
        advertising_data = [31] + [0] * 30
        controller.send_cmd(hci.LeSetAdvertisingDataRaw(advertising_data=advertising_data))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 16. Repeat steps 4–14.
        for n in range(10):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                                           advertising_data=advertising_data),
                                 timeout=5)

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingDataRaw(advertising_data=[]))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        for n in range(10):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                                           advertising_data=[]),
                                 timeout=5)

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
