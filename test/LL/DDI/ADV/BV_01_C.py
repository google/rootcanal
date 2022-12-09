import lib_rootcanal_python3 as rootcanal
import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    # LL/DDI/ADV/BV-01-C [Non-Connectable Advertising Events]
    async def test(self):
        # Test parameters.
        LL_advertiser_advInterval_MIN = 0x200
        LL_advertiser_advInterval_MAX = 0x200
        LL_advertiser_Adv_Channel_Map = 0x7
        controller = self.controller

        # 1. Configure Lower Tester to monitor advertising packets from the IUT.

        # 2. Upper Tester enables non-connectable advertising in the IUT using a selected advertising
        # channel and a selected advertising interval between the minimum and maximum advertising
        # intervals.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(
                advertising_interval_min=LL_advertiser_advInterval_MIN,
                advertising_interval_max=LL_advertiser_advInterval_MAX,
                advertising_type=hci.AdvertisingType.ADV_NONCONN_IND,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                advertising_channel_map=LL_advertiser_Adv_Channel_Map,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN_AND_CONNECT))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingDataRaw())

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Expect the IUT to send ADV_NONCONN_IND on the selected advertising channel.
        # 4. Expect the following event to start one advertising interval after the start of the first packet.
        # 5. Repeat steps 3–4 until a number of advertising intervals (100) have been detected.
        for n in range(10):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_NONCONN_IND,
                                                           advertising_data=[]),
                                 timeout=5)

        # 6. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to disable advertising in the
        # IUT and receives an HCI_Command_Complete event from the IUT.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
