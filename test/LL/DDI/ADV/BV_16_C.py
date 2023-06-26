# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):
    # Test parameters.
    LL_advertiser_advInterval_MIN = 0x200
    LL_advertiser_advInterval_MAX = 0x200
    LL_advertiser_Adv_Channel_Map = 0x7

    # LL/DDI/ADV/BV-16-C [Advertising Data: Discoverable]
    async def test(self):
        controller = self.controller

        # 1. Upper Tester enables discoverable undirected advertising in the IUT using a selected advertising
        # channel and a selected advertising interval between the minimum and maximum advertising
        # intervals.
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

        # 2. Upper Tester sends an HCI_LE_Set_Advertising_Data command to the IUT and receives an
        # HCI_Command_Complete in response. The data element used in the command is a number
        # indicating the length of the data. The data length is 1 byte.
        advertising_data = [1]
        controller.send_cmd(hci.LeSetAdvertisingData(advertising_data=advertising_data))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to enable
        # advertising and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. Lower Tester expects the IUT to send ADV_SCAN_IND packets including the data submitted in
        # step 3 starting an event on the selected advertising channel.
        # 5. Expect the following event to start after advertising interval time calculating from the start of the
        # first packet.
        # 6. Repeat steps 5–6 until a number of advertising intervals (50) have been detected.
        for n in range(3):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                           advertising_data=advertising_data),
                                 timeout=5)

        # 7. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to disable
        # advertising function and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 8. Upper Tester sends an HCI_LE_Set_Advertising_Data to configure the IUT to send advertising
        # packets without advertising data and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingData(advertising_data=[]))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 9. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to enable
        # advertising and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 10. Lower Tester expects the IUT to send ADV_SCAN_IND packets including no advertising data
        # starting an event on the selected advertising channel.
        # 11. Expect the next event to start after advertising interval time calculating from the start of the first
        # packet.
        # 12. Repeat steps 11–12 until a number of advertising intervals (50) have been detected.
        for n in range(3):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                           advertising_data=[]),
                                 timeout=5)

        # 13. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to the IUT to disable
        # advertising and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 14. Upper Tester sends an HCI_LE_Set_Advertising_Data command to the IUT and receives an
        # HCI_Command_Complete in response. The data element is a number indicating the length of the
        # data field in the first octet encoded unsigned least significant bit first and the rest of the octets
        # zeroes. The data length is 31 bytes.
        advertising_data = [31] + [0] * 30
        controller.send_cmd(hci.LeSetAdvertisingData(advertising_data=advertising_data))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 15. Repeat steps 4–14.
        for n in range(3):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                           advertising_data=advertising_data),
                                 timeout=5)

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingData(advertising_data=[]))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        for n in range(3):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                           advertising_data=[]),
                                 timeout=5)

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
