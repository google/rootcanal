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

    # LL/DDI/ADV/BV-15-C [Discoverable Advertising Events]
    async def test(self):
        controller = self.controller

        # 1. Configure Lower Tester to monitor advertising packets from the IUT.
        # 2. Upper Tester enables discoverable undirected advertising in the IUT using a selected advertising
        # channel and a selected advertising interval between the minimum and maximum advertising.
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

        controller.send_cmd(hci.LeSetAdvertisingData(advertising_data=[]))

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Lower Tester expects the IUT to send ADV_SCAN_IND packets starting an event on the selected
        # advertising channel.
        # 4. Expect the next event to start after advertising interval time calculated from the start of the first
        # packet.
        # 5. Repeat steps 3–4 until a number of advertising intervals (100) have been detected.
        for n in range(3):
            await self.expect_ll(ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                           advertising_data=[]),
                                 timeout=5)

        # 6. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to disable advertising in the
        # IUT and receives an HCI_Command_Complete event from the IUT.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
