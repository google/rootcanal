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
from typing import List
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):
    # Test parameters.
    LL_advertiser_advInterval_MIN = 0x200
    LL_advertiser_advInterval_MAX = 0x200
    LL_advertiser_Adv_Channel_Map = 0x7

    # LL/DDI/ADV/BV-21-C [Extended Advertising, Legacy PDUs, Non-Connectable]
    async def test(self):
        controller = self.controller

        # 1. Configure Lower Tester to monitor advertising packets from the IUT.
        # 2. The Upper Tester sends an HCI_LE_Set_Extended_Advertising_Parameters command to the
        # IUT using a selected primary advertising channel and minimum advertising interval. The
        # Advertising_Event_Properties parameter shall be set to 00010000b (ADV_NONCONN_IND
        # legacy PDU).
        controller.send_cmd(
            hci.LeSetExtendedAdvertisingParametersLegacy(
                advertising_handle=0,
                legacy_advertising_event_properties=hci.LegacyAdvertisingEventProperties.ADV_NONCONN_IND,
                primary_advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                primary_advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                primary_advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # For each round from 1–3 based on Table 4.2:
        await self.steps_3_8(advertising_data=[1])
        await self.steps_3_8(advertising_data=[])
        await self.steps_3_8(advertising_data=[0xf8] + [0] * 30)

    async def steps_3_8(self, advertising_data: List[int]):
        controller = self.controller

        # 3. Upper Tester sends an HCI_LE_Set_Extended_Advertising_Data command to the IUT with
        # values according to Table 4.2 and receives an HCI_Command_Complete in response.
        controller.send_cmd(
            hci.LeSetExtendedAdvertisingData(advertising_handle=0,
                                             operation=hci.Operation.COMPLETE_ADVERTISEMENT,
                                             advertising_data=advertising_data))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. Upper Tester sends an HCI_LE_Set_Extended_Advertising_Enable command to the IUT to
        # enable advertising and receives an HCI_Command_Complete event in response.
        controller.send_cmd(
            hci.LeSetExtendedAdvertisingEnable(
                enable=hci.Enable.ENABLED,
                enabled_sets=[hci.EnabledSet(advertising_handle=0, duration=0, max_extended_advertising_events=0)]))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 5. Lower Tester expects the IUT to send ADV_NONCONN_IND packets including the data
        # submitted in step 3 starting an event on the selected primary advertising channel.
        # 6. Expect the following event to start after advertising interval time calculating from the start of the
        # first packet.
        # 7. Repeat steps 5–6 until a number of advertising intervals (50) have been detected.
        for n in range(3):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_NONCONN_IND,
                                          advertising_data=advertising_data))

        # 8. Upper Tester sends an HCI_LE_Set_Extended_Advertising_Enable command to the IUT to
        # disable advertising function and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetExtendedAdvertisingEnable(enable=hci.Enable.DISABLED, enabled_sets=[]))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
