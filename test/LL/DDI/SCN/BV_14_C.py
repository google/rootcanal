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
from py.controller import ControllerTest, generate_rpa


class Test(ControllerTest):

    # LL/DDI/SCN/BV-13-C  [Network Privacy - Passive Scanning: Directed Events to an address
    # different from the scanner’s address]
    async def test(self):
        # Test parameters.
        RPA_timeout = 0x10
        LL_scanner_scanInterval_MIN = 0x2000
        LL_scanner_scanInterval_MAX = 0x2000
        LL_scanner_scanWindow_MIN = 0x200
        LL_scanner_scanWindow_MAX = 0x200
        LL_scanner_Adv_Channel_Map = 0x7

        controller = self.controller
        peer_irk = bytes([1] * 16)
        local_irk = bytes([2] * 16)
        peer_resolvable_address = generate_rpa(peer_irk)
        local_resolvable_address_1 = generate_rpa(local_irk)
        local_resolvable_address_2 = generate_rpa(local_irk)

        if not controller.le_features.ll_privacy:
            self.skipTest("LL privacy not supported")

        # 1. The Upper Tester sets a resolvable private address for the IUT to use.
        controller.send_cmd(hci.LeSetRandomAddress(random_address=local_resolvable_address_1))

        await self.expect_evt(hci.LeSetRandomAddressComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetResolvablePrivateAddressTimeout(rpa_timeout=RPA_timeout))

        await self.expect_evt(
            hci.LeSetResolvablePrivateAddressTimeoutComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. The Upper Tester enables passive scanning using filter policy 0x02 in the IUT.
        controller.send_cmd(
            hci.LeSetScanParameters(le_scan_type=hci.LeScanType.PASSIVE,
                                    le_scan_interval=LL_scanner_scanInterval_MAX,
                                    le_scan_window=LL_scanner_scanWindow_MAX,
                                    own_address_type=hci.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                                    scanning_filter_policy=hci.LeScanningFilterPolicy.CHECK_INITIATORS_IDENTITY))

        await self.expect_evt(hci.LeSetScanParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(
            hci.LeSetScanEnable(le_scan_enable=hci.Enable.ENABLED, filter_duplicates=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Configure the Lower Tester to start advertising. The Lower Tester uses a resolvable private
        # address type in the AdvA field. The InitA field also contains a resolvable private address, which
        # does not match the address set by the Upper Tester in the IUT.

        # 4. The Lower Tester sends an ADV_ DIRECT _IND packet each advertising event using the
        # selected advertising channel only. Repeat for at least 20 advertising intervals.
        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=peer_resolvable_address,
                                                     destination_address=local_resolvable_address_2,
                                                     advertising_address_type=ll.AddressType.RANDOM,
                                                     target_address_type=ll.AddressType.RANDOM,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_DIRECT_IND,
                                                     advertising_data=[1, 2, 3]),
                           rssi=-16)

        # 5. The Upper Tester receives at least one HCI_LE_Direct_Advertising_Report reporting the
        # advertising packets sent by the Lower Tester.
        await self.expect_evt(
            hci.LeDirectedAdvertisingReport(responses=[
                hci.LeDirectedAdvertisingResponse(event_type=hci.AdvertisingEventType.ADV_DIRECT_IND,
                                                  address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                                                  address=peer_resolvable_address,
                                                  direct_address_type=hci.DirectAddressType.RANDOM_DEVICE_ADDRESS,
                                                  direct_address=local_resolvable_address_2,
                                                  rssi=0xf0)
            ]))

        # 6. The Upper Tester sends an HCI_LE_Set_Scan_Enable to the IUT to stop the scanning function
        # and receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetScanEnable(le_scan_enable=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
