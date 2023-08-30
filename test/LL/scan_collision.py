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

    # Verify that the scanner gracefully handles being disabled before
    # receiving the response to a scan request.
    async def test(self):
        # Test parameters.
        LL_scanner_scanInterval_MIN = 0x2000
        LL_scanner_scanInterval_MAX = 0x2000
        LL_scanner_scanWindow_MIN = 0x200
        LL_scanner_scanWindow_MAX = 0x200
        LL_scanner_Adv_Channel_Map = 0x7

        controller = self.controller
        peer_address = Address('aa:bb:cc:dd:ee:ff')

        controller.send_cmd(
            hci.LeSetScanParameters(le_scan_type=hci.LeScanType.ACTIVE,
                                    le_scan_interval=LL_scanner_scanInterval_MAX,
                                    le_scan_window=LL_scanner_scanWindow_MAX,
                                    own_address_type=hci.OwnAddressType.RESOLVABLE_OR_PUBLIC_ADDRESS,
                                    scanning_filter_policy=hci.LeScanningFilterPolicy.ACCEPT_ALL))

        await self.expect_evt(hci.LeSetScanParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(
            hci.LeSetScanEnable(le_scan_enable=hci.Enable.ENABLED, filter_duplicates=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=peer_address,
                                                     advertising_address_type=ll.AddressType.RANDOM,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                     advertising_data=[]),
                           rssi=-16)

        await self.expect_evt(
            hci.LeAdvertisingReport(responses=[
                hci.LeAdvertisingResponse(event_type=hci.AdvertisingEventType.ADV_SCAN_IND,
                                          address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                                          address=peer_address,
                                          advertising_data=[],
                                          rssi=0xf0)
            ]))

        await self.expect_ll(
            ll.LeScan(source_address=controller.address,
                      destination_address=peer_address,
                      advertising_address_type=ll.AddressType.RANDOM,
                      scanning_address_type=ll.AddressType.PUBLIC))

        # Disable the scanner before the scan response is received.
        controller.send_cmd(hci.LeSetScanEnable(le_scan_enable=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # Send the scan response now; it should be ignored by the disabled scanner.
        controller.send_ll(ll.LeScanResponse(source_address=peer_address,
                                             advertising_address_type=ll.AddressType.RANDOM,
                                             scan_response_data=[]),
                           rssi=-16)

        # Re-enable the scanner and send the advertising PDU again.
        # This time expect the scan response to be properly reported.
        controller.send_cmd(
            hci.LeSetScanEnable(le_scan_enable=hci.Enable.ENABLED, filter_duplicates=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=peer_address,
                                                     advertising_address_type=ll.AddressType.RANDOM,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_SCAN_IND,
                                                     advertising_data=[]),
                           rssi=-16)

        await self.expect_evt(
            hci.LeAdvertisingReport(responses=[
                hci.LeAdvertisingResponse(event_type=hci.AdvertisingEventType.ADV_SCAN_IND,
                                          address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                                          address=peer_address,
                                          advertising_data=[],
                                          rssi=0xf0)
            ]))

        await self.expect_ll(
            ll.LeScan(source_address=controller.address,
                      destination_address=peer_address,
                      advertising_address_type=ll.AddressType.RANDOM,
                      scanning_address_type=ll.AddressType.PUBLIC))

        controller.send_ll(ll.LeScanResponse(source_address=peer_address,
                                             advertising_address_type=ll.AddressType.RANDOM,
                                             scan_response_data=[]),
                           rssi=-16)

        await self.expect_evt(
            hci.LeAdvertisingReport(responses=[
                hci.LeAdvertisingResponse(event_type=hci.AdvertisingEventType.SCAN_RESPONSE,
                                          address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                                          address=peer_address,
                                          advertising_data=[],
                                          rssi=0xf0)
            ]))
