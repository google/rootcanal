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

import asyncio
import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest, generate_rpa


class Test(ControllerTest):

    LL_initiator_scanInterval_MIN = 0x2000
    LL_initiator_scanInterval_MAX = 0x2000
    LL_initiator_scanWindow_MIN = 0x200
    LL_initiator_scanWindow_MAX = 0x200
    LL_initiator_Adv_Channel_Map = 0x7
    LL_initiator_Channel_Map = 0x7

    # LL/CON/INI/BV-09-C [Network Privacy – Connection Establishment using
    # resolving list, Initiator]
    #
    # Verify that the IUT when initiating connection establishment only connects
    # to devices that are in the resolving list. The Lower Tester uses
    # connectable undirected advertising.
    async def test(self):
        # Test parameters.
        controller = self.controller
        local_irk = bytes([1] * 16)
        peer_irk = bytes([2] * 16)
        random_irk = bytes([3] * 16)
        peer_address = Address('aa:bb:cc:dd:ee:ff')

        if not controller.le_features.ll_privacy:
            self.skipTest("LL privacy not supported")

        # 1. Configure the Lower Tester to start advertising with a resolvable
        # private address generated from a random IRK.

        # 2. The Upper Tester adds the Lower Tester to the resolving list using
        # a different IRK than in step 1.
        controller.send_cmd(
            hci.LeAddDeviceToResolvingList(
                peer_irk=peer_irk,
                local_irk=local_irk,
                peer_identity_address=peer_address,
                peer_identity_address_type=hci.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS))

        await self.expect_evt(
            hci.LeAddDeviceToResolvingListComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetResolvablePrivateAddressTimeout(rpa_timeout=0x10))

        await self.expect_evt(
            hci.LeSetResolvablePrivateAddressTimeoutComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAddressResolutionEnable(address_resolution_enable=hci.Enable.ENABLED))

        await self.expect_evt(
            hci.LeSetAddressResolutionEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. The Upper Tester enables the initiator state in the IUT.
        controller.send_cmd(
            hci.LeCreateConnection(le_scan_interval=Test.LL_initiator_scanInterval_MIN,
                                   le_scan_window=Test.LL_initiator_scanWindow_MIN,
                                   initiator_filter_policy=hci.InitiatorFilterPolicy.USE_PEER_ADDRESS,
                                   peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                   peer_address=peer_address,
                                   own_address_type=hci.OwnAddressType.RESOLVABLE_OR_PUBLIC_ADDRESS,
                                   connection_interval_min=0x200,
                                   connection_interval_max=0x200,
                                   max_latency=0x6,
                                   supervision_timeout=0xc80,
                                   min_ce_length=0,
                                   max_ce_length=0))

        await self.expect_evt(hci.LeCreateConnectionStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. Lower Tester sends ADV_IND packets, each advertising event, using the selected advertising
        # interval. Lower Tester repeats until the time exceeds 4 * scanInterval + 3 * scanWindow.
        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=generate_rpa(random_irk),
                                                     advertising_address_type=ll.AddressType.RANDOM,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                                     advertising_data=[1, 2, 3]),
                           rssi=-16)

        # 5. The IUT compares the address by checking against its resolving list and does not find a match.

        # 6. The Lower Tester receives no CONNECT_IND after any of the ADV_IND packets.
        try:
            await self.expect_ll(ll.LeConnect, timeout=1.0)
            self.assertTrue(False)
        except asyncio.exceptions.TimeoutError:
            pass

        # 7. The Lower Tester stops advertising.

        # 8. The Lower Tester begins advertising again using the correct
        # resolvable address, which matches the one in the IUT resolving list.
        # Lower Tester repeats until the time exceeds 4 * scanInterval +
        # 3 * scanWindow, or step 9 occurs.
        peer_resolvable_address = generate_rpa(peer_irk)
        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=peer_resolvable_address,
                                                     advertising_address_type=ll.AddressType.RANDOM,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                                     advertising_data=[1, 2, 3]),
                           rssi=-16)

        # 9. The Lower Tester receives a CONNECT_IND packet T_IFS after any of the ADV_IND packets.
        connect_ind = await self.expect_ll(
            ll.LeConnect(source_address=self.Any,
                         destination_address=peer_resolvable_address,
                         initiating_address_type=ll.AddressType.RANDOM,
                         advertising_address_type=ll.AddressType.RANDOM,
                         conn_interval=0x200,
                         conn_peripheral_latency=0x6,
                         conn_supervision_timeout=0xc80))

        self.assertTrue(connect_ind.source_address.is_resolvable())
        self.assertTrue(connect_ind.source_address != controller.address)

        controller.send_ll(
            ll.LeConnectComplete(source_address=peer_resolvable_address,
                                 destination_address=connect_ind.source_address,
                                 initiating_address_type=ll.AddressType.RANDOM,
                                 advertising_address_type=ll.AddressType.RANDOM,
                                 conn_interval=0x200,
                                 conn_peripheral_latency=0x6,
                                 conn_supervision_timeout=0xc80))

        # 10. Upper Tester receives an HCI_LE_Enhanced_Connection_Complete event from the IUT
        # including the Lower Tester’s RPA and Identity address and connection interval selected.
        connect_complete = await self.expect_evt(
            hci.LeEnhancedConnectionComplete(status=ErrorCode.SUCCESS,
                                             connection_handle=self.Any,
                                             role=hci.Role.CENTRAL,
                                             peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                             peer_address=peer_address,
                                             peer_resolvable_private_address=peer_resolvable_address,
                                             local_resolvable_private_address=connect_ind.source_address,
                                             connection_interval=0x200,
                                             peripheral_latency=0x6,
                                             supervision_timeout=0xc80,
                                             central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        # 11. After the CONNECT_IND has been received, the Lower Tester receives the first correctly
        # formatted LL Data Channel PDU on the data channel.

        # 12. The Lower Tester sends a correctly formatted LL Data Channel PDU to the IUT on the same data
        # channel using the acknowledgement scheme.

        # 13. The Lower Tester receives correctly formatted LL Data Channel PDUs on subsequent data
        # channels at connection intervals, calculated for the connection interval used.

        # 14. Repeat a number of events (at least 100 events) to verify that the connection is maintained.

        # 15. The Upper Tester terminates the connection.
        controller.send_ll(
            ll.Disconnect(source_address=peer_resolvable_address,
                          destination_address=connect_ind.source_address,
                          reason=hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION))

        await self.expect_evt(
            hci.DisconnectionComplete(status=hci.ErrorCode.SUCCESS,
                                      connection_handle=connect_complete.connection_handle,
                                      reason=hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION))
