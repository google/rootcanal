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
import math
import random
import unittest
from dataclasses import dataclass
from hci_packets import ErrorCode, FragmentPreference
from py.bluetooth import Address
from py.controller import ControllerTest, generate_rpa
from typing import List


@dataclass
class TestRound:
    data_length: int


class Test(ControllerTest):
    # Test parameters.
    LL_advertiser_advInterval_MIN = 0x800
    LL_advertiser_advInterval_MAX = 0x800
    LL_advertiser_Adv_Channel_Map = 0x7
    LL_initiator_connInterval = 0x200
    LL_initiator_connPeripheralLatency = 0x200
    LL_initiator_connSupervisionTimeout = 0x200

    # LL/SEC/ADV/BV-11-C [Network Privacy - Directed Connectable Advertising
    # using local and remote IRK]
    #
    # Verify that the IUT, when transmitting directed connectable advertising
    # events, is using resolvable private addresses for AdvA and InitA fields
    # when the Lower Tester has distributed its own IRK.
    #
    # Verify that when address resolution is disabled on the IUT, the Lower
    # Tester resolvable private address is not resolved, and therefore a
    # connection is not established.
    async def test(self):
        controller = self.controller
        local_irk = bytes([1] * 16)
        peer_irk = bytes([2] * 16)
        random_irk = bytes([3] * 16)
        peer_address = Address('aa:bb:cc:dd:ee:ff')

        # 1. The Lower Tester adds the Device Identity of the IUT to its resolving list.
        # 2. Configure the Lower Tester to initiate a connection while using a resolvable private address.

        # 3. The Upper Tester populates the resolving list with the device identity of the Lower Tester
        # connected with the local device identity. The IUT use these when generating resolvable private
        # addresses for use in the advertising packet’s AdvA and InitA fields.
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

        # 4. The Upper Tester enables resolving list and directed connectable advertising in the IUT.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=Test.LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=Test.LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_DIRECT_IND_HIGH,
                                           own_address_type=hci.OwnAddressType.RESOLVABLE_OR_PUBLIC_ADDRESS,
                                           peer_address=peer_address,
                                           peer_address_type=hci.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                                           advertising_channel_map=0x7,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingData())

        await self.expect_evt(hci.LeSetAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAddressResolutionEnable(address_resolution_enable=hci.Enable.ENABLED))

        await self.expect_evt(
            hci.LeSetAddressResolutionEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 5. The Lower Tester expects the IUT to send ADV_DIRECT_IND packets on an applicable
        # advertising channel.
        direct_ind = await self.expect_ll(ll.LeLegacyAdvertisingPdu(
            source_address=self.Any,
            destination_address=self.Any,
            advertising_address_type=ll.AddressType.RANDOM,
            target_address_type=ll.AddressType.RANDOM,
            advertising_type=ll.LegacyAdvertisingType.ADV_DIRECT_IND,
            advertising_data=[]),
                                          timeout=5)

        self.assertTrue(direct_ind.source_address.is_resolvable())
        self.assertTrue(direct_ind.destination_address.is_resolvable())

        # 6. The Lower Tester identifies the IUT. The Lower Tester sends a CONNECT_IND with the AdvA
        # address of the ADV_DIRECT_IND and the InitA generated based on its Device Identity. The IUT
        # verifies AdvA and resolves the InitA Address and identifies the Lower Tester.
        # 7. The Lower Tester connects to the IUT. The Lower Tester sends empty LL DATA packets starting
        # with the first event one connection interval after the connection request using the common data
        # channel selection parameters.
        init_a = generate_rpa(peer_irk)
        controller.send_ll(
            ll.LeConnect(source_address=init_a,
                         destination_address=direct_ind.source_address,
                         initiating_address_type=ll.AddressType.RANDOM,
                         advertising_address_type=ll.AddressType.RANDOM,
                         conn_interval=Test.LL_initiator_connInterval,
                         conn_peripheral_latency=0x6,
                         conn_supervision_timeout=0xc80))

        await self.expect_ll(
            ll.LeConnectComplete(source_address=direct_ind.source_address,
                                 destination_address=init_a,
                                 initiating_address_type=ll.AddressType.RANDOM,
                                 advertising_address_type=ll.AddressType.RANDOM,
                                 conn_interval=Test.LL_initiator_connInterval,
                                 conn_peripheral_latency=0x6,
                                 conn_supervision_timeout=0xc80))

        connection_complete_evt = await self.expect_evt(
            hci.LeEnhancedConnectionComplete(
                status=hci.ErrorCode.SUCCESS,
                connection_handle=self.Any,
                role=hci.Role.PERIPHERAL,
                peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                peer_address=peer_address,
                local_resolvable_private_address=direct_ind.source_address,
                peer_resolvable_private_address=init_a,
                connection_interval=0x200,
                peripheral_latency=0x6,
                supervision_timeout=0xc80,
                central_clock_accuracy=hci.ClockAccuracy.PPM_500,
            ))

        # 8. The Upper Tester terminates the connection.
        controller.send_cmd(
            hci.Disconnect(connection_handle=connection_complete_evt.connection_handle,
                           reason=hci.DisconnectReason.REMOTE_USER_TERMINATED_CONNECTION))

        await self.expect_evt(hci.DisconnectStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_ll(
            ll.Disconnect(source_address=direct_ind.source_address,
                          destination_address=init_a,
                          reason=hci.DisconnectReason.REMOTE_USER_TERMINATED_CONNECTION))

        await self.expect_evt(
            hci.DisconnectionComplete(status=ErrorCode.SUCCESS,
                                      connection_handle=connection_complete_evt.connection_handle,
                                      reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST))

        # 9. The Upper Tester disables address resolution in the IUT.
        controller.send_cmd(hci.LeSetAddressResolutionEnable(address_resolution_enable=hci.Enable.DISABLED))

        await self.expect_evt(
            hci.LeSetAddressResolutionEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 10. Repeat steps 11–14 at least 20 times.

        # 11. The Upper Tester enables directed connectable advertising in the IUT.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 12. The Lower Tester expects the IUT to send ADV_DIRECT_IND packets on an applicable
        # advertising channel. The Lower Tester resolves the AdvA address and identifies the IUT.
        direct_ind = await self.expect_ll(ll.LeLegacyAdvertisingPdu(
            source_address=self.Any,
            destination_address=self.Any,
            advertising_address_type=ll.AddressType.RANDOM,
            target_address_type=ll.AddressType.RANDOM,
            advertising_type=ll.LegacyAdvertisingType.ADV_DIRECT_IND,
            advertising_data=[]),
                                          timeout=5)

        self.assertTrue(direct_ind.source_address.is_resolvable())
        self.assertTrue(direct_ind.destination_address.is_resolvable())

        # 13. The Lower Tester sends a CONNECT_IND with the AdvA address of the ADV_IND and the InitA
        # set to a different address than the last CONNECT_IND. The IUT does not resolve the address in
        # the InitA field. No connection event is sent to the Upper Tester.
        init_a = generate_rpa(local_irk)
        controller.send_ll(
            ll.LeConnect(source_address=init_a,
                         destination_address=direct_ind.source_address,
                         initiating_address_type=ll.AddressType.RANDOM,
                         advertising_address_type=ll.AddressType.RANDOM,
                         conn_interval=0x200,
                         conn_peripheral_latency=0x6,
                         conn_supervision_timeout=0xc80))

        # 14. The Upper Tester receives an HCI_LE_Connection_Complete event or an
        # HCI_LE_Enhanced_Connection_Complete event with the Status code set to Advertising Timeout
        # (0x3C).
        await self.expect_evt(hci.LeConnectionComplete(status=hci.ErrorCode.ADVERTISING_TIMEOUT,))

        # Empty the LL queue.
        controller.ll_queue.clear()
