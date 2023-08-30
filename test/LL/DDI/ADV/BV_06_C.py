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

    # LL/DDI/ADV/BV-06-C [Connection Request]
    async def test(self):
        # Test parameters.
        LL_advertiser_advInterval_MIN = 0x200
        LL_advertiser_advInterval_MAX = 0x200
        LL_initiator_connInterval = 0x200
        LL_initiator_connPeripheralLatency = 0x200
        LL_initiator_connSupervisionTimeout = 0x200
        LL_advertiser_Adv_Channel_Map = 0x7
        controller = self.controller
        peer_address = Address('aa:bb:cc:dd:ee:ff')
        invalid_local_address = Address([
            controller.address.address[0] ^ 0xff, controller.address.address[1], controller.address.address[2],
            controller.address.address[3], controller.address.address[4], controller.address.address[5]
        ])
        connection_handle = 0xefe

        # 1. Upper Tester enables undirected advertising in the IUT using all supported advertising channels
        # and a selected advertising interval between the minimum and maximum advertising intervals.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. Configure Lower Tester to monitor the advertising and connection procedures of the IUT and
        # send a CONNECT_IND packet on the first supported advertising channel.
        # 3. Configure Lower Tester to use a public device address as parameter of CONNECT_IND.

        # 4. The Lower Tester receives an ADV_IND packet from the IUT and responds with a
        # CONNECT_IND packet T_IFS after the end of the advertising packet.
        await self.expect_ll(
            ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                      advertising_address_type=ll.AddressType.PUBLIC,
                                      advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                      advertising_data=[]))

        controller.send_ll(ll.LeConnect(source_address=peer_address,
                                        destination_address=controller.address,
                                        initiating_address_type=ll.AddressType.PUBLIC,
                                        advertising_address_type=ll.AddressType.PUBLIC,
                                        conn_interval=LL_initiator_connInterval,
                                        conn_peripheral_latency=LL_initiator_connPeripheralLatency,
                                        conn_supervision_timeout=LL_initiator_connSupervisionTimeout),
                           rssi=-16)

        # 5. The Lower Tester receives no ADV_IND packet after the advertising interval from the IUT. Wait
        # for a time equal to 4 advertising intervals to check that no ADV_IND is received.
        # Note: Link layer sends LeConnectComplete here.
        await self.expect_ll(
            ll.LeConnectComplete(source_address=controller.address,
                                 destination_address=peer_address,
                                 conn_interval=LL_initiator_connInterval,
                                 conn_peripheral_latency=LL_initiator_connPeripheralLatency,
                                 conn_supervision_timeout=LL_initiator_connSupervisionTimeout))

        # 6. Upper Tester receives an HCI_LE_Connection_Complete event from the IUT including the
        # parameters sent to the IUT in step 4.
        await self.expect_evt(
            hci.LeEnhancedConnectionComplete(status=ErrorCode.SUCCESS,
                                             connection_handle=connection_handle,
                                             role=hci.Role.PERIPHERAL,
                                             peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                             peer_address=peer_address,
                                             connection_interval=LL_initiator_connInterval,
                                             peripheral_latency=LL_initiator_connPeripheralLatency,
                                             supervision_timeout=LL_initiator_connSupervisionTimeout,
                                             central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        # 7. The Upper Tester sends an HCI_Disconnect command to the IUT with the Connection_Handle
        # and receives a successful HCI_Command_Status event in return.
        controller.send_cmd(
            hci.Disconnect(connection_handle=connection_handle,
                           reason=hci.DisconnectReason.REMOTE_USER_TERMINATED_CONNECTION))

        await self.expect_evt(hci.DisconnectStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # Note: Link layer sends Disconnect here.
        await self.expect_ll(
            ll.Disconnect(source_address=controller.address,
                          destination_address=peer_address,
                          reason=int(hci.DisconnectReason.REMOTE_USER_TERMINATED_CONNECTION)))

        # 8. The IUT sends an HCI_Disconnect_Complete event to the Upper Tester.
        await self.expect_evt(
            hci.DisconnectionComplete(status=ErrorCode.SUCCESS,
                                      connection_handle=connection_handle,
                                      reason=hci.ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST))

        # 9. Configure Lower Tester to use a public device address that differs from the IUT address in the
        # most significant octet as parameter of CONNECT_IND.
        # 10. Repeat steps 4–8.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_ll(
            ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                      advertising_address_type=ll.AddressType.PUBLIC,
                                      advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                      advertising_data=[]))

        controller.send_ll(ll.LeConnect(source_address=peer_address,
                                        destination_address=invalid_local_address,
                                        initiating_address_type=ll.AddressType.PUBLIC,
                                        advertising_address_type=ll.AddressType.PUBLIC,
                                        conn_interval=LL_initiator_connInterval,
                                        conn_peripheral_latency=LL_initiator_connPeripheralLatency,
                                        conn_supervision_timeout=LL_initiator_connSupervisionTimeout),
                           rssi=-16)

        # Connect rejected, another ADV_IND event should be received.
        await self.expect_ll(
            ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                      advertising_address_type=ll.AddressType.PUBLIC,
                                      advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                      advertising_data=[]))

        # 11. Configure Lower Tester to use a public device address that differs from the IUT address in the
        # least significant octet as parameter of CONNECT_IND.

        # 12. Repeat steps 4–8.

        # 13. Configure Lower Tester to use a public device address that differs from the IUT address in the
        # most and least significant octets as parameter of CONNECT_IND.

        # 14. Repeat steps 4–8.

        # 15. Configure Lower Tester to monitor the advertising and connection procedures of the IUT and
        # send a CONNECT_IND packet on the second supported advertising channel.

        # 16. Repeat steps 3–14.

        # 17. Configure Lower Tester to monitor the advertising and connection procedures of the IUT and
        # send a CONNECT_IND packet on the third supported advertising channel.

        # 18. Repeat steps 3–14.
