import asyncio
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
    LL_initiator_connInterval = 0x200
    LL_initiator_connPeripheralLatency = 0x200
    LL_initiator_connSupervisionTimeout = 0x200

    # LL/DDI/ADV/BV-11-C [Directed Advertising Events]
    async def test(self):
        controller = self.controller
        peer_address = Address('aa:bb:cc:dd:ee:ff')
        connection_handle = 0xefe

        # 1. Configure Lower Tester to start passive scanning.
        # 2. Upper Tester enables high duty cycle directed advertising in the IUT using all supported
        # advertising channels.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(
                advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                advertising_type=hci.AdvertisingType.ADV_DIRECT_IND_HIGH,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                peer_address=peer_address,
                peer_address_type=hci.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN_AND_CONNECT))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Lower Tester expects the IUT to send ADV_DIRECT_IND packets: A packet starting an event on
        # an applicable advertising channel with the lowest advertising channel index, then optionally
        # following packets on applicable advertising channels with increasing advertising channel indexes.
        # Expect the intervals between starts of packet on any single channel to be equal to or below
        # 3.75 ms.
        # 4. Repeat until the IUT stops advertising and verify that it stops after 1.28s. For each advertising
        # channel, verify that at least 30 of the intervals between starts of packets on that channel are
        # equal to or below 3.75 ms.
        try:
            end_time = asyncio.get_running_loop().time() + 5
            while asyncio.get_running_loop().time() < end_time:
                await self.expect_ll(
                    ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                              destination_address=peer_address,
                                              advertising_address_type=ll.AddressType.PUBLIC,
                                              target_address_type=ll.AddressType.PUBLIC,
                                              advertising_type=ll.LegacyAdvertisingType.ADV_DIRECT_IND,
                                              advertising_data=[]))
            # Note: The test should timeout waiting for a directed advertising event
            # past the direct advertising timeout.
            self.assertTrue(False)
        except asyncio.exceptions.TimeoutError:
            print('stopped advertising OK')

        # 5. Upper Tester receives an HCI_LE_Connection_Complete event from the IUT with status
        # parameter set to ‘directed advertising timeout’.
        # Note: The correct event to receive is LE Enhanced Connection Complete,
        # but the PTS tool expects LE Connection Complete for the test GAP/DISC/GENP/BV-05-C.
        await self.expect_evt(hci.LeConnectionComplete(status=ErrorCode.ADVERTISING_TIMEOUT))

        # 6. Configure Lower Tester to initiate a connection.
        # 7. Upper Tester enables directed advertising in the IUT using all supported advertising channels.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 8. Lower Tester receives an ADV_DIRECT_IND packet from the IUT on the selected advertising
        # channel (defined as an IXIT), then responds with a CONNECT_IND packet T_IFS after the end of
        # the advertising packet and does not send any data packets to the IUT.
        # 9. Lower Tester receives no ADV_DIRECT_IND packets from the IUT after the advertising interval.
        # 10. Repeat steps 8–9 until the IUT stops advertising.
        await self.expect_ll(
            ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                      destination_address=peer_address,
                                      advertising_address_type=ll.AddressType.PUBLIC,
                                      target_address_type=ll.AddressType.PUBLIC,
                                      advertising_type=ll.LegacyAdvertisingType.ADV_DIRECT_IND,
                                      advertising_data=[]))

        controller.send_ll(ll.LeConnect(source_address=peer_address,
                                        destination_address=controller.address,
                                        advertising_address_type=ll.AddressType.PUBLIC,
                                        initiating_address_type=ll.AddressType.PUBLIC,
                                        conn_interval=self.LL_initiator_connInterval,
                                        conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                        conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout),
                           rssi=-16)

        # Note: another advertising pdu is received waiting from the connect
        # complete.
        await self.expect_ll(ll.LeLegacyAdvertisingPdu)

        # Note: Link layer sends LeConnectComplete here.
        await self.expect_ll(
            ll.LeConnectComplete(source_address=controller.address,
                                 destination_address=peer_address,
                                 initiating_address_type=ll.AddressType.PUBLIC,
                                 advertising_address_type=ll.AddressType.PUBLIC,
                                 conn_interval=self.LL_initiator_connInterval,
                                 conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                 conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout))

        # 11. Upper Tester receives an HCI_LE_Connection_Complete event from the IUT including the
        # parameters sent to the IUT in step 8.
        await self.expect_evt(
            hci.LeEnhancedConnectionComplete(status=ErrorCode.SUCCESS,
                                             connection_handle=connection_handle,
                                             role=hci.Role.PERIPHERAL,
                                             peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                             peer_address=peer_address,
                                             conn_interval=self.LL_initiator_connInterval,
                                             conn_latency=self.LL_initiator_connPeripheralLatency,
                                             supervision_timeout=self.LL_initiator_connSupervisionTimeout,
                                             central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        # 12. Upper Tester receives an HCI_LE_Disconnection_Complete event from the IUT with the reason
        # parameter indicating ‘connection failed to be established’, with the connection handle parameter
        # matching to step 8.
        controller.send_ll(
            ll.Disconnect(source_address=peer_address,
                          destination_address=controller.address,
                          reason=int(hci.ErrorCode.CONNECTION_FAILED_ESTABLISHMENT)))

        await self.expect_evt(
            hci.DisconnectionComplete(status=ErrorCode.SUCCESS,
                                      connection_handle=connection_handle,
                                      reason=hci.ErrorCode.CONNECTION_FAILED_ESTABLISHMENT))
