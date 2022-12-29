import lib_rootcanal_python3 as rootcanal
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

    # LL/DDI/ADV/BV-19-C [Low Duty Cycle Directed Advertising Events]
    async def test(self):
        controller = self.controller
        public_peer_address = Address('aa:bb:cc:dd:ee:ff')
        connection_handle = 0xefe

        # 1. Configure Lower Tester to start scanning and monitor advertising packets from the IUT.
        # 2. Upper Tester enables low duty cycle directed advertising in the IUT using a selected advertising
        # channel and a selected advertising interval between the minimum and maximum advertising.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(
                advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                advertising_type=hci.AdvertisingType.ADV_DIRECT_IND_LOW,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                peer_address=public_peer_address,
                peer_address_type=hci.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN_AND_CONNECT))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Lower Tester expects the IUT to send ADV_DIRECT_IND packets starting an event on the
        # selected advertising channel.
        # 4. Expect the next event to start after the advertising interval time calculated from the start of the
        # first packet.
        # 5. Repeat steps 3–4 until the number of advertising intervals (100) have been detected.
        for n in range(3):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          destination_address=public_peer_address,
                                          target_address_type=ll.AddressType.PUBLIC,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_DIRECT_IND,
                                          advertising_data=[]))

        # 6. Configure the Lower Tester to initiate a connection.
        # 7. Lower Tester receives an ADV_DIRECT_IND packet from the IUT on the selected advertising
        # channel (defined as an IXIT), then responds with a CONNECT_IND packet T_IFS after the end of
        # the advertising packet and does not send any data packets to the IUT.
        await self.expect_ll(
            ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                      destination_address=public_peer_address,
                                      target_address_type=ll.AddressType.PUBLIC,
                                      advertising_address_type=ll.AddressType.PUBLIC,
                                      advertising_type=ll.LegacyAdvertisingType.ADV_DIRECT_IND,
                                      advertising_data=[]))

        controller.send_ll(ll.LeConnect(source_address=public_peer_address,
                                        destination_address=controller.address,
                                        advertising_address_type=ll.AddressType.PUBLIC,
                                        initiating_address_type=ll.AddressType.PUBLIC,
                                        conn_interval=self.LL_initiator_connInterval,
                                        conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                        conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout),
                           rssi=-16)

        # Note: Link layer sends LeConnectComplete here.
        await self.expect_ll(
            ll.LeConnectComplete(source_address=controller.address,
                                 destination_address=public_peer_address,
                                 initiating_address_type=ll.AddressType.PUBLIC,
                                 advertising_address_type=ll.AddressType.PUBLIC,
                                 conn_interval=self.LL_initiator_connInterval,
                                 conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                 conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout))

        # 8. Lower Tester receives no ADV_DIRECT_IND packets from the IUT after the advertising interval.
        # 9. Repeat steps 7–8 until the IUT stops advertising.

        # 10. Upper Tester receives an HCI_LE_Connection_Complete event from the IUT including the
        # parameters sent to the IUT in step 7.
        await self.expect_evt(
            hci.LeEnhancedConnectionComplete(status=ErrorCode.SUCCESS,
                                             connection_handle=connection_handle,
                                             role=hci.Role.PERIPHERAL,
                                             peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                             peer_address=public_peer_address,
                                             conn_interval=self.LL_initiator_connInterval,
                                             conn_latency=self.LL_initiator_connPeripheralLatency,
                                             supervision_timeout=self.LL_initiator_connSupervisionTimeout,
                                             central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        # 11. Upper Tester receives an HCI_Disconnection_Complete event from the IUT once the
        # Establishment Timeout has expired.
        controller.send_ll(
            ll.Disconnect(source_address=public_peer_address,
                          destination_address=controller.address,
                          reason=int(hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION)))

        await self.expect_evt(
            hci.DisconnectionComplete(status=ErrorCode.SUCCESS,
                                      connection_handle=connection_handle,
                                      reason=hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION))
