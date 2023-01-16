import lib_rootcanal_python3 as rootcanal
import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    # LL/DDI/ADV/BV-07-C [Scan Request Connection Request]
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
        connection_handle = 0xefe

        # 1. Upper Tester enables undirected advertising in the IUT using all supported advertising channels,
        # a selected advertising interval between the minimum and maximum advertising intervals, and
        # filtering policy set to ‘Allow Scan Request from Any, Allow Connect Request from Any (Default)
        # (0x00)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. Upper Tester sends an HCI_LE_Set_Scan_Response_Data command with data set to “IUT” and
        # receives an HCI_Command_Complete event from the IUT.
        scan_response_data = [ord('I'), ord('U'), ord('T')]
        controller.send_cmd(hci.LeSetScanResponseDataRaw(advertising_data=scan_response_data))

        await self.expect_evt(hci.LeSetScanResponseDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Configure Lower Tester to monitor the advertising, scan response and connection procedures of
        # the IUT, sending a SCAN_REQ and a CONNECT_IND packet on a supported advertising
        # channel (defined as an IXIT).

        # 4. Lower Tester receives an ADV_IND packet from the IUT on the selected advertising channel and
        # responds with an SCAN_REQ packet on the selected advertising channel T_IFS after the end of
        # an advertising packet.
        # 5. Lower Tester receives an SCAN_RSP packet from the IUT addressed to the Lower Tester T_IFS
        # after the end of the request packet.
        # 6. Repeat steps 4–5 30 times or until IUT sends SCAN_RSP.
        for n in range(10):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeScan(source_address=peer_address,
                                         destination_address=controller.address,
                                         advertising_address_type=ll.AddressType.PUBLIC,
                                         scanning_address_type=ll.AddressType.PUBLIC),
                               rssi=-16)

            await self.expect_ll(
                ll.LeScanResponse(source_address=controller.address,
                                  destination_address=peer_address,
                                  advertising_address_type=ll.AddressType.PUBLIC,
                                  scan_response_data=scan_response_data))

        # 7. Lower Tester receives an ADV_IND packet from the IUT on the selected advertising channel and
        # responds with a CONNECT_IND packet T_IFS after the end of the advertising packet.
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

        # 8. The Lower Tester receives no ADV_IND packet after advertising interval from the IUT after
        # sending the connection request to indicate that the IUT has stopped advertising.
        # Note: Link layer sends LeConnectComplete here.
        await self.expect_ll(
            ll.LeConnectComplete(source_address=controller.address,
                                 destination_address=peer_address,
                                 conn_interval=LL_initiator_connInterval,
                                 conn_peripheral_latency=LL_initiator_connPeripheralLatency,
                                 conn_supervision_timeout=LL_initiator_connSupervisionTimeout))

        # 9. Upper Tester receives an HCI_LE_Connection_Complete event from the IUT including the
        # parameters sent to the IUT.
        await self.expect_evt(
            hci.LeEnhancedConnectionComplete(status=ErrorCode.SUCCESS,
                                             connection_handle=connection_handle,
                                             role=hci.Role.PERIPHERAL,
                                             peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                             peer_address=peer_address,
                                             conn_interval=LL_initiator_connInterval,
                                             conn_latency=LL_initiator_connPeripheralLatency,
                                             supervision_timeout=LL_initiator_connSupervisionTimeout,
                                             central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        # 10. Peripheral Connection Terminated (connection interval, Peripheral latency, timeout, channel map,
        # un-encrypted, connection handle from step 9).
