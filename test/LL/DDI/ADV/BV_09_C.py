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

    # LL/DDI/ADV/BV-09-C [Connection Request Device Filtering]
    async def test(self):
        controller = self.controller
        public_peer_address = Address('aa:bb:cc:dd:ee:ff')
        random_peer_address = Address('00:bb:cc:dd:ee:ff')
        invalid_peer_address = Address('aa:bb:cc:dd:ee:00')

        # Test preparation.
        controller.send_cmd(
            hci.LeAddDeviceToFilterAcceptList(address=public_peer_address,
                                              address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS))

        await self.expect_evt(
            hci.LeAddDeviceToFilterAcceptListComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(
            hci.LeAddDeviceToFilterAcceptList(address=random_peer_address,
                                              address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS))

        await self.expect_evt(
            hci.LeAddDeviceToFilterAcceptListComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 1. Upper Tester enables undirected advertising in the IUT, all supported advertising channels and
        # filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow Connect Request from
        # Filter Accept List (0x03)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(
                advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                advertising_type=hci.AdvertisingType.ADV_IND,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN_AND_CONNECT))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. Upper Tester sends an HCI_LE_Set_Scan_Response_Data command with data set to “IUT” and
        # receives an HCI_Command_Complete event from the IUT.
        scan_response_data = [ord('I'), ord('U'), ord('T')]
        controller.send_cmd(hci.LeSetScanResponseDataRaw(advertising_data=scan_response_data))

        await self.expect_evt(hci.LeSetScanResponseDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Lower Tester address type is set to Public Address type.
        await self.steps_4_14(peer_address=public_peer_address,
                              peer_address_type=ll.AddressType.PUBLIC,
                              connection_handle=0xefe)

        # 15. Upper Tester enables undirected advertising in the IUT using public address type, all supported
        # advertising channels and filtering policy set to ‘Allow Scan Request from Filter Accept List, Allow
        # Connect Request from Filter Accept List (0x03)’.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 16. Lower Tester address type is set to Random Address type.
        # 17. Repeat steps 4–14.
        await self.steps_4_14(peer_address=random_peer_address,
                              peer_address_type=ll.AddressType.RANDOM,
                              connection_handle=0xeff)

        # 18. Upper Tester enables undirected advertising in the IUT using public address type, all supported
        # advertising channels and filtering policy set to ‘Allow Scan Request from Any, Allow Connect
        # Request from Filter Accept List (0x02)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_CONNECT))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 19. Lower Tester address type is set to Public Address type.
        # 20. Repeat steps 4–14.
        await self.steps_4_14(peer_address=public_peer_address,
                              peer_address_type=ll.AddressType.PUBLIC,
                              connection_handle=0x000)

        # 21. Upper Tester enables undirected advertising in the IUT using public address type, all supported
        # advertising channels and filtering policy set to ‘Allow Scan Request from Any, Allow Connect
        # Request from Filter Accept List (0x02)’.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 22. Lower Tester address type is set to Random Address type.
        # 23. Repeat steps 4–14.
        await self.steps_4_14(peer_address=random_peer_address,
                              peer_address_type=ll.AddressType.RANDOM,
                              connection_handle=0x001)

        # 24. Upper Tester enables undirected advertising in the IUT using all supported advertising channels,
        # minimum advertising interval and filtering policy set to ‘Allow Scan Request from Any, Allow
        # Connect Request from Any (Default) (0x00)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.steps_24_29(peer_address=public_peer_address,
                               peer_address_type=ll.AddressType.PUBLIC,
                               connection_handle=0x002)

        # 30. Repeat steps 24–29, except that in step 25, configure Lower Tester to use a device address not
        # on the IUT’s Filter Accept List as the address parameter of the CONNECT_IND PDU; the address
        # shall be formed by using the same address type as the entry on the IUT's Filter Accept List but
        # changing the most significant octet of the address to ensure a mis-match.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.steps_24_29(peer_address=invalid_peer_address,
                               peer_address_type=ll.AddressType.PUBLIC,
                               connection_handle=0x003)

        # 31. Repeat steps 24–29, except that in step 25, configure Lower Tester to use a device address not
        # on the IUT’s Filter Accept List as the address parameter of the CONNECT_IND PDU; the address
        # shall be formed by using the same address type as the entry on the IUT's Filter Accept List,
        # changing the least significant octet of the address to ensure a mis-match.
        # Note: skipping as redundant

        # 32. Repeat steps 24–29, except that in step 25, configure Lower Tester to use a device address not
        # on the IUT’s Filter Accept List as the address parameter of the CONNECT_IND PDU; the address
        # shall be formed by using the same address type as the entry on the IUT's Filter Accept List but
        # changing both the most and least significant octets of the address to ensure a mis-match.
        # Note: skipping as redundant

        # 33. Repeat steps 24–32, except that in step 25, configure Lower Tester to monitor the advertising
        # and connection procedures of the IUT and send a CONNECT_IND packet on the second
        # supported advertising channel in response to connectable advertisements.
        # Note: skipping as redundant

        # 34. Repeat steps 24–32, except that in step 25, configure Lower Tester to monitor the advertising
        # and connection procedures of the IUT and send a CONNECT_IND packet on the third supported
        # advertising channel in response to connectable advertisements.
        # Note: skipping as redundant

        # 35. Upper Tester enables undirected advertising in the IUT using all supported advertising channels,
        # minimum advertising intervals and filtering policy set to ‘Allow Scan Request from Filter Accept
        # List, Allow Connect Request from Any (0x01)’.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                                           advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                                           advertising_type=hci.AdvertisingType.ADV_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.LISTED_SCAN))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 36. Repeat steps 25–29.
        await self.steps_24_29(peer_address=public_peer_address,
                               peer_address_type=ll.AddressType.PUBLIC,
                               connection_handle=0x004)

    # Subroutine for steps 4-14.
    async def steps_4_14(self, peer_address: Address, peer_address_type: ll.AddressType, connection_handle: int):
        # 4. Configure Lower Tester to monitor the advertising and connection procedures of the IUT and
        # send a CONNECT_IND packet on the selected supported advertising channel (defined as an
        # IXIT) in response to connectable advertisements. The initiator’s address in the CONNECT_IND
        # PDU shall be formed by using the same address type as the entry on the IUT's Filter Accept List
        # but changing the most significant octet of the address to ensure a mis-match.
        # 5. Lower Tester receives an ADV_IND packet from the IUT and responds with a CONNECT_IND
        # packet with the selected address on the selected advertising channel T_IFS after the end of an
        # advertising packet.
        # 6. Lower Tester expects the IUT to continue advertising.
        # 7. Repeat steps 5–6 30 times.
        controller = self.controller
        invalid_peer_address = Address([
            peer_address.address[0] ^ 0xff, peer_address.address[1], peer_address.address[2], peer_address.address[3],
            peer_address.address[4], peer_address.address[5]
        ])

        for n in range(3):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeConnect(source_address=invalid_peer_address,
                                            destination_address=controller.address,
                                            advertising_address_type=ll.AddressType.PUBLIC,
                                            initiating_address_type=peer_address_type,
                                            conn_interval=self.LL_initiator_connInterval,
                                            conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                            conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout),
                               rssi=-16)

        # 8. Configure Lower Tester to use a device address on the IUT’s Filter Accept List but an incorrect
        # address type as the address parameter of the CONNECT_IND PDU.
        # 9. Repeat steps 5–6 30 times.
        invalid_peer_address_type = (ll.AddressType.RANDOM
                                     if peer_address_type == ll.AddressType.PUBLIC else ll.AddressType.PUBLIC)

        for n in range(3):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

            controller.send_ll(ll.LeConnect(source_address=peer_address,
                                            destination_address=controller.address,
                                            advertising_address_type=ll.AddressType.PUBLIC,
                                            initiating_address_type=invalid_peer_address_type,
                                            conn_interval=self.LL_initiator_connInterval,
                                            conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                            conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout),
                               rssi=-16)

        # 10. Configure Lower Tester to use a device address on the IUT’s Filter Accept List and correct
        # address type as the address parameter of the CONNECT_IND PDU.
        # 11. Lower Tester receives an ADV_IND packet from the IUT and responds with a CONNECT_IND
        # packet with the selected address in the Filter Accept List in the policy applied, on the selected
        # advertising channel T_IFS after the end of an advertising packet.
        # 12. The Lower Tester receives no ADV_IND packet after advertising interval from the IUT after
        # sending the connection request to indicate that the IUT has stopped advertising. Wait for a time
        # equal to 4 advertising intervals to check that no ADV_IND is received.
        await self.expect_ll(
            ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                      advertising_address_type=ll.AddressType.PUBLIC,
                                      advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                      advertising_data=[]))

        controller.send_ll(ll.LeConnect(source_address=peer_address,
                                        destination_address=controller.address,
                                        advertising_address_type=ll.AddressType.PUBLIC,
                                        initiating_address_type=peer_address_type,
                                        conn_interval=self.LL_initiator_connInterval,
                                        conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                        conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout),
                           rssi=-16)

        # Note: Link layer sends LeConnectComplete here.
        await self.expect_ll(
            ll.LeConnectComplete(source_address=controller.address,
                                 destination_address=peer_address,
                                 initiating_address_type=peer_address_type,
                                 advertising_address_type=ll.AddressType.PUBLIC,
                                 conn_interval=self.LL_initiator_connInterval,
                                 conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                 conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout))

        # 13. Upper Tester receives an HCI_LE_Connection_Complete event from the IUT including the
        # parameters sent to the IUT.
        await self.expect_evt(
            hci.LeEnhancedConnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=connection_handle,
                role=hci.Role.PERIPHERAL,
                peer_address_type=(hci.AddressType.PUBLIC_DEVICE_ADDRESS if peer_address_type == ll.AddressType.PUBLIC
                                   else hci.AddressType.RANDOM_DEVICE_ADDRESS),
                peer_address=peer_address,
                conn_interval=self.LL_initiator_connInterval,
                conn_latency=self.LL_initiator_connPeripheralLatency,
                supervision_timeout=self.LL_initiator_connSupervisionTimeout,
                central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        # 14. Peripheral Connection Terminated (connection interval, Peripheral latency, timeout, channel map,
        # un-encrypted, connection handle).
        controller.send_ll(
            ll.Disconnect(source_address=peer_address,
                          destination_address=controller.address,
                          reason=int(hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION)))

        await self.expect_evt(
            hci.DisconnectionComplete(status=ErrorCode.SUCCESS,
                                      connection_handle=connection_handle,
                                      reason=hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION))

    # Subroutine for steps 24-29.
    async def steps_24_29(self, peer_address: Address, peer_address_type: ll.AddressType, connection_handle: int):
        # 25. Configure Lower Tester to monitor the advertising and connection procedures of the IUT and
        # send a CONNECT_IND packet on the first supported advertising channel in response to
        # connectable advertisements. The initiator’s address in the CONNECT_IND PDU shall be an
        # address on the IUT's Filter Accept List.
        # 26. Lower Tester receives an ADV_IND packet from the IUT and responds with a CONNECT_IND
        # packet T_IFS after the end of the advertising packet.
        # 27. The Lower Tester verifies that the IUT has started to maintain a connection by responding with
        # correctly formatted LL Data Channel PDUs to the Lower Tester’s corrected formatted LL Data
        # Packets on the data channels. If no data packets are received, repeat steps 26 and 27 up to 20
        # times or until the IUT stops advertising.
        # 28. The Lower Tester receives no ADV_IND packet after advertising interval from the IUT after
        # sending the connection request. Wait for a time equal to 4 advertising intervals to check that no
        # ADV_IND is received.
        controller = self.controller

        await self.expect_ll(
            ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                      advertising_address_type=ll.AddressType.PUBLIC,
                                      advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                      advertising_data=[]))

        controller.send_ll(ll.LeConnect(source_address=peer_address,
                                        destination_address=controller.address,
                                        advertising_address_type=ll.AddressType.PUBLIC,
                                        initiating_address_type=peer_address_type,
                                        conn_interval=self.LL_initiator_connInterval,
                                        conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                        conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout),
                           rssi=-16)

        # Note: Link layer sends LeConnectComplete here.
        await self.expect_ll(
            ll.LeConnectComplete(source_address=controller.address,
                                 destination_address=peer_address,
                                 initiating_address_type=peer_address_type,
                                 advertising_address_type=ll.AddressType.PUBLIC,
                                 conn_interval=self.LL_initiator_connInterval,
                                 conn_peripheral_latency=self.LL_initiator_connPeripheralLatency,
                                 conn_supervision_timeout=self.LL_initiator_connSupervisionTimeout))

        # 29. Upper Tester receives an HCI_LE_Connection_Complete event from the IUT including the
        # parameters sent to the IUT in step 25 and as postamble: Peripheral Connection Terminated
        # (connection interval, Peripheral latency, timeout, channel map, un-encrypted, connection handle).
        await self.expect_evt(
            hci.LeEnhancedConnectionComplete(
                status=ErrorCode.SUCCESS,
                connection_handle=connection_handle,
                role=hci.Role.PERIPHERAL,
                peer_address_type=(hci.AddressType.PUBLIC_DEVICE_ADDRESS if peer_address_type == ll.AddressType.PUBLIC
                                   else hci.AddressType.RANDOM_DEVICE_ADDRESS),
                peer_address=peer_address,
                conn_interval=self.LL_initiator_connInterval,
                conn_latency=self.LL_initiator_connPeripheralLatency,
                supervision_timeout=self.LL_initiator_connSupervisionTimeout,
                central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        controller.send_ll(
            ll.Disconnect(source_address=peer_address,
                          destination_address=controller.address,
                          reason=int(hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION)))

        await self.expect_evt(
            hci.DisconnectionComplete(status=ErrorCode.SUCCESS,
                                      connection_handle=connection_handle,
                                      reason=hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION))
