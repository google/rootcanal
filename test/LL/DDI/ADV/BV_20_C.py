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

    # LL/DDI/ADV/BV-20-C [Advertising Always Using the LE 1M PHY]
    async def test(self):
        controller = self.controller
        public_peer_address = Address('aa:bb:cc:dd:ee:ff')
        connection_handle = 0xefe

        # 1. Configure Lower Tester to monitor advertising packets from the IUT. Lower Tester will only
        # accept advertising packets sent using the LE 1M PHY setting. Lower Tester will scan for at least
        # 30 advertising intervals on each advertising channel (for example, scan on channel 37 for the first
        # 30 intervals, then on channel 38 for another 30 intervals, then finally on channel 39 for the last 30
        # intervals).
        # 2. Upper Tester sends a LE_Set_Default_PHY command to the IUT, with the ALL_PHYS field set to
        # zero, and the TX_PHYS and RX_PHYS fields both set to prefer the LE 2M PHY.
        controller.send_cmd(
            hci.LeSetDefaultPhy(all_phys_no_transmit_preference=False,
                                all_phys_no_receive_preference=False,
                                tx_phys_bitmask=0x2,
                                rx_phys_bitmask=0x2))

        await self.expect_evt(hci.LeSetDefaultPhyComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. Upper Tester enables undirected advertising in the IUT using all supported advertising channels
        # and minimum advertising interval.
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

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. Lower Tester expects the IUT to send ADV_IND packets starting an event on an applicable
        # advertising channel using the LE 1M PHY.
        # 5. Repeat step 4 until at least 90 advertising packets have been detected, i.e., at least 30 packets
        # on each channel.
        for n in range(3):
            await self.expect_ll(
                ll.LeLegacyAdvertisingPdu(source_address=controller.address,
                                          advertising_address_type=ll.AddressType.PUBLIC,
                                          advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                          advertising_data=[]))

        # 6. Upper Tester sends an HCI_LE_Set_Advertising_Enable command to disable advertising in the
        # IUT and receives an HCI_Command_Complete event from the IUT.
        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=False))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
