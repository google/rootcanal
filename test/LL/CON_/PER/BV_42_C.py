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

from dataclasses import dataclass
import hci_packets as hci
import link_layer_packets as ll
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest
from typing import List


@dataclass
class TestRound:
    req_tx_phys: int
    req_rx_phys: int
    phy_ltpref_c_to_p: List[int]
    phy_ltpref_p_to_c: List[int]


class Test(ControllerTest):

    # LL/CON/PER/BV-40-C [Initiating PHY Update Procedure]
    async def test(self):
        # Test parameters.
        controller = self.controller
        acl_connection_handle = 0xefe
        peer_address = Address('11:22:33:44:55:66')

        # Prelude: Establish an ACL connection as central with the IUT.
        controller.send_cmd(
            hci.LeSetAdvertisingParameters(advertising_interval_min=0x200,
                                           advertising_interval_max=0x200,
                                           advertising_type=hci.AdvertisingType.ADV_IND,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           advertising_channel_map=0x7,
                                           advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES))

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(hci.LeSetAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_ll(ll.LeConnect(source_address=peer_address,
                                        destination_address=controller.address,
                                        initiating_address_type=ll.AddressType.PUBLIC,
                                        advertising_address_type=ll.AddressType.PUBLIC,
                                        conn_interval=0x200,
                                        conn_peripheral_latency=0x200,
                                        conn_supervision_timeout=0x200),
                           rssi=-16)

        await self.expect_ll(
            ll.LeConnectComplete(source_address=controller.address,
                                 destination_address=peer_address,
                                 conn_interval=0x200,
                                 conn_peripheral_latency=0x200,
                                 conn_supervision_timeout=0x200))

        await self.expect_evt(
            hci.LeEnhancedConnectionComplete(status=ErrorCode.SUCCESS,
                                             connection_handle=acl_connection_handle,
                                             role=hci.Role.PERIPHERAL,
                                             peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                             peer_address=peer_address,
                                             connection_interval=0x200,
                                             peripheral_latency=0x200,
                                             supervision_timeout=0x200,
                                             central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        # 1. Upper Tester sends an HCI_LE_Set_PHY command to the IUT with the ALL_PHYS fields set to a
        # value of 0x03. Upper Tester receives an HCI_Command_Status event indicating success in
        # response.
        controller.send_cmd(
            hci.LeSetPhy(connection_handle=acl_connection_handle,
                         all_phys_no_transmit_preference=True,
                         all_phys_no_receive_preference=True,
                         tx_phys=0,
                         rx_phys=0))

        await self.expect_evt(hci.LeSetPhyStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        await self.expect_ll(
            ll.LlPhyReq(source_address=controller.address, destination_address=peer_address, tx_phys=0x7, rx_phys=0x7))

        controller.send_ll(
            ll.LlPhyUpdateInd(source_address=peer_address,
                              destination_address=controller.address,
                              phy_c_to_p=0x2,
                              phy_p_to_c=0x2))

        # 2. The Upper Tester receives an HCI_LE_PHY_Update_Complete event from the IUT.
        await self.expect_evt(
            hci.LePhyUpdateComplete(status=ErrorCode.SUCCESS,
                                    connection_handle=acl_connection_handle,
                                    tx_phy=hci.PhyType.LE_2M,
                                    rx_phy=hci.PhyType.LE_2M))

        test_rounds = [
            TestRound(0x03, 0x01, [0x02], [0x01]),
            TestRound(0x05, 0x02, [0x01], [0x02]),
            TestRound(0x02, 0x04, [0x02], [0x04]),
            TestRound(0x01, 0x02, [0x01], [0x02]),
            TestRound(0x04, 0x01, [0x04], [0x01]),
            TestRound(0x03, 0x06, [0x02], [0x02]),
            TestRound(0x01, 0x01, [0x01], [0x01]),
            TestRound(0x04, 0x03, [0x04], [0x01]),
            TestRound(0x05, 0x01, [0x01], [0x01]),
            TestRound(0x04, 0x04, [0x04], [0x04]),
            TestRound(0x05, 0x07, [0x04], [0x02, 0x04]),
            TestRound(0x05, 0x05, [0x04], [0x01]),
            TestRound(0x04, 0x02, [0x04], [0x02]),
            TestRound(0x03, 0x07, [0x01], [0x04, 0x01]),
            TestRound(0x06, 0x06, [0x02], [0x04]),
            TestRound(0x03, 0x02, [0x02], [0x02]),
            TestRound(0x01, 0x06, [0x01], [0x04]),
            TestRound(0x05, 0x06, [0x01], [0x04]),
            TestRound(0x04, 0x05, [0x04], [0x01]),
            TestRound(0x01, 0x05, [0x01], [0x04]),
            TestRound(0x05, 0x03, [0x01], [0x02]),
            TestRound(0x01, 0x04, [0x01], [0x04]),
            TestRound(0x01, 0x03, [0x01], [0x02]),
            TestRound(0x03, 0x05, [0x02], [0x01]),
            TestRound(0x06, 0x04, [0x02], [0x04]),
            TestRound(0x02, 0x07, [0x02], [0x01, 0x02]),
            TestRound(0x06, 0x01, [0x02], [0x01]),
            TestRound(0x02, 0x02, [0x02], [0x02]),
            TestRound(0x03, 0x04, [0x01], [0x04]),
            TestRound(0x07, 0x03, [0x04, 0x01], [0x01]),
            TestRound(0x02, 0x01, [0x02], [0x01]),
            TestRound(0x03, 0x03, [0x01], [0x01]),
            TestRound(0x02, 0x03, [0x02], [0x01]),
            TestRound(0x04, 0x07, [0x04], [0x02, 0x04]),
            TestRound(0x07, 0x04, [0x01, 0x04], [0x04]),
            TestRound(0x07, 0x01, [0x04, 0x02], [0x01]),
            TestRound(0x06, 0x05, [0x04], [0x01]),
            TestRound(0x02, 0x06, [0x02], [0x04]),
            TestRound(0x07, 0x07, [0x01, 0x02], [0x01, 0x04]),
            TestRound(0x04, 0x06, [0x04], [0x02]),
            TestRound(0x02, 0x05, [0x02], [0x01]),
            TestRound(0x06, 0x02, [0x04], [0x02]),
            TestRound(0x07, 0x02, [0x01, 0x02], [0x02]),
            TestRound(0x07, 0x06, [0x04, 0x01], [0x04]),
            TestRound(0x06, 0x07, [0x02], [0x02, 0x01]),
            TestRound(0x06, 0x03, [0x02], [0x02]),
            TestRound(0x05, 0x04, [0x04], [0x04]),
            TestRound(0x07, 0x05, [0x04, 0x02], [0x01]),
            TestRound(0x01, 0x07, [0x01], [0x04, 0x02]),
        ]

        # 3. Perform steps 4 through 11 2N times as follows, where N is the number of cases in Table 4.67,
        # Table 4.68, or Table 4.69 (selected based on the supported PHY(s)):
        # ▪ firstly using cases 1 to N from the relevant table in order;
        # ▪ then using the cases from the relevant table in a random order.
        phy_c_to_p = 0x2
        phy_p_to_c = 0x2
        for test_round in test_rounds:
            (phy_c_to_p, phy_p_to_c) = await self.steps_4_11(peer_address, acl_connection_handle, phy_c_to_p,
                                                             phy_p_to_c, **vars(test_round))

    async def steps_4_11(self, peer_address: Address, connection_handle: int, phy_c_to_p: int, phy_p_to_c: int,
                         req_tx_phys: int, req_rx_phys: int, phy_ltpref_c_to_p: List[int],
                         phy_ltpref_p_to_c: List[int]):
        controller = self.controller

        def phy_from_mask(mask: int):
            if mask & 0x4:
                return hci.PhyType.LE_CODED
            elif mask & 0x2:
                return hci.PhyType.LE_2M
            else:
                return hci.PhyType.LE_1M

        # 4. Lower Tester sends an LL_PHY_REQ PDU to the IUT to initiate a PHY change with the payload
        # defined in the LL_PHY_REQ section of the relevant table.
        controller.send_ll(
            ll.LlPhyReq(source_address=peer_address,
                        destination_address=controller.address,
                        tx_phys=req_tx_phys,
                        rx_phys=req_rx_phys))

        # 5. Lower Tester receives an LL_PHY_RSP control PDU from the IUT with at least one bit set in
        # each field (TX_PHYS, RX_PHYS).
        phy_rsp = await self.expect_ll(
            ll.LlPhyRsp(source_address=controller.address,
                        destination_address=peer_address,
                        tx_phys=self.Any,
                        rx_phys=self.Any))

        self.assertTrue(phy_rsp.tx_phys != 0)
        self.assertTrue(phy_rsp.rx_phys != 0)

        # 6. Lower Tester responds with an LL_PHY_UPDATE_IND PDU.
        next_phy_c_to_p = req_tx_phys & phy_rsp.rx_phys
        next_phy_p_to_c = req_rx_phys & phy_rsp.tx_phys

        if next_phy_c_to_p.bit_count() > 1:
            for phy in phy_ltpref_c_to_p:
                if (next_phy_c_to_p & phy) != 0:
                    next_phy_c_to_p = phy
                    break

        if next_phy_p_to_c.bit_count() > 1:
            for phy in phy_ltpref_p_to_c:
                if (next_phy_p_to_c & phy) != 0:
                    next_phy_p_to_c = phy
                    break

        next_phy_c_to_p = next_phy_c_to_p or phy_c_to_p
        next_phy_p_to_c = next_phy_p_to_c or phy_p_to_c

        controller.send_ll(
            ll.LlPhyUpdateInd(source_address=peer_address,
                              destination_address=controller.address,
                              phy_c_to_p=(0 if next_phy_c_to_p == phy_c_to_p else next_phy_c_to_p),
                              phy_p_to_c=(0 if next_phy_p_to_c == phy_p_to_c else next_phy_p_to_c)))

        # 7. Lower Tester receives a packet from the IUT acknowledging the LL_PHY_UPDATE_IND.
        # If both the PHY_C_TO_P and PHY_P_TO_C fields of the LL_PHY_UPDATE_IND are zero, skip
        # to step 11.

        # 8. Lower Tester sends empty DATA packets to the IUT, receiving acknowledgements until the event
        # count matches the indicated Instant of the PHY change.

        # 9. At the Instant of the PHY change the IUT starts maintaining the connection with the new PHY(s)
        # selected by the Lower Tester.

        # 10. Lower Tester sends empty DATA packets to the IUT, receiving acknowledgements. If the PHY(s)
        # have changed, the Lower Tester shall use the new PHY(s).

        # 11. If the PHY(s) were changed, Upper Tester receives a LE_PHY_Update_Complete event from the
        # IUT containing the PHYs selected. If both PHYs were NOT changed, Upper Tester does NOT
        # receive a LE_PHY_Update_Complete event
        if next_phy_c_to_p != phy_c_to_p or next_phy_p_to_c != phy_p_to_c:
            await self.expect_evt(
                hci.LePhyUpdateComplete(connection_handle=connection_handle,
                                        status=ErrorCode.SUCCESS,
                                        tx_phy=phy_from_mask(next_phy_p_to_c),
                                        rx_phy=phy_from_mask(next_phy_c_to_p)))

        return (next_phy_c_to_p, next_phy_p_to_c)
