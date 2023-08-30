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


@dataclass
class TestRound:
    req_tx_phys: int
    req_rx_phys: int


class Test(ControllerTest):

    # LL/CON/CEN/BV-43-C [Responding to PHY Update Procedure]
    async def test(self):
        # Test parameters.
        controller = self.controller
        acl_connection_handle = 0xefe
        peer_address = Address('11:22:33:44:55:66')

        # Prelude: Establish an ACL connection as central with the IUT.
        controller.send_cmd(
            hci.LeExtendedCreateConnection(initiator_filter_policy=hci.InitiatorFilterPolicy.USE_PEER_ADDRESS,
                                           own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                           peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                           peer_address=peer_address,
                                           initiating_phys=0x1,
                                           initiating_phy_parameters=[
                                               hci.InitiatingPhyParameters(
                                                   scan_interval=0x200,
                                                   scan_window=0x100,
                                                   connection_interval_min=0x200,
                                                   connection_interval_max=0x200,
                                                   max_latency=0x6,
                                                   supervision_timeout=0xc80,
                                                   min_ce_length=0,
                                                   max_ce_length=0,
                                               )
                                           ]))

        await self.expect_evt(hci.LeExtendedCreateConnectionStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        controller.send_ll(ll.LeLegacyAdvertisingPdu(source_address=peer_address,
                                                     advertising_address_type=ll.AddressType.PUBLIC,
                                                     advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                                                     advertising_data=[]),
                           rssi=-16)

        await self.expect_ll(
            ll.LeConnect(source_address=controller.address,
                         destination_address=peer_address,
                         initiating_address_type=ll.AddressType.PUBLIC,
                         advertising_address_type=ll.AddressType.PUBLIC,
                         conn_interval=0x200,
                         conn_peripheral_latency=0x6,
                         conn_supervision_timeout=0xc80))

        controller.send_ll(
            ll.LeConnectComplete(source_address=peer_address,
                                 destination_address=controller.address,
                                 initiating_address_type=ll.AddressType.PUBLIC,
                                 advertising_address_type=ll.AddressType.PUBLIC,
                                 conn_interval=0x200,
                                 conn_peripheral_latency=0x6,
                                 conn_supervision_timeout=0xc80))

        await self.expect_evt(
            hci.LeEnhancedConnectionComplete(status=ErrorCode.SUCCESS,
                                             connection_handle=acl_connection_handle,
                                             role=hci.Role.CENTRAL,
                                             peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                                             peer_address=peer_address,
                                             connection_interval=0x200,
                                             peripheral_latency=0x6,
                                             supervision_timeout=0xc80,
                                             central_clock_accuracy=hci.ClockAccuracy.PPM_500))

        await self.expect_evt(
            hci.LeChannelSelectionAlgorithm(connection_handle=acl_connection_handle,
                                            channel_selection_algorithm=hci.ChannelSelectionAlgorithm.ALGORITHM_1))

        # 1. The Upper Tester sends an HCI_LE_Set_PHY command to the IUT with the ALL_PHYS field set
        # to a value of 0x03. The Upper Tester receives an HCI_Command_Status event indicating
        # success in response. The controller may send a LL_PHY_REQ to the Lower Tester. In this case,
        # the Lower Tester sends a LL_PHY_RSP specifying the current PHY in both directions in
        # response and the IUT completes the transaction with an LL_PHY_UPDATE_IND. Whether or not
        # the procedure is carried out with the Lower Tester, the Upper Tester receives an
        # HCI_LE_PHY_Update_Complete event from the IUT indicating both directions are operating
        # using the LE 1M PHY.
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
            ll.LlPhyRsp(source_address=peer_address, destination_address=controller.address, tx_phys=0x1, rx_phys=0x1))

        await self.expect_ll(
            ll.LlPhyUpdateInd(source_address=controller.address,
                              destination_address=peer_address,
                              phy_c_to_p=0x0,
                              phy_p_to_c=0x0))

        await self.expect_evt(
            hci.LePhyUpdateComplete(status=ErrorCode.SUCCESS,
                                    connection_handle=acl_connection_handle,
                                    tx_phy=hci.PhyType.LE_1M,
                                    rx_phy=hci.PhyType.LE_1M))

        test_rounds = [
            TestRound(0x03, 0x01),
            TestRound(0x05, 0x02),
            TestRound(0x02, 0x04),
            TestRound(0x01, 0x02),
            TestRound(0x04, 0x01),
            TestRound(0x03, 0x06),
            TestRound(0x01, 0x01),
            TestRound(0x04, 0x03),
            TestRound(0x05, 0x01),
            TestRound(0x04, 0x04),
            TestRound(0x05, 0x07),
            TestRound(0x05, 0x05),
            TestRound(0x04, 0x02),
            TestRound(0x03, 0x07),
            TestRound(0x06, 0x06),
            TestRound(0x03, 0x02),
            TestRound(0x01, 0x06),
            TestRound(0x05, 0x06),
            TestRound(0x04, 0x05),
            TestRound(0x01, 0x05),
            TestRound(0x05, 0x03),
            TestRound(0x01, 0x04),
            TestRound(0x01, 0x03),
            TestRound(0x03, 0x05),
            TestRound(0x06, 0x04),
            TestRound(0x02, 0x07),
            TestRound(0x06, 0x01),
            TestRound(0x02, 0x02),
            TestRound(0x03, 0x04),
            TestRound(0x07, 0x03),
            TestRound(0x02, 0x01),
            TestRound(0x03, 0x03),
            TestRound(0x02, 0x03),
            TestRound(0x04, 0x07),
            TestRound(0x07, 0x04),
            TestRound(0x07, 0x01),
            TestRound(0x06, 0x05),
            TestRound(0x02, 0x06),
            TestRound(0x07, 0x07),
            TestRound(0x04, 0x06),
            TestRound(0x02, 0x05),
            TestRound(0x06, 0x02),
            TestRound(0x07, 0x02),
            TestRound(0x07, 0x06),
            TestRound(0x06, 0x07),
            TestRound(0x06, 0x03),
            TestRound(0x05, 0x04),
            TestRound(0x07, 0x05),
            TestRound(0x01, 0x07),
        ]

        # 2. Perform steps 3–9 2N times as follows, where N is the number of cases in Table 4.78, Table
        # 4.79, or Table 4.80 (selected based on the supported PHY(s)):
        # ▪ firstly using cases 1 to N from the relevant table in order;
        # ▪ then using the cases from the relevant table in a random order.
        phy_c_to_p = 0x1
        phy_p_to_c = 0x1
        for test_round in test_rounds:
            (phy_c_to_p, phy_p_to_c) = await self.steps_3_9(peer_address, acl_connection_handle, phy_c_to_p, phy_p_to_c,
                                                            **vars(test_round))

    async def steps_3_9(self, peer_address: Address, connection_handle: int, phy_c_to_p: int, phy_p_to_c: int,
                        req_tx_phys: int, req_rx_phys: int):
        controller = self.controller

        def phy_from_mask(mask: int):
            if mask & 0x4:
                return hci.PhyType.LE_CODED
            elif mask & 0x2:
                return hci.PhyType.LE_2M
            else:
                return hci.PhyType.LE_1M

        # 3. Lower Tester sends an LL_PHY_REQ PDU to the IUT with the payload specified in the relevant
        # table.
        controller.send_ll(
            ll.LlPhyReq(source_address=peer_address,
                        destination_address=controller.address,
                        tx_phys=req_tx_phys,
                        rx_phys=req_rx_phys))

        # 4. Lower Tester receives an LL_PHY_UPDATE_IND PDU from the IUT with a value selected for
        # PHY_C_TO_P and PHY_P_TO_C that is either a bit value present in the LL_PHY_REQ or zero,
        # with a maximum of 1 bit set for each field. If either the PHY_C_TO_P or PHY_P_TO_C fields are
        # nonzero, then the Instant shall have a valid value.
        phy_update_ind = await self.expect_ll(
            ll.LlPhyUpdateInd(source_address=controller.address,
                              destination_address=peer_address,
                              phy_c_to_p=self.Any,
                              phy_p_to_c=self.Any))

        # 5. Maintain the connection using empty DATA packets until the event count matches the Instant
        # indicated in the LL_PHY_UPDATE_IND packet.

        # 6. Once the event count matches the time, the PHY(s) selected by the IUT in the
        # LL_PHY_UPDATE_IND packet will be used.

        # 7. At the Instant of the PHY change start maintaining the connection with the selected PHY(s).

        # 8. IUT sends empty DATA packets to the Lower Tester, and Lower Tester acknowledges these
        # packets, using the selected PHY(s).

        # 9. If the PHY(s) were changed, Upper Tester receives an LE_PHY_Update_Complete event from
        # the IUT containing the PHY(s) selected. If both PHYs were NOT changed, Upper Tester does
        # NOT receive an LE_PHY_Update_Complete event.
        next_phy_c_to_p = phy_update_ind.phy_c_to_p or phy_c_to_p
        next_phy_p_to_c = phy_update_ind.phy_p_to_c or phy_p_to_c

        if phy_update_ind.phy_c_to_p != 0 or phy_update_ind.phy_p_to_c != 0:
            await self.expect_evt(
                hci.LePhyUpdateComplete(connection_handle=connection_handle,
                                        status=ErrorCode.SUCCESS,
                                        tx_phy=phy_from_mask(next_phy_c_to_p),
                                        rx_phy=phy_from_mask(next_phy_p_to_c)))

        return (next_phy_c_to_p, next_phy_p_to_c)
