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
    req_all_phys: int
    req_tx_phys: int
    req_rx_phys: int
    rsp_tx_phys: int
    rsp_rx_phys: int


class Test(ControllerTest):

    # LL/CON/CEN/BV-41-C [Initiating PHY Update Procedure]
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

        test_rounds = [
            TestRound(0x00, 0x02, 0x02, 0x02, 0x02),
            TestRound(0x00, 0x01, 0x02, 0x01, 0x02),
            TestRound(0x00, 0x02, 0x01, 0x02, 0x01),
            TestRound(0x00, 0x01, 0x01, 0x01, 0x01),
            TestRound(0x00, 0x03, 0x02, 0x03, 0x02),
            TestRound(0x00, 0x03, 0x01, 0x03, 0x01),
            TestRound(0x00, 0x01, 0x03, 0x01, 0x03),
            TestRound(0x00, 0x02, 0x03, 0x02, 0x03),
            TestRound(0x00, 0x03, 0x03, 0x03, 0x03),
            TestRound(0x01, 0x00, 0x02, 0x03, 0x03),
            TestRound(0x02, 0x02, 0x00, 0x03, 0x03),
            TestRound(0x03, 0x00, 0x00, 0x03, 0x03),
            TestRound(0x00, 0x04, 0x04, 0x04, 0x04),
            TestRound(0x00, 0x01, 0x04, 0x01, 0x04),
            TestRound(0x00, 0x04, 0x01, 0x04, 0x01),
            TestRound(0x00, 0x01, 0x01, 0x01, 0x01),
            TestRound(0x00, 0x05, 0x04, 0x05, 0x04),
            TestRound(0x00, 0x05, 0x01, 0x05, 0x01),
            TestRound(0x00, 0x01, 0x05, 0x01, 0x05),
            TestRound(0x00, 0x04, 0x05, 0x04, 0x05),
            TestRound(0x00, 0x05, 0x05, 0x05, 0x05),
            TestRound(0x01, 0x00, 0x04, 0x05, 0x05),
            TestRound(0x02, 0x04, 0x00, 0x05, 0x05),
            TestRound(0x03, 0x00, 0x00, 0x05, 0x05),
            TestRound(0x00, 0x06, 0x06, 0x02, 0x02),
            TestRound(0x00, 0x06, 0x06, 0x04, 0x04),
            TestRound(0x00, 0x06, 0x06, 0x02, 0x02),
            TestRound(0x00, 0x02, 0x04, 0x02, 0x04),
            TestRound(0x00, 0x04, 0x02, 0x04, 0x02),
            TestRound(0x03, 0x00, 0x00, 0x04, 0x04),
            TestRound(0x03, 0x00, 0x00, 0x02, 0x02),
            TestRound(0x03, 0x00, 0x00, 0x01, 0x01),
        ]

        # Repeat steps 1-9 for each Round shown in Table 4.77.
        phy_c_to_p = 0x1
        phy_p_to_c = 0x1
        for test_round in test_rounds:
            (phy_c_to_p, phy_p_to_c) = await self.steps_1_9(peer_address, acl_connection_handle, phy_c_to_p, phy_p_to_c,
                                                            **vars(test_round))

    async def steps_1_9(self, peer_address: Address, connection_handle: int, phy_c_to_p: int, phy_p_to_c: int,
                        req_all_phys: int, req_tx_phys: int, req_rx_phys: int, rsp_tx_phys: int, rsp_rx_phys: int):
        controller = self.controller

        def phy_from_mask(mask: int):
            if mask & 0x4:
                return hci.PhyType.LE_CODED
            elif mask & 0x2:
                return hci.PhyType.LE_2M
            else:
                return hci.PhyType.LE_1M

        # 1. Upper Tester sends an HCI_LE_Set_PHY command to the IUT with the payload defined in the
        # HCI_LE_Set_PHY section of Table 4.77 and PHY_options set to 0x0000.
        controller.send_cmd(
            hci.LeSetPhy(connection_handle=connection_handle,
                         all_phys_no_transmit_preference=(req_all_phys & 0x1) != 0,
                         all_phys_no_receive_preference=(req_all_phys & 0x2) != 0,
                         tx_phys=req_tx_phys,
                         rx_phys=req_rx_phys,
                         phy_options=hci.PhyOptions.NO_PREFERENCE))

        # 2. The Upper Tester receives an HCI_Command_Status event from the IUT in response. If any bits
        # set in TX_PHYS or RX_PHYS correspond to unsupported PHYs, the Status shall be set to
        # “Unsupported Feature or Parameter Value (0x11)”. Otherwise the Status shall be set to zero.
        await self.expect_evt(hci.LeSetPhyStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. If the IUT does not initiate a PHY change, proceed to step 9 if the Status in step 2 was set to zero
        # or proceed to the next round if the Status in step 2 was set to a nonzero value.

        if (req_all_phys & 0x1) != 0:
            req_tx_phys = 0x7
        if (req_all_phys & 0x2) != 0:
            req_rx_phys = 0x7

        # 4. The Lower Tester receives an LL_PHY_REQ control PDU from the IUT with at least one bit set in
        # each field (RX_PHYS, TX_PHYS). The Lower Tester acknowledges the IUT’s request and
        # responds with an LL_PHY_RSP PDU with the payload defined in the LL_PHY_RSP section of
        # Table 4.77.
        await self.expect_ll(
            ll.LlPhyReq(source_address=controller.address,
                        destination_address=peer_address,
                        tx_phys=req_tx_phys,
                        rx_phys=req_rx_phys))

        controller.send_ll(
            ll.LlPhyRsp(source_address=peer_address,
                        destination_address=controller.address,
                        tx_phys=rsp_tx_phys,
                        rx_phys=rsp_rx_phys))

        # 5. Lower Tester receives an LL_PHY_UPDATE_IND with zero or one bits set in each field
        # (PHY_C_TO_P, PHY_P_TO_C) and a selected PHY present in the payload sent in the
        # LL_PHY_RSP PDU. If no bits are set in either field, proceed to step 8.
        phy_update_ind = await self.expect_ll(
            ll.LlPhyUpdateInd(source_address=controller.address,
                              destination_address=peer_address,
                              phy_c_to_p=self.Any,
                              phy_p_to_c=self.Any))

        self.assertTrue((phy_update_ind.phy_c_to_p & ~req_tx_phys) == 0)
        self.assertTrue((phy_update_ind.phy_c_to_p & ~rsp_rx_phys) == 0)
        self.assertTrue((phy_update_ind.phy_p_to_c & ~req_rx_phys) == 0)
        self.assertTrue((phy_update_ind.phy_p_to_c & ~rsp_tx_phys) == 0)
        phy_c_to_p = phy_update_ind.phy_c_to_p or phy_c_to_p
        phy_p_to_c = phy_update_ind.phy_p_to_c or phy_p_to_c

        # 6. Maintain the connection using empty DATA packets until the event count matches the Instant
        # indicated in the LL_PHY_UPDATE_IND packet.

        # 7. Once the event count matches the time, the new PHY(s) selected by the IUT will be used.

        # 8. IUT sends empty DATA packets to the Lower Tester, and the Lower Tester acknowledges these
        # packets, using the selected PHY(s).

        # 9. If the command was accepted in step 2 or at least one of the PHY fields in the
        # LL_PHY_UPDATE_IND PDU was nonzero, the Upper Tester receives an
        # LE_PHY_Update_Complete event from the IUT with a payload consistent with the PHY(s)
        # indicated in the LL_PHY_UPDATE_IND PDU (or the prior PHY, in cases where a field in
        # LL_PHY_UPDATE_IND was zero or LL_PHY_UPDATE_IND was not sent). Otherwise the Upper
        # Tester receives no event.
        await self.expect_evt(
            hci.LePhyUpdateComplete(connection_handle=connection_handle,
                                    status=ErrorCode.SUCCESS,
                                    tx_phy=phy_from_mask(phy_c_to_p),
                                    rx_phy=phy_from_mask(phy_p_to_c)))

        return (phy_c_to_p, phy_p_to_c)
