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
import llcp_packets as llcp
import random
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    SDU_Interval_C_TO_P = 10000  # 10ms
    SDU_Interval_P_TO_C = 10000  # 10ms
    ISO_Interval = 16  # 20ms
    Worst_Case_SCA = hci.ClockAccuracy.PPM_500
    Packing = hci.Packing.SEQUENTIAL
    Framing = hci.Enable.DISABLED
    NSE = 4
    Max_SDU_C_TO_P = 130
    Max_SDU_P_TO_C = 130
    Max_PDU_C_TO_P = 130
    Max_PDU_P_TO_C = 130
    PHY_C_TO_P = 0x1
    PHY_P_TO_C = 0x1
    FT_C_TO_P = 1
    FT_P_TO_C = 1
    BN_C_TO_P = 2
    BN_P_TO_C = 2
    Max_Transport_Latency_C_TO_P = 40000  # 40ms
    Max_Transport_Latency_P_TO_C = 40000  # 40ms
    RTN_C_TO_P = 3
    RTN_P_TO_C = 3

    # LL/CIS/CEN/BV-01-C [CIS Setup Procedure, Central Initiated]
    async def test(self):
        # Test parameters.
        cig_id = 0x12
        cis_id_1 = 0x42
        cis_id_2 = 0x43
        cis_connection_handle_1 = 0xe00
        cis_connection_handle_2 = 0xe01
        peer_address_1 = Address('aa:bb:cc:dd:ee:ff')
        peer_address_2 = Address('aa:bb:cc:dd:ee:fe')
        controller = self.controller

        # Enable Connected Isochronous Stream Host Support.
        await self.enable_connected_isochronous_stream_host_support()

        # Prelude: Establish ACL connections as central with the IUT.
        acl_connection_handle_1 = await self.establish_le_connection_central(peer_address_1)
        acl_connection_handle_2 = await self.establish_le_connection_central(peer_address_2)

        # Prelude: Establish CIS(1) and CIS(2) with connected peers.
        controller.send_cmd(
            hci.LeSetCigParametersTest(cig_id=cig_id,
                                       sdu_interval_c_to_p=self.SDU_Interval_C_TO_P,
                                       sdu_interval_p_to_c=self.SDU_Interval_P_TO_C,
                                       ft_c_to_p=self.FT_C_TO_P,
                                       ft_p_to_c=self.FT_P_TO_C,
                                       iso_interval=self.ISO_Interval,
                                       worst_case_sca=self.Worst_Case_SCA,
                                       packing=self.Packing,
                                       framing=self.Framing,
                                       cis_config=[
                                           hci.LeCisParametersTestConfig(cis_id=cis_id_1,
                                                                         nse=self.NSE,
                                                                         max_sdu_c_to_p=self.Max_SDU_C_TO_P,
                                                                         max_sdu_p_to_c=self.Max_SDU_P_TO_C,
                                                                         max_pdu_c_to_p=self.Max_PDU_C_TO_P,
                                                                         max_pdu_p_to_c=self.Max_PDU_P_TO_C,
                                                                         phy_c_to_p=self.PHY_C_TO_P,
                                                                         phy_p_to_c=self.PHY_P_TO_C,
                                                                         bn_c_to_p=self.BN_C_TO_P,
                                                                         bn_p_to_c=self.BN_P_TO_C),
                                           hci.LeCisParametersTestConfig(cis_id=cis_id_2,
                                                                         nse=self.NSE,
                                                                         max_sdu_c_to_p=self.Max_SDU_C_TO_P,
                                                                         max_sdu_p_to_c=self.Max_SDU_P_TO_C,
                                                                         max_pdu_c_to_p=self.Max_PDU_C_TO_P,
                                                                         max_pdu_p_to_c=self.Max_PDU_P_TO_C,
                                                                         phy_c_to_p=self.PHY_C_TO_P,
                                                                         phy_p_to_c=self.PHY_P_TO_C,
                                                                         bn_c_to_p=self.BN_C_TO_P,
                                                                         bn_p_to_c=self.BN_P_TO_C)
                                       ]))

        await self.expect_evt(
            hci.LeSetCigParametersTestComplete(status=ErrorCode.SUCCESS,
                                               num_hci_command_packets=1,
                                               cig_id=cig_id,
                                               connection_handle=[cis_connection_handle_1, cis_connection_handle_2]))

        controller.send_cmd(
            hci.LeCreateCis(cis_config=[
                hci.LeCreateCisConfig(cis_connection_handle=cis_connection_handle_1,
                                      acl_connection_handle=acl_connection_handle_1),
                hci.LeCreateCisConfig(cis_connection_handle=cis_connection_handle_2,
                                      acl_connection_handle=acl_connection_handle_2)
            ]))

        await self.expect_evt(hci.LeCreateCisStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        cis_req_1 = await self.expect_llcp(source_address=controller.address,
                                           destination_address=peer_address_1,
                                           expected_pdu=llcp.CisReq(cig_id=cig_id,
                                                                    cis_id=cis_id_1,
                                                                    phy_c_to_p=hci.PhyType.LE_1M,
                                                                    phy_p_to_c=hci.PhyType.LE_1M,
                                                                    framed=self.Framing == hci.Enable.ENABLED,
                                                                    max_sdu_c_to_p=self.Max_SDU_C_TO_P,
                                                                    max_sdu_p_to_c=self.Max_SDU_P_TO_C,
                                                                    sdu_interval_c_to_p=self.SDU_Interval_C_TO_P,
                                                                    sdu_interval_p_to_c=self.SDU_Interval_P_TO_C,
                                                                    max_pdu_c_to_p=self.Max_PDU_C_TO_P,
                                                                    max_pdu_p_to_c=self.Max_PDU_P_TO_C,
                                                                    nse=self.NSE,
                                                                    sub_interval=self.Any,
                                                                    bn_p_to_c=self.BN_C_TO_P,
                                                                    bn_c_to_p=self.BN_P_TO_C,
                                                                    ft_c_to_p=self.FT_C_TO_P,
                                                                    ft_p_to_c=self.FT_P_TO_C,
                                                                    iso_interval=self.ISO_Interval,
                                                                    cis_offset_min=self.Any,
                                                                    cis_offset_max=self.Any,
                                                                    conn_event_count=0))

        controller.send_llcp(source_address=peer_address_1,
                             destination_address=controller.address,
                             pdu=llcp.CisRsp(cis_offset_min=cis_req_1.cis_offset_min,
                                             cis_offset_max=cis_req_1.cis_offset_max,
                                             conn_event_count=0))

        cis_ind_1 = await self.expect_llcp(source_address=controller.address,
                                           destination_address=peer_address_1,
                                           expected_pdu=llcp.CisInd(aa=0,
                                                                    cis_offset=self.Any,
                                                                    cig_sync_delay=self.Any,
                                                                    cis_sync_delay=self.Any,
                                                                    conn_event_count=0))

        await self.expect_evt(
            hci.LeCisEstablished(status=ErrorCode.SUCCESS,
                                 connection_handle=cis_connection_handle_1,
                                 cig_sync_delay=cis_ind_1.cig_sync_delay,
                                 cis_sync_delay=cis_ind_1.cis_sync_delay,
                                 transport_latency_c_to_p=self.Any,
                                 transport_latency_p_to_c=self.Any,
                                 phy_c_to_p=hci.SecondaryPhyType.LE_1M,
                                 phy_p_to_c=hci.SecondaryPhyType.LE_1M,
                                 nse=self.NSE,
                                 bn_c_to_p=self.BN_C_TO_P,
                                 bn_p_to_c=self.BN_P_TO_C,
                                 ft_c_to_p=self.FT_C_TO_P,
                                 ft_p_to_c=self.FT_P_TO_C,
                                 max_pdu_c_to_p=self.Max_PDU_C_TO_P,
                                 max_pdu_p_to_c=self.Max_PDU_P_TO_C,
                                 iso_interval=self.ISO_Interval))

        cis_req_2 = await self.expect_llcp(source_address=controller.address,
                                           destination_address=peer_address_2,
                                           expected_pdu=llcp.CisReq(cig_id=cig_id,
                                                                    cis_id=cis_id_2,
                                                                    phy_c_to_p=hci.PhyType.LE_1M,
                                                                    phy_p_to_c=hci.PhyType.LE_1M,
                                                                    framed=self.Framing == hci.Enable.ENABLED,
                                                                    max_sdu_c_to_p=self.Max_SDU_C_TO_P,
                                                                    max_sdu_p_to_c=self.Max_SDU_P_TO_C,
                                                                    sdu_interval_c_to_p=self.SDU_Interval_C_TO_P,
                                                                    sdu_interval_p_to_c=self.SDU_Interval_P_TO_C,
                                                                    max_pdu_c_to_p=self.Max_PDU_C_TO_P,
                                                                    max_pdu_p_to_c=self.Max_PDU_P_TO_C,
                                                                    nse=self.NSE,
                                                                    sub_interval=self.Any,
                                                                    bn_p_to_c=self.BN_C_TO_P,
                                                                    bn_c_to_p=self.BN_P_TO_C,
                                                                    ft_c_to_p=self.FT_C_TO_P,
                                                                    ft_p_to_c=self.FT_P_TO_C,
                                                                    iso_interval=self.ISO_Interval,
                                                                    cis_offset_min=self.Any,
                                                                    cis_offset_max=self.Any,
                                                                    conn_event_count=0))

        controller.send_llcp(source_address=peer_address_2,
                             destination_address=controller.address,
                             pdu=llcp.CisRsp(cis_offset_min=cis_req_2.cis_offset_min,
                                             cis_offset_max=cis_req_2.cis_offset_max,
                                             conn_event_count=0))

        cis_ind_2 = await self.expect_llcp(source_address=controller.address,
                                           destination_address=peer_address_2,
                                           expected_pdu=llcp.CisInd(aa=0,
                                                                    cis_offset=self.Any,
                                                                    cig_sync_delay=self.Any,
                                                                    cis_sync_delay=self.Any,
                                                                    conn_event_count=0))

        await self.expect_evt(
            hci.LeCisEstablished(status=ErrorCode.SUCCESS,
                                 connection_handle=cis_connection_handle_2,
                                 cig_sync_delay=cis_ind_2.cig_sync_delay,
                                 cis_sync_delay=cis_ind_2.cis_sync_delay,
                                 transport_latency_c_to_p=self.Any,
                                 transport_latency_p_to_c=self.Any,
                                 phy_c_to_p=hci.SecondaryPhyType.LE_1M,
                                 phy_p_to_c=hci.SecondaryPhyType.LE_1M,
                                 nse=self.NSE,
                                 bn_c_to_p=self.BN_C_TO_P,
                                 bn_p_to_c=self.BN_P_TO_C,
                                 ft_c_to_p=self.FT_C_TO_P,
                                 ft_p_to_c=self.FT_P_TO_C,
                                 max_pdu_c_to_p=self.Max_PDU_C_TO_P,
                                 max_pdu_p_to_c=self.Max_PDU_P_TO_C,
                                 iso_interval=self.ISO_Interval))

        # 1. The Upper Tester orders the IUT to send a payload of the specified length to the Lower Testers.
        iso_sdu = [random.randint(1, 251) for n in range(self.Max_SDU_C_TO_P)]

        # 2. Lower Tester 1 receives the payload PDU in the first subevent on CIS(1).
        # 3. Lower Tester 1 sends an Ack T_IFS after receiving the payload PDU.
        controller.send_iso(
            hci.IsoWithoutTimestamp(
                connection_handle=cis_connection_handle_1,
                pb_flag=hci.IsoPacketBoundaryFlag.COMPLETE_SDU,
                packet_sequence_number=42,
                payload=iso_sdu,
            ))

        await self.expect_ll(
            ll.LeConnectedIsochronousPdu(source_address=controller.address,
                                         destination_address=peer_address_1,
                                         cig_id=cig_id,
                                         cis_id=cis_id_1,
                                         sequence_number=42,
                                         data=iso_sdu))

        # 4. Lower Tester 2 receives the payload PDU in the first subevent on CIS(2).
        # 5. Lower Tester 2 sends an Ack T_IFS after receiving the payload PDU.
        controller.send_iso(
            hci.IsoWithoutTimestamp(
                connection_handle=cis_connection_handle_2,
                pb_flag=hci.IsoPacketBoundaryFlag.COMPLETE_SDU,
                packet_sequence_number=42,
                payload=iso_sdu,
            ))

        await self.expect_ll(
            ll.LeConnectedIsochronousPdu(source_address=controller.address,
                                         destination_address=peer_address_2,
                                         cig_id=cig_id,
                                         cis_id=cis_id_2,
                                         sequence_number=42,
                                         data=iso_sdu))

        # 6. If Table 4.139 specifies a BN of 2 or 3, when CIS(1) subevent interval ends, repeat steps 1–3 in
        # the next subevent.
        # 7. If Table 4.139 specifies a BN of 2 or 3, when CIS(2) subevent interval ends, repeat steps 4 and 5
        # in the next subevent.
        # 8. If Table 4.139 specifies a BN of 3, when CIS(1) subevent interval ends, repeat steps 1–3 in the
        # next subevent.
        # 9. If Table 4.139 specifies a BN of 3, when CIS(2) subevent interval ends, repeat steps 4 and 5 in
        # the next subevent.
        # 10. The time between the ACL connection event for the first received CIS and the start of the first
        # subevent on the same CIS is the observed CIS_Offset(a). The Lower Tester validates that
        # CIS_Offset(a) = CIS_Offset in the LL_CIS_IND associated with CIS sent during setup of the
        # CISes.
        # 11. The time between the ACL connection event for the second received CIS and the start of the first
        # subevent on the same CIS is the observed CIS_Offset(b). The Lower Tester validates that the
        # CIS_Offset(b) = CIS_Offset in the LL_CIS_IND associated with CIS sent during setup of the
        # CISes.
