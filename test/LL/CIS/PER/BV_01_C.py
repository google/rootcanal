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

    SDU_Interval_C_TO_P = 7500  # 7.5ms
    SDU_Interval_P_TO_C = 7500  # 7.5ms
    ISO_Interval = 6  # 7.5ms
    Sub_Interval = 7500  # 7.5ms (approximation)
    CIG_Sync_Delay = 7500  # 7.5ms (approximation)
    CIS_Sync_Delay = 7500  # 7.5ms (approximation)
    Worst_Case_SCA = hci.ClockAccuracy.PPM_500
    Packing = hci.Packing.SEQUENTIAL
    Framing = hci.Enable.DISABLED
    NSE = 2
    Max_SDU_C_TO_P = 160
    Max_SDU_P_TO_C = 160
    Max_PDU_C_TO_P = 160
    Max_PDU_P_TO_C = 160
    PHY_C_TO_P = 0x1
    PHY_P_TO_C = 0x1
    FT_C_TO_P = 1
    FT_P_TO_C = 1
    BN_C_TO_P = 1
    BN_P_TO_C = 1
    Max_Transport_Latency_C_TO_P = 40000  # 40ms
    Max_Transport_Latency_P_TO_C = 40000  # 40ms
    RTN_C_TO_P = 3
    RTN_P_TO_C = 3

    # LL/CIS/PER/BV-01-C [CIS Setup Response Procedure, Peripheral]
    async def test(self):
        # Test parameters.
        cig_id = 0x12
        cis_id = 0x42
        acl_connection_handle = 0xefe
        cis_connection_handle = 0xe00
        peer_address = Address('aa:bb:cc:dd:ee:ff')
        controller = self.controller

        # Enable Connected Isochronous Stream Host Support.
        await self.enable_connected_isochronous_stream_host_support()

        # Prelude: Establish an ACL connection as peripheral with the IUT.
        acl_connection_handle = await self.establish_le_connection_peripheral(peer_address)

        # 1. The Upper Tester sends an HCI_LE_Set_Event_Mask command with all events enabled,
        # including the HCI_LE_CIS_Request event. The IUT sends a successful
        # HCI_Command_Complete in response.
        controller.send_cmd(hci.LeSetEventMask(le_event_mask=0xffffffffffffffff))

        await self.expect_evt(hci.LeSetEventMaskComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. The Lower Tester sends an LL_CIS_REQ to the IUT with the contents specified in Table 4.156.
        # All bits in the RFU fields in the LL_CIS_REQ are set.
        controller.send_llcp(source_address=peer_address,
                             destination_address=controller.address,
                             pdu=llcp.CisReq(cig_id=cig_id,
                                             cis_id=cis_id,
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
                                             sub_interval=self.Sub_Interval,
                                             bn_p_to_c=self.BN_C_TO_P,
                                             bn_c_to_p=self.BN_P_TO_C,
                                             ft_c_to_p=self.FT_C_TO_P,
                                             ft_p_to_c=self.FT_P_TO_C,
                                             iso_interval=self.ISO_Interval,
                                             cis_offset_min=0,
                                             cis_offset_max=0,
                                             conn_event_count=0))

        # 3. The IUT sends an HCI_LE_CIS_Request event to the Upper Tester and the parameters include
        # CIS_Connection_Handle assigned by the IUT.
        await self.expect_evt(
            hci.LeCisRequest(acl_connection_handle=acl_connection_handle,
                             cis_connection_handle=cis_connection_handle,
                             cig_id=cig_id,
                             cis_id=cis_id))

        # 4. The Upper Tester sends an HCI_LE_Accept_CIS_Request command to the IUT, with the
        # Connection_Handle field set to the value of the CIS_Connection_Handle received in step 3.
        controller.send_cmd(hci.LeAcceptCisRequest(connection_handle=cis_connection_handle))

        # 5. The IUT sends a successful Command Status to the Upper Tester.
        await self.expect_evt(hci.LeAcceptCisRequestStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 6. The IUT sends an LL_CIS_RSP PDU to the Upper Tester. In the message, the CIS_Offset_Min
        # field and the CIS_Offset_Max field are equal to or a subset of the values received in the
        # LL_CIS_REQ sent in step 2.
        cis_rsp = await self.expect_llcp(source_address=controller.address,
                                         destination_address=peer_address,
                                         expected_pdu=llcp.CisRsp(cis_offset_min=self.Any,
                                                                  cis_offset_max=self.Any,
                                                                  conn_event_count=0))

        # 7. The Lower Tester sends an LL_CIS_IND where the CIS_Offset is the time (ms) from the start of
        # the ACL connection event in connEvent Count to the first CIS anchor point, the CIS_Sync_Delay
        # is CIG_Sync_Delay minus the offset from the CIG reference point to the CIS anchor point in s,
        # and the connEventCount is the CIS_Offset reference point.
        controller.send_llcp(source_address=peer_address,
                             destination_address=controller.address,
                             pdu=llcp.CisInd(aa=0,
                                             cis_offset=cis_rsp.cis_offset_max,
                                             cig_sync_delay=self.CIG_Sync_Delay,
                                             cis_sync_delay=self.CIS_Sync_Delay,
                                             conn_event_count=0))

        # 8. The IUT sends a successful HCI_LE_CIS_Established event to the Upper Tester, after the first
        # CIS packet sent by the Lower Tester. The Connection_Handle parameter is the
        # CIS_Connection_Handle value provided in the HCI_LE_CIS_Request event.
        await self.expect_evt(
            hci.LeCisEstablished(status=ErrorCode.SUCCESS,
                                 connection_handle=cis_connection_handle,
                                 cig_sync_delay=self.CIG_Sync_Delay,
                                 cis_sync_delay=self.CIS_Sync_Delay,
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

        # 9. The Upper Tester sends an HCI_LE_Setup_ISO_Data_Path command to the IUT with the output
        # path enabled and receives a successful HCI_Command_Complete in response.
        controller.send_cmd(
            hci.LeSetupIsoDataPath(
                connection_handle=cis_connection_handle,
                data_path_direction=hci.DataPathDirection.OUTPUT,
                data_path_id=0,
                codec_id=0,
                controller_delay=0,
                codec_configuration=[],
            ))

        await self.expect_evt(
            hci.LeSetupIsoDataPathComplete(status=ErrorCode.SUCCESS,
                                           num_hci_command_packets=1,
                                           connection_handle=cis_connection_handle))

        # 10. The Lower Tester sends data packets to the IUT.
        iso_sdu = [random.randint(1, 251) for n in range(self.Max_SDU_C_TO_P)]
        controller.send_ll(
            ll.LeConnectedIsochronousPdu(source_address=controller.address,
                                         cig_id=cig_id,
                                         cis_id=cis_id,
                                         sequence_number=42,
                                         data=iso_sdu))

        # 11. The IUT sends an ISO data packet to the Upper Tester
        await self.expect_iso(
            hci.IsoWithoutTimestamp(
                connection_handle=cis_connection_handle,
                pb_flag=hci.IsoPacketBoundaryFlag.COMPLETE_SDU,
                packet_sequence_number=42,
                iso_sdu_length=len(iso_sdu),
                payload=iso_sdu,
            ))
