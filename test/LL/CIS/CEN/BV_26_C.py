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
    Framing = hci.Enable.ENABLED
    NSE = 4
    Max_SDU_C_TO_P = 16
    Max_SDU_P_TO_C = 16
    PHY_C_TO_P = 0x1
    PHY_P_TO_C = 0x1
    Max_Transport_Latency_C_TO_P = 60  # 60ms
    Max_Transport_Latency_P_TO_C = 60  # 60ms
    RTN_C_TO_P = 3
    RTN_P_TO_C = 3

    # LL/CIS/CEN/BV-01-C [CIS Setup Procedure, Central Initiated]
    async def test(self):
        # Test parameters.
        cig_id = 0x12
        cis_id = 0x42
        cis_connection_handle = 0xe00
        peer_address = Address('aa:bb:cc:dd:ee:ff')
        controller = self.controller

        # Enable Connected Isochronous Stream Host Support.
        await self.enable_connected_isochronous_stream_host_support()

        # Prelude: Establish an ACL connection as central with the IUT.
        acl_connection_handle = await self.establish_le_connection_central(peer_address)

        # 1. The Upper Tester sends an HCI_LE_Set_CIG_Parameters command to the IUT with
        # Max_SDU_C_To_P and Max_SDU_P_To_C both set to 16, other parameters set to default, but
        # with PHY and latency specified in Table 4.142 and framing enabled. The Upper Tester receives a
        # success response from the IUT with CIS_Count = 1.
        controller.send_cmd(
            hci.LeSetCigParameters(cig_id=cig_id,
                                   sdu_interval_c_to_p=self.SDU_Interval_C_TO_P,
                                   sdu_interval_p_to_c=self.SDU_Interval_P_TO_C,
                                   worst_case_sca=self.Worst_Case_SCA,
                                   max_transport_latency_c_to_p=self.Max_Transport_Latency_C_TO_P,
                                   max_transport_latency_p_to_c=self.Max_Transport_Latency_P_TO_C,
                                   packing=self.Packing,
                                   framing=self.Framing,
                                   cis_config=[
                                       hci.CisParametersConfig(cis_id=cis_id,
                                                               max_sdu_c_to_p=self.Max_SDU_C_TO_P,
                                                               max_sdu_p_to_c=self.Max_SDU_P_TO_C,
                                                               phy_c_to_p=self.PHY_C_TO_P,
                                                               phy_p_to_c=self.PHY_P_TO_C,
                                                               rtn_c_to_p=self.RTN_C_TO_P,
                                                               rtn_p_to_c=self.RTN_P_TO_C)
                                   ]))

        await self.expect_evt(
            hci.LeSetCigParametersComplete(status=ErrorCode.SUCCESS,
                                           num_hci_command_packets=1,
                                           cig_id=cig_id,
                                           connection_handle=[cis_connection_handle]))

        # 2. The Upper Tester sends an HCI_LE_Create_CIS command to create a single CIS and receives a
        # success response from the IUT.
        controller.send_cmd(
            hci.LeCreateCis(cis_config=[
                hci.LeCreateCisConfig(cis_connection_handle=cis_connection_handle,
                                      acl_connection_handle=acl_connection_handle)
            ]))

        await self.expect_evt(hci.LeCreateCisStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. The Lower Tester receives an LL_CIS_REQ PDU from the IUT with all fields set to valid values.
        # CIS_Offset_Min is a value between 500µs and TSPX_conn_interval, CIS_Offset_Max is a value
        # between CIS_Offset_Min and the CIS_Offset_Max value as calculated in [14] Section 2.4.2.29
        # using TSPX_conn_interval as the value of connInterval, and connEventCount is the reference
        # event anchor point for which the offsets applied.
        cis_req = await self.expect_llcp(source_address=controller.address,
                                         destination_address=peer_address,
                                         expected_pdu=llcp.CisReq(cig_id=cig_id,
                                                                  cis_id=cis_id,
                                                                  phy_c_to_p=hci.PhyType.LE_1M,
                                                                  phy_p_to_c=hci.PhyType.LE_1M,
                                                                  framed=self.Framing == hci.Enable.ENABLED,
                                                                  max_sdu_c_to_p=self.Max_SDU_C_TO_P,
                                                                  max_sdu_p_to_c=self.Max_SDU_P_TO_C,
                                                                  sdu_interval_c_to_p=self.Any,
                                                                  sdu_interval_p_to_c=self.Any,
                                                                  max_pdu_c_to_p=self.Any,
                                                                  max_pdu_p_to_c=self.Any,
                                                                  nse=self.Any,
                                                                  sub_interval=self.Any,
                                                                  bn_p_to_c=self.Any,
                                                                  bn_c_to_p=self.Any,
                                                                  ft_c_to_p=self.Any,
                                                                  ft_p_to_c=self.Any,
                                                                  iso_interval=self.Any,
                                                                  cis_offset_min=self.Any,
                                                                  cis_offset_max=self.Any,
                                                                  conn_event_count=0))

        # 4. The Lower Tester sends an LL_CIS_RSP PDU to the IUT.
        controller.send_llcp(source_address=peer_address,
                             destination_address=controller.address,
                             pdu=llcp.CisRsp(cis_offset_min=cis_req.cis_offset_min,
                                             cis_offset_max=cis_req.cis_offset_max,
                                             conn_event_count=0))

        # 5. The Lower Tester receives an LL_CIS_IND from the IUT where the CIS_Offset is the time (ms)
        # from the start of the ACL connection event in connEvent Count to the first CIS anchor point, the
        # CIS_Sync_Delay is CIG_Sync_Delay minus the offset from the CIG reference point to the CIS
        # anchor point in s, and the connEventCount is the CIS_Offset reference point.
        cis_ind = await self.expect_llcp(source_address=controller.address,
                                         destination_address=peer_address,
                                         expected_pdu=llcp.CisInd(aa=0,
                                                                  cis_offset=self.Any,
                                                                  cig_sync_delay=self.Any,
                                                                  cis_sync_delay=self.Any,
                                                                  conn_event_count=0))

        # 6. The Upper Tester receives an HCI_LE_CIS_Established event indicating success, after the first
        # CIS packet sent by the Lower Tester. The Connection_Handle parameter is set to the value
        # provided in the HCI_LE_Create_CIS command.
        await self.expect_evt(
            hci.LeCisEstablished(status=ErrorCode.SUCCESS,
                                 connection_handle=cis_connection_handle,
                                 cig_sync_delay=cis_ind.cig_sync_delay,
                                 cis_sync_delay=cis_ind.cis_sync_delay,
                                 transport_latency_c_to_p=self.Any,
                                 transport_latency_p_to_c=self.Any,
                                 phy_c_to_p=hci.SecondaryPhyType.LE_1M,
                                 phy_p_to_c=hci.SecondaryPhyType.LE_1M,
                                 nse=cis_req.nse,
                                 bn_c_to_p=cis_req.bn_c_to_p,
                                 bn_p_to_c=cis_req.bn_p_to_c,
                                 ft_c_to_p=cis_req.ft_c_to_p,
                                 ft_p_to_c=cis_req.ft_p_to_c,
                                 max_pdu_c_to_p=cis_req.max_pdu_c_to_p,
                                 max_pdu_p_to_c=cis_req.max_pdu_p_to_c,
                                 iso_interval=cis_req.iso_interval))

        # 7. The Upper Tester sends an HCI_LE_Setup_ISO_Data_Path command and receives a success
        # response from the IUT.
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

        # 8. The Upper Tester sends HCI ISO data packets over the CIS and the Lower Tester receives
        # framed ISO data.
        iso_sdu = [random.randint(1, 251) for n in range(self.Max_SDU_C_TO_P)]
        controller.send_iso(
            hci.IsoWithoutTimestamp(
                connection_handle=cis_connection_handle,
                pb_flag=hci.IsoPacketBoundaryFlag.COMPLETE_SDU,
                packet_sequence_number=42,
                payload=iso_sdu,
            ))

        await self.expect_ll(
            ll.LeConnectedIsochronousPdu(source_address=controller.address,
                                         destination_address=peer_address,
                                         cig_id=cig_id,
                                         cis_id=cis_id,
                                         sequence_number=42,
                                         data=iso_sdu))

        # 9. The Upper Tester sends an HCI_Disconnect command to the IUT with Reason set to any valid
        # value and Connection_Handle set to the connection handle of the active CIS and receives a
        # successful HCI_Command_Status event in response.
        controller.send_cmd(
            hci.Disconnect(connection_handle=cis_connection_handle, reason=ErrorCode.REMOTE_USER_TERMINATED_CONNECTION))

        await self.expect_evt(hci.DisconnectStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 10. The IUT sends an LL_CIS_TERMINATE_IND PDU to the Lower Tester, and the ErrorCode field
        # in the CrtData matches the Reason code value that the Upper Tester sent in step 9.
        await self.expect_llcp(
            source_address=controller.address,
            destination_address=peer_address,
            expected_pdu=llcp.CisTerminateInd(cig_id=cig_id,
                                              cis_id=cis_id,
                                              error_code=ErrorCode.REMOTE_USER_TERMINATED_CONNECTION))

        # 11. The Lower Tester sends an LL Ack to the IUT.
        # 12. The IUT sends an HCI_Disconnection_Complete event to the Upper Tester.
        await self.expect_evt(
            hci.DisconnectionComplete(status=ErrorCode.SUCCESS,
                                      connection_handle=cis_connection_handle,
                                      reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST))

        # 13. The Upper Tester sends an HCI_LE_Remove_CIG command to the IUT with CIG_ID set to the
        # value of the current inactive CIG.
        controller.send_cmd(hci.LeRemoveCig(cig_id=cig_id))

        # 14. The IUT sends an HCI_Command_Complete event to the Upper Tester with Status set to 0x00
        # and CIG_ID set to the CIG_ID value in step 13.
        await self.expect_evt(
            hci.LeRemoveCigComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1, cig_id=cig_id))

        # 15. The Upper Tester sends an HCI_LE_Set_CIG_Parameters command to the IUT with default
        # parameters but with Max_SDU_C_To_P set to 0 and receives a success response from the IUT
        # with CIS_Count = 1.
        controller.send_cmd(
            hci.LeSetCigParameters(cig_id=cig_id,
                                   sdu_interval_c_to_p=self.SDU_Interval_C_TO_P,
                                   sdu_interval_p_to_c=self.SDU_Interval_P_TO_C,
                                   worst_case_sca=self.Worst_Case_SCA,
                                   max_transport_latency_c_to_p=self.Max_Transport_Latency_C_TO_P,
                                   max_transport_latency_p_to_c=self.Max_Transport_Latency_P_TO_C,
                                   packing=self.Packing,
                                   framing=self.Framing,
                                   cis_config=[
                                       hci.CisParametersConfig(cis_id=cis_id,
                                                               max_sdu_c_to_p=0,
                                                               max_sdu_p_to_c=self.Max_SDU_P_TO_C,
                                                               phy_c_to_p=self.PHY_C_TO_P,
                                                               phy_p_to_c=self.PHY_P_TO_C,
                                                               rtn_c_to_p=self.RTN_C_TO_P,
                                                               rtn_p_to_c=self.RTN_P_TO_C)
                                   ]))

        await self.expect_evt(
            hci.LeSetCigParametersComplete(status=ErrorCode.SUCCESS,
                                           num_hci_command_packets=1,
                                           cig_id=cig_id,
                                           connection_handle=[cis_connection_handle]))

        # 16. The Upper Tester sends an HCI_LE_Create_CIS command to create a single CIS and receives a
        # success response from the IUT.
        controller.send_cmd(
            hci.LeCreateCis(cis_config=[
                hci.LeCreateCisConfig(cis_connection_handle=cis_connection_handle,
                                      acl_connection_handle=acl_connection_handle)
            ]))

        await self.expect_evt(hci.LeCreateCisStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 17. The IUT sends an LL_CIS_REQ PDU to the Lower Tester with all fields set to valid values.
        # 18. The value of Max_SDU_C_To_P and BN_C_To_P in the CrtData of the LL_CIS_REQ PDU are
        # verified to be equal to 0. The test fails if the values are not equal to 0.
        cis_req = await self.expect_llcp(source_address=controller.address,
                                         destination_address=peer_address,
                                         expected_pdu=llcp.CisReq(cig_id=cig_id,
                                                                  cis_id=cis_id,
                                                                  phy_c_to_p=hci.PhyType.LE_1M,
                                                                  phy_p_to_c=hci.PhyType.LE_1M,
                                                                  framed=self.Framing == hci.Enable.ENABLED,
                                                                  max_sdu_c_to_p=0,
                                                                  max_sdu_p_to_c=self.Max_SDU_P_TO_C,
                                                                  sdu_interval_c_to_p=self.Any,
                                                                  sdu_interval_p_to_c=self.Any,
                                                                  max_pdu_c_to_p=self.Any,
                                                                  max_pdu_p_to_c=self.Any,
                                                                  nse=self.Any,
                                                                  sub_interval=self.Any,
                                                                  bn_c_to_p=0,
                                                                  bn_p_to_c=self.Any,
                                                                  ft_c_to_p=self.Any,
                                                                  ft_p_to_c=self.Any,
                                                                  iso_interval=self.Any,
                                                                  cis_offset_min=self.Any,
                                                                  cis_offset_max=self.Any,
                                                                  conn_event_count=0))

        # 19. The Lower Tester sends an LL_CIS_RSP PDU to the IUT.
        controller.send_llcp(source_address=peer_address,
                             destination_address=controller.address,
                             pdu=llcp.CisRsp(cis_offset_min=cis_req.cis_offset_min,
                                             cis_offset_max=cis_req.cis_offset_max,
                                             conn_event_count=0))

        # 20. The IUT sends an LL_CIS_IND to the Lower Tester.
        cis_ind = await self.expect_llcp(source_address=controller.address,
                                         destination_address=peer_address,
                                         expected_pdu=llcp.CisInd(aa=0,
                                                                  cis_offset=self.Any,
                                                                  cig_sync_delay=self.Any,
                                                                  cis_sync_delay=self.Any,
                                                                  conn_event_count=0))

        # 21. The IUT sends an empty ISO Data Packet to the Lower Tester.
        # 22. The Lower Tester sends an LL Ack to the IUT.
        # 23. The IUT sends an HCI_LE_CIS_Established event to the Upper Tester. The Connection_Handle
        # parameter is set to the value provided in step 16.
        await self.expect_evt(
            hci.LeCisEstablished(status=ErrorCode.SUCCESS,
                                 connection_handle=cis_connection_handle,
                                 cig_sync_delay=cis_ind.cig_sync_delay,
                                 cis_sync_delay=cis_ind.cis_sync_delay,
                                 transport_latency_c_to_p=self.Any,
                                 transport_latency_p_to_c=self.Any,
                                 phy_c_to_p=hci.SecondaryPhyType.LE_1M,
                                 phy_p_to_c=hci.SecondaryPhyType.LE_1M,
                                 nse=cis_req.nse,
                                 bn_c_to_p=cis_req.bn_c_to_p,
                                 bn_p_to_c=cis_req.bn_p_to_c,
                                 ft_c_to_p=cis_req.ft_c_to_p,
                                 ft_p_to_c=cis_req.ft_p_to_c,
                                 max_pdu_c_to_p=cis_req.max_pdu_c_to_p,
                                 max_pdu_p_to_c=cis_req.max_pdu_p_to_c,
                                 iso_interval=cis_req.iso_interval))

        # 24. The Upper Tester sends an HCI_LE_Setup_ISO_Data_Path command to the IUT with
        # Connection_Handle set to the value provided in step 16 and Data_Path_Direction set to Output.
        controller.send_cmd(
            hci.LeSetupIsoDataPath(
                connection_handle=cis_connection_handle,
                data_path_direction=hci.DataPathDirection.OUTPUT,
                data_path_id=0,
                codec_id=0,
                controller_delay=0,
                codec_configuration=[],
            ))

        # 25. The IUT sends a successful HCI_Command_Complete event to the Upper Tester.
        await self.expect_evt(
            hci.LeSetupIsoDataPathComplete(status=ErrorCode.SUCCESS,
                                           num_hci_command_packets=1,
                                           connection_handle=cis_connection_handle))

        # 26. The IUT sends a CIS Null PDU to the Lower Tester.
        # 27. The Lower Tester sends an ISO Data Packet to the IUT.
        # 28. Repeat steps 26 and 27, 50 times.
        iso_sdu = [random.randint(1, 251) for n in range(self.Max_SDU_P_TO_C)]
        controller.send_ll(
            ll.LeConnectedIsochronousPdu(source_address=peer_address,
                                         destination_address=controller.address,
                                         cig_id=cig_id,
                                         cis_id=cis_id,
                                         sequence_number=42,
                                         data=iso_sdu))

        await self.expect_iso(
            hci.IsoWithoutTimestamp(
                connection_handle=cis_connection_handle,
                pb_flag=hci.IsoPacketBoundaryFlag.COMPLETE_SDU,
                iso_sdu_length=len(iso_sdu),
                packet_sequence_number=42,
                payload=iso_sdu,
            ))
