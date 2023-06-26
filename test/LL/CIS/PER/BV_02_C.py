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
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    SDU_Interval_C_TO_P = 10000  # 7.5ms
    SDU_Interval_P_TO_C = 10000  # 7.5ms
    ISO_Interval = 20000  # 7.5ms
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

    # LL/CIS/PER/BV-02-C [CIS Setup Response Procedure, Peripheral, Reject Response]
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
                                             sub_interval=0,
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

        # 4. The Upper Tester sends an HCI_LE_Reject_CIS_Request command to the IUT with a valid
        # reason code and receives a successful return status
        controller.send_cmd(
            hci.LeRejectCisRequest(connection_handle=cis_connection_handle,
                                   reason=ErrorCode.CONNECTION_REJECTED_LIMITED_RESOURCES))

        # 5. The Upper Tester receives an HCI_Command_Complete event from the IUT
        await self.expect_evt(
            hci.LeRejectCisRequestComplete(status=ErrorCode.SUCCESS,
                                           num_hci_command_packets=1,
                                           connection_handle=cis_connection_handle))

        # 6. The Lower Tester receives an LL_REJECT_EXT_IND from the IUT with a valid reason code.
        await self.expect_llcp(source_address=controller.address,
                               destination_address=peer_address,
                               expected_pdu=llcp.RejectExtInd(
                                   reject_opcode=llcp.Opcode.LL_CIS_REQ,
                                   error_code=ErrorCode.CONNECTION_REJECTED_LIMITED_RESOURCES))
