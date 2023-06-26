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

    # LL/CIS/CEN/BV-03-C [CIS Setup Procedure, Central Initiated, Rejected]
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

        # 1. The Upper Tester sends an HCI_LE_Set_CIG_Parameters command to the IUT with valid
        # parameters and receives a successful HCI_Command_Complete event.
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
                                           hci.LeCisParametersTestConfig(cis_id=cis_id,
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
                                               connection_handle=[cis_connection_handle]))

        # 2. The Upper Tester sends an HCI_LE_Create_CIS command with the ACL_Connection_Handle of
        # the established ACL and valid Connection_Handle from the IUT received in step 1.
        controller.send_cmd(
            hci.LeCreateCis(cis_config=[
                hci.LeCreateCisConfig(cis_connection_handle=cis_connection_handle,
                                      acl_connection_handle=acl_connection_handle)
            ]))

        await self.expect_evt(hci.LeCreateCisStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. The Lower Tester receives an LL_CIS_REQ PDU from the IUT with all fields set to valid values.
        cis_req = await self.expect_llcp(source_address=controller.address,
                                         destination_address=peer_address,
                                         expected_pdu=llcp.CisReq(cig_id=cig_id,
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
                                                                  sub_interval=self.Any,
                                                                  bn_p_to_c=self.BN_C_TO_P,
                                                                  bn_c_to_p=self.BN_P_TO_C,
                                                                  ft_c_to_p=self.FT_C_TO_P,
                                                                  ft_p_to_c=self.FT_P_TO_C,
                                                                  iso_interval=self.ISO_Interval,
                                                                  cis_offset_min=self.Any,
                                                                  cis_offset_max=self.Any,
                                                                  conn_event_count=0))

        # 4. The Lower Tester sends an LL_REJECT_EXT_IND to the IUT with an error code not equal to 0x00.
        controller.send_llcp(source_address=peer_address,
                             destination_address=controller.address,
                             pdu=llcp.RejectExtInd(reject_opcode=llcp.Opcode.LL_CIS_REQ,
                                                   error_code=hci.ErrorCode.REMOTE_USER_TERMINATED_CONNECTION))

        # 5. The Upper Tester receives an HCI_LE_CIS_Established event from the IUT with a status failure.
        # The Status field has the same value as the LL_REJECT_EXT_IND PDU in step 4.
        await self.expect_evt(
            hci.LeCisEstablished(status=ErrorCode.REMOTE_USER_TERMINATED_CONNECTION,
                                 connection_handle=cis_connection_handle))
