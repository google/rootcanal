# Copyright 2024 Google LLC
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
import math
import random
from dataclasses import dataclass
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest
from typing import Optional

ADV_IND = 0x13
ADV_DIRECT_IND = 0x15
ADV_SCAN_IND = 0x12
ADV_EXT_IND = 0x02


@dataclass
class TestRound:
    advertising_event_properties: int
    target_address: Optional[Address]
    scan_data_length: int


class Test(ControllerTest):

    # LL/DDI/SCN/BV-20-C  [Extended Scanning, Active – LE 1M PHY, Core 5.0]
    #
    # Verify that a scanner IUT detects and requests additional information from
    # advertisements received and reports the results from the Controller. The
    # Lower Tester advertises using scannable extended advertising events on one
    # channel at a time and expects the IUT to report the advertising to the
    # Upper Tester. Both directed and undirected advertising events are tested.
    async def test(self):
        # Test rounds.
        # Note: some tests are skipped as no distinction is made between
        # ADV_EXT_IND, AUX_ADV_IND, AUX_CHAIN_IND.
        controller = self.controller
        invalid_address = Address("11:22:33:44:55:66")
        test_rounds = [
            TestRound(ADV_IND, None, 0),
            TestRound(ADV_IND, None, 31),
            TestRound(ADV_SCAN_IND, None, 0),
            TestRound(ADV_SCAN_IND, None, 31),
            TestRound(ADV_EXT_IND, None, 1),
            TestRound(ADV_EXT_IND, controller.address, 1),
            TestRound(ADV_EXT_IND, invalid_address, 1),
            TestRound(ADV_EXT_IND, None, 191),
            TestRound(ADV_EXT_IND, None, 382),
            TestRound(ADV_EXT_IND, None, 1647),
        ]

        # 1. For each round as specified in Table 4.2-35 based on Table 4.2-36, if ScanData Length is less
        # than or equal to the “Scan Max Data” then perform steps 2–8 and otherwise omit this round.
        for test_round in test_rounds:
            await self.steps_2_8(**vars(test_round))

    async def steps_2_8(self, advertising_event_properties: int, target_address: Optional[Address],
                        scan_data_length: int):

        controller = self.controller
        lower_tester_address = Address("ca:fe:ca:fe:00:01")

        # 2. The Upper Tester sends an HCI_LE_Set_Extended_Scan_Parameters command to the IUT. The
        # Scanning_PHYs parameter is set as specified in Table 4.2-35, Scan_Type[0] set to 0x01 (Active
        # Scanning), Scan_Interval[0] set to 0x0010, and Scan_Window[0] set to 0x0010.
        # Own_Address_Type is set to 0x00 (Public Device Address), and Scanning_Filter_Policy is set to
        # 0x00 (Accept All) and receives a successful HCI_Command_Complete.
        controller.send_cmd(
            hci.LeSetExtendedScanParameters(own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                            scanning_filter_policy=hci.LeScanningFilterPolicy.ACCEPT_ALL,
                                            scanning_phys=0x1,
                                            scanning_phy_parameters=[
                                                hci.ScanningPhyParameters(le_scan_type=hci.LeScanType.ACTIVE,
                                                                          le_scan_interval=0x0010,
                                                                          le_scan_window=0x0010)
                                            ]))

        await self.expect_evt(
            hci.LeSetExtendedScanParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. The Upper Tester sends an HCI_LE_Set_Extended_Scan_Enable command to the IUT to enable
        # scanning. Filter_Duplicates, Duration, and Period are all set to zero and receive a successful
        # HCI_Command_Complete.
        controller.send_cmd(
            hci.LeSetExtendedScanEnable(enable=hci.Enable.ENABLED,
                                        filter_duplicates=hci.Enable.DISABLED,
                                        duration=0,
                                        period=0))

        await self.expect_evt(hci.LeSetExtendedScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. The Lower Tester begins advertising on the channel as specified in Table 4.2-35 using the PDU
        # Type specified in Table 4.2-36 for this round. If AUX_ADV_IND is included in the round, the
        # ADV_EXT_IND includes an AuxPtr that refers to the AUX_ADV_IND on the PHY as specified in
        # Table 4.2-35, and all fields specified should be included with the AUX_ADV_IND only. If AdvA is
        # specified, the appropriate PDU includes the field, where “LT” equals the Lower Tester address. If
        # TargetA is specified, the appropriate PDU includes the field, where “IUT” equals the IUT address
        # and “Not IUT” equals a random address other than the IUT address. Repeat for at least 20
        # advertising intervals or until step 5 occurs.
        connectable = (advertising_event_properties & 0x1) != 0
        scannable = (advertising_event_properties & 0x2) != 0
        directed = (advertising_event_properties & 0x4) != 0
        high_duty_cycle = (advertising_event_properties & 0x8) != 0
        legacy = (advertising_event_properties & 0x10) != 0

        if legacy:
            if advertising_event_properties == ADV_IND:
                advertising_type = ll.LegacyAdvertisingType.ADV_IND
            elif advertising_event_properties == ADV_DIRECT_IND:
                advertising_type = ll.LegacyAdvertisingType.ADV_DIRECT_IND
            elif advertising_event_properties == ADV_SCAN_IND:
                advertising_type = ll.LegacyAdvertisingType.ADV_SCAN_IND
            elif advertising_event_properties == ADV_NONCONN_IND:
                advertising_type = ll.LegacyAdvertisingType.ADV_NONCONN_IND
            pdu = ll.LeLegacyAdvertisingPdu(source_address=lower_tester_address,
                                            destination_address=target_address or Address(),
                                            advertising_address_type=ll.AddressType.PUBLIC,
                                            target_address_type=ll.AddressType.PUBLIC,
                                            advertising_type=advertising_type,
                                            advertising_data=[])
        else:
            pdu = ll.LeExtendedAdvertisingPdu(source_address=lower_tester_address,
                                              destination_address=target_address or Address(),
                                              advertising_address_type=ll.AddressType.PUBLIC,
                                              target_address_type=ll.AddressType.PUBLIC,
                                              connectable=connectable,
                                              scannable=scannable,
                                              directed=not target_address is None,
                                              sid=0,
                                              tx_power=0x7f,
                                              primary_phy=ll.PrimaryPhyType.LE_1M,
                                              secondary_phy=ll.SecondaryPhyType.NO_PACKETS,
                                              advertising_data=[])

        # 5. For undirected advertisements or advertisements directed at the IUT, the Lower Tester receives
        # either a SCAN_REQ (if advertising with legacy PDUs) or an AUX_SCAN_REQ (if advertising with
        # extended PDUs) on the appropriate advertising channel. The ScanA field is set to the IUT’s
        # address, and the AdvA address is set to the Lower Tester’s address. The Upper Tester receives
        # an HCI_LE_Extended_Advertising_Report event from the IUT with an Event_Type where bit 3
        # (Scan response) is not set, the Data Status in the Event_Type field is set to Complete (0b00),
        # Periodic_Advertising_Interval is set to 0, and no advertising data. If the advertisements were
        # directed but TargetA is not the IUT, skip to step 8.
        for n in range(3):
            if not legacy:
                sid = random.randint(0, 15)
                pdu.sid = sid
            else:
                sid = 0xff

            controller.send_ll(pdu, rssi=0)

            if target_address and target_address != controller.address:
                # If the controller still emits an event, the error
                # will appear in the subsequent rounds.
                continue

            await self.expect_evt(
                hci.LeExtendedAdvertisingReport(responses=[
                    hci.LeExtendedAdvertisingResponse(
                        connectable=connectable,
                        scannable=scannable,
                        directed=not target_address is None,
                        scan_response=False,
                        legacy=legacy,
                        data_status=hci.DataStatus.COMPLETE,
                        address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                        address=lower_tester_address,
                        primary_phy=hci.PrimaryPhyType.LE_1M,
                        secondary_phy=hci.SecondaryPhyType.NO_PACKETS,
                        advertising_sid=sid,
                        tx_power=0x7f,
                        rssi=0,
                        periodic_advertising_interval=0,
                        direct_address_type=hci.DirectAdvertisingAddressType.NO_ADDRESS_PROVIDED
                        if not target_address else hci.DirectAdvertisingAddressType.PUBLIC_DEVICE_ADDRESS,
                        direct_address=target_address or Address(),
                        advertising_data=[])
                ]))

            await self.expect_ll(
                ll.LeScan(source_address=controller.address,
                          destination_address=lower_tester_address,
                          scanning_address_type=ll.AddressType.PUBLIC,
                          advertising_address_type=ll.AddressType.PUBLIC))

            advertising_data = [random.randint(1, 254) for n in range(scan_data_length)]

            # 6. Perform step 6A or 6B depending on the PDU sent by the IUT in step 5.
            # Alternative 6A (The IUT sent a SCAN_REQ in step 5):
            # 6A.1 The Lower Tester responds with a SCAN_RSP packet to the IUT T_IFS after the end
            # of the SCAN_REQ PDU. If ScanData is specified, the SCAN_RSP PDU includes the
            # field populated with random octets from 1 to 254 of the specified count.
            # Alternative 6B (The IUT sent an AUX_SCAN_REQ in step 5):
            # 6B.1 The Lower Tester responds with an AUX_SCAN_RSP packet to the IUT T_IFS after
            # the end of the AUX_SCAN_REQ PDU with an AdvMode of 0b00. If ScanData is
            # specified, the AUX_SCAN_RSP PDU includes the AdvData field populated with
            # random octets from 1 to 254 of the specified count. If the ScanData is greater in
            # length than will fit in one PDU, the Lower Tester includes an AuxPtr field and sends
            # one or more AUX_CHAIN_IND PDUs containing the remaining data. Each PDU
            # except the last contains as much AdvData as can fit.
            controller.send_ll(ll.LeScanResponse(source_address=lower_tester_address,
                                                 destination_address=controller.address,
                                                 advertising_address_type=ll.AddressType.PUBLIC,
                                                 scan_response_data=advertising_data),
                               rssi=0)

            # 7. If the Lower Tester sent a scan response in step 6, the Upper Tester receives one or more
            # HCI_LE_Extended_Advertising_Report events from the IUT with an Event_Type where bit 3
            # (Scan response) is set, and Periodic_Advertising_Interval is set to 0. If ScanData was included in
            # the response, the Upper Tester receives the data included in one of the advertising packets. If
            # ScanData is sent to the Upper Tester in multiple reports, the Data Status in the Event_Type field
            # for each report except the last is set to “Incomplete, more data to come”, 0b01. The Event_Type
            # field for the last report sent with advertisement data is set to “Complete”, 0b00.
            offset = 0
            max_fragment_length = 229
            num_fragments = math.ceil(scan_data_length / max_fragment_length) or 1

            for n in range(num_fragments):
                remaining_length = scan_data_length - offset
                fragment_length = min(max_fragment_length, remaining_length)
                data_status = hci.DataStatus.CONTINUING if remaining_length > max_fragment_length else hci.DataStatus.COMPLETE
                await self.expect_evt(
                    hci.LeExtendedAdvertisingReport(responses=[
                        hci.LeExtendedAdvertisingResponse(
                            connectable=connectable,
                            scannable=scannable,
                            directed=False,
                            scan_response=True,
                            legacy=legacy,
                            data_status=data_status,
                            address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                            address=lower_tester_address,
                            primary_phy=hci.PrimaryPhyType.LE_1M,
                            secondary_phy=hci.SecondaryPhyType.NO_PACKETS,
                            # TODO SID should be set in scan response PDU
                            advertising_sid=0xff,
                            tx_power=0x7f,
                            rssi=0,
                            periodic_advertising_interval=0,
                            direct_address_type=hci.DirectAdvertisingAddressType.NO_ADDRESS_PROVIDED,
                            direct_address=Address(),
                            advertising_data=advertising_data[offset:offset + fragment_length])
                    ]))
                offset += fragment_length

        # 8. The Upper Tester sends an HCI_LE_Set_Scan_Enable to the IUT to disable scanning and
        # receives an HCI_Command_Complete event in response.
        controller.send_cmd(hci.LeSetExtendedScanEnable(enable=hci.Enable.DISABLED))

        await self.expect_evt(hci.LeSetExtendedScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
