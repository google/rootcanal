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
ADV_NONCONN_IND = 0x10
ADV_EXT_IND = 0x0


@dataclass
class TestRound:
    duration: int
    advertising_event_properties: int
    target_address: Optional[Address]
    advertising_data_length: int


class Test(ControllerTest):

    # LL/DDI/SCN/BV-19-C  [Extended Scanning, Passive – LE 1M PHY]
    async def test(self):
        # Test rounds.
        # Note: some tests are skipped as no distinction is made between
        # ADV_EXT_IND, AUX_ADV_IND, AUX_CHAIN_IND.
        controller = self.controller
        invalid_address = Address("11:22:33:44:55:66")
        test_rounds = [
            TestRound(0x0, ADV_IND, None, 0),
            TestRound(0x0, ADV_IND, None, 31),
            TestRound(0x0, ADV_DIRECT_IND, controller.address, 0),
            TestRound(0x0, ADV_DIRECT_IND, invalid_address, 0),
            TestRound(0x0, ADV_NONCONN_IND, None, 0),
            TestRound(0x0, ADV_NONCONN_IND, None, 31),
            TestRound(0x0, ADV_EXT_IND, None, 0),
            TestRound(0x0, ADV_EXT_IND, controller.address, 0),
            TestRound(0x0, ADV_EXT_IND, invalid_address, 0),
            TestRound(0x0, ADV_EXT_IND, None, 191),
            TestRound(0x0, ADV_EXT_IND, None, 382),
            TestRound(0x1f4, ADV_EXT_IND, controller.address, 0),
            TestRound(0x0, ADV_EXT_IND, None, 31),
            TestRound(0x0, ADV_EXT_IND, None, 1645),
        ]

        # 7. Repeat steps 1–5 for each Round shown in Table 4.30
        for test_round in test_rounds:
            await self.steps_1_6(**vars(test_round))

    async def steps_1_6(self, duration: int, advertising_event_properties: int, target_address: Optional[Address],
                        advertising_data_length: int):

        controller = self.controller
        lower_tester_address = Address("ca:fe:ca:fe:00:01")

        # 1. The Upper Tester sends an HCI_LE_Set_Extended_Scan_Parameters_Command to the IUT.
        # The Scanning_PHYs parameter shall be set as specified in Table 4.29, Scan_Type[0] set to 0x00
        # (Passive Scanning), Scan_Interval[0] set to 0x0010, and Scan_Window[0] set to 0x0010.
        # Own_Address_Type shall be set to 0x00 (Public Device Address), and Scanning_Filter_Policy
        # shall be set to 0x00 (Accept All).
        controller.send_cmd(
            hci.LeSetExtendedScanParameters(own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                            scanning_filter_policy=hci.LeScanningFilterPolicy.ACCEPT_ALL,
                                            scanning_phys=0x1,
                                            scanning_phy_parameters=[
                                                hci.ScanningPhyParameters(le_scan_type=hci.LeScanType.PASSIVE,
                                                                          le_scan_interval=0x0010,
                                                                          le_scan_window=0x0010)
                                            ]))

        await self.expect_evt(
            hci.LeSetExtendedScanParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 2. The Upper Tester sends an HCI_LE_Set_Extended_Scan_Enable command to the IUT to enable
        # scanning. Filter_Duplicates and Period shall be set to zero. The Duration parameter shall be set
        # to the value specified in Table 4.30 for this round.
        controller.send_cmd(
            hci.LeSetExtendedScanEnable(enable=hci.Enable.ENABLED,
                                        filter_duplicates=hci.Enable.DISABLED,
                                        duration=duration,
                                        period=0))

        await self.expect_evt(hci.LeSetExtendedScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 3. The Lower Tester begins advertising using the PDU Type specified in Table 4.30 for this round. If
        # AUX_ADV_IND is included in the round, the ADV_EXT_IND shall include an AuxPtr that refers to
        # the AUX_ADV_IND, and all fields specified should be included with the AUX_ADV_IND only. If
        # AdvA is specified the appropriate PDU shall include the field, where “LT” equals the Lower Tester
        # address. If InitA/TargetA is specified the appropriate PDU shall include the field, where “IUT”
        # equals the IUT address and “Not IUT” equals a random address other than the IUT address. If
        # AdvData is specified the PDU shall include the field populated with random octets of the specified
        # count. If the AdvData is greater in length than will fit in one PDU, the Lower Tester shall include
        # an AuxPtr field and send one or more AUX_CHAIN_IND PDUs containing the remaining data.
        # Each PDU except the last shall contain as much AdvData as can fit. If Duration is set to 0x0000,
        # repeat for at least 20 advertising intervals, otherwise repeat until the end of the round.
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

        # 4. For undirected advertisements or advertisements directed at the IUT, the Upper Tester receives
        # one or more HCI_LE_Extended_Advertising_Report events from the IUT with an advertising
        # event type matching the type sent in step 3 and the Primary_PHY set as specified in Table 4.29,
        # and if the advertisements used extended PDUs, the Secondary_PHY shall be set as specified in
        # Table 4.29. If AdvData was included in the advertisement, the Upper Tester receives the data
        # included in one or more of the advertising packets. If AdvData is sent to the Upper Tester in
        # multiple reports, the Data Status in the Event_Type field for each report except the last is set to
        # “Incomplete, more data to come”, 0b01. The Event_Type field for the last report sent with
        # advertisement data is set to “Complete”, 0b00. If the advertisement was directed at the IUT, the
        # Upper Tester receives the Direct Address Type and Direct Address used to direct the
        # advertisement at the IUT.
        for n in range(3):
            advertising_data = [random.randint(1, 254) for n in range(advertising_data_length)]
            pdu.advertising_data = advertising_data

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

            offset = 0
            max_fragment_length = 229
            num_fragments = math.ceil(advertising_data_length / max_fragment_length) or 1
            for n in range(num_fragments):
                remaining_length = advertising_data_length - offset
                fragment_length = min(max_fragment_length, remaining_length)
                data_status = hci.DataStatus.CONTINUING if remaining_length > max_fragment_length else hci.DataStatus.COMPLETE
                await self.expect_evt(
                    hci.LeExtendedAdvertisingReport(responses=[
                        hci.LeExtendedAdvertisingResponse(
                            connectable=connectable,
                            scannable=scannable,
                            directed=not target_address is None,
                            scan_response=False,
                            legacy=legacy,
                            data_status=data_status,
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
                            advertising_data=advertising_data[offset:offset + fragment_length])
                    ]))
                offset += fragment_length

        if duration > 0:
            # 5. If the Duration was set to 0x0000 (No Scanning Duration), repeat step 4 until a number of
            # advertising reports (10) have been generated. Each time the Upper Tester receives a report, the
            # Lower Tester shall change the AdvData, if any. If the round uses extended advertising PDUs, it
            # shall also change the DID sub-field of the ADI field to a new value.
            # Otherwise repeat step 4 until the amount of time specified for Duration has elapsed. Afterwards,
            # the Upper Tester receives an HCI_Scan_Timeout event from the IUT. Skip step 6.
            timeout = duration * 100 + 10
            await self.expect_evt(hci.LeScanTimeout(), timeout=timeout)

        else:
            # 6. Upper Tester sends an HCI_LE_Set_Scan_Enable to the IUT to disable scanning and receives
            # an HCI_Command_Complete event in response.
            controller.send_cmd(hci.LeSetExtendedScanEnable(enable=hci.Enable.DISABLED))

            await self.expect_evt(
                hci.LeSetExtendedScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
