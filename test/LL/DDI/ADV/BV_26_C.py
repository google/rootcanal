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

import asyncio
import hci_packets as hci
import link_layer_packets as ll
import math
import random
import unittest
from dataclasses import dataclass
from hci_packets import ErrorCode, FragmentPreference
from py.bluetooth import Address
from py.controller import ControllerTest
from typing import List


@dataclass
class TestRound:
    data_length: int


class Test(ControllerTest):
    # Test parameters.
    LL_advertiser_advInterval_MIN = 0x200
    LL_advertiser_advInterval_MAX = 0x200
    LL_advertiser_Adv_Channel_Map = 0x7
    LL_initiator_connInterval = 0x200
    LL_initiator_connPeripheralLatency = 0x200
    LL_initiator_connSupervisionTimeout = 0x200

    # LL/DDI/ADV/BV-26-C [Extended Advertising, Periodic Advertising – LE 1M PHY]
    async def test(self):
        controller = self.controller

        if not controller.le_features.le_periodic_advertising:
            self.skipTest("LE periodic advertising not supported")

        # 1. The Upper Tester sends an HCI_LE_Read_Maximum_Advertising_Data_Length command to the
        # IUT and receives a Maximum_Advertising_Data_Length between 0x001F and 0x0672 in return.
        # The Upper Tester stores the Maximum_Advertising_Data_Length for future use.
        # For each round from 1–6 based on Table 4.10.
        controller.send_cmd(hci.LeReadMaximumAdvertisingDataLength())

        event = await self.expect_cmd_complete(hci.LeReadMaximumAdvertisingDataLengthComplete)
        maximum_advertising_data_length = event.maximum_advertising_data_length

        # Test rounds.
        test_rounds = [
            TestRound(0),
            TestRound(252),
            TestRound(474),
            TestRound(711),
            TestRound(948),
            TestRound(maximum_advertising_data_length),
        ]

        # 17. Repeat steps 2–16 for each Round shown in Table 4.10.
        for test_round in test_rounds:
            await self.steps_2_16(maximum_advertising_data_length, **vars(test_round))

    async def steps_2_16(self, maximum_advertising_data_length: int, data_length: int):
        controller = self.controller

        # 2. If the Data Length listed in Table 4.10 for the current Round is less than or equal to the
        # Maximum_Advertising_Data_Length proceed to step 3, otherwise skip to step 17.
        if data_length > maximum_advertising_data_length:
            return

        # 3. The Upper Tester sends an HCI_LE_Set_Extended_Advertising_Parameters command to the
        # IUT using all supported advertising channels and a selected advertising interval between the
        # minimum and maximum advertising intervals supported. Advertising_Event_Properties parameter
        # shall be set to 0x0000. The Primary_Advertising_PHY and Secondary_Advertising_PHY shall be
        # set to the values specified in Table 4.9.
        controller.send_cmd(
            hci.LeSetExtendedAdvertisingParameters(advertising_handle=0,
                                                   advertising_event_properties=hci.AdvertisingEventProperties(),
                                                   primary_advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                                                   primary_advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                                                   primary_advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                                                   own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                                   advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES,
                                                   primary_advertising_phy=hci.PrimaryPhyType.LE_1M))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. The Upper Tester sends an HCI_LE_Set_Periodic_Advertising_Parameters command to the IUT
        # using all supported advertising channels and selected periodic interval.
        # Periodic_Advertising_Properties parameter shall be set to 0x0000.
        controller.send_cmd(
            hci.LeSetPeriodicAdvertisingParameters(advertising_handle=0,
                                                   periodic_advertising_interval_min=0x100,
                                                   periodic_advertising_interval_max=0x100,
                                                   include_tx_power=False))

        await self.expect_evt(
            hci.LeSetPeriodicAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 5. The Upper Tester sends one or more HCI_LE_Set_Periodic_Advertising_Data commands to the
        # IUT with values according to Table 4.10 and using random octets from 1 to 254 as the payload. If
        # the Data Length is greater than 252 the Upper Tester shall send multiple commands using one
        # Operation 0x01 (First fragment) command, followed by zero or more Operation 0x00
        # (Intermediate Fragment) commands, and a final Operation 0x02 (Last fragment) command.
        # Otherwise the Upper Tester shall send a single command using Operation 0x03 (Complete Data).
        advertising_data = [random.randint(1, 254) for n in range(data_length)]
        num_fragments = math.ceil(data_length / 251) or 1  # Make sure to set the advertising data if it is empty.
        for n in range(num_fragments):
            fragment_offset = 251 * n
            fragment_length = min(251, data_length - fragment_offset)
            if num_fragments == 1:
                operation = hci.Operation.COMPLETE_ADVERTISEMENT
            elif n == 0:
                operation = hci.Operation.FIRST_FRAGMENT
            elif n == num_fragments - 1:
                operation = hci.Operation.LAST_FRAGMENT
            else:
                operation = hci.Operation.INTERMEDIATE_FRAGMENT

            controller.send_cmd(
                hci.LeSetPeriodicAdvertisingData(advertising_handle=0,
                                                 operation=operation,
                                                 advertising_data=advertising_data[fragment_offset:fragment_offset +
                                                                                   fragment_length]))

            await self.expect_evt(
                hci.LeSetPeriodicAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 6. The Upper Tester enables periodic advertising using the
        # HCI_LE_Set_Periodic_Advertising_Enable command with the Enable parameter set to 0x01
        # (Periodic Advertising).
        controller.send_cmd(hci.LeSetPeriodicAdvertisingEnable(enable=True, include_adi=False, advertising_handle=0))

        await self.expect_evt(
            hci.LeSetPeriodicAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # Note: no periodic advertising event is expected until extended
        # advertising is also enabled for the advertising set.

        # 7. The Upper Tester enables advertising using the HCI_LE_Set_Extended_Advertising_Enable
        # command. The Duration[0] parameter is set to 0x0000 (No Advertising Duration).
        controller.send_cmd(
            hci.LeSetExtendedAdvertisingEnable(
                enable=hci.Enable.ENABLED,
                enabled_sets=[hci.EnabledSet(advertising_handle=0, duration=0, max_extended_advertising_events=0)]))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 8. The Lower Tester receives an ADV_EXT_IND packet from the IUT with AdvMode set to 00b with
        # the AuxPtr Extended Header field present.

        # 9. The Lower Tester utilizes the AuxPtr field to listen for an AUX_ADV_IND PDU on the secondary
        # advertising channel with the AdvMode field set to 00b and the SyncInfo Extended Header fields
        # present.

        # 10. The Lower Tester utilizes the SyncInfo field to listen for an AUX_SYNC_IND PDU on the
        # secondary advertising channel using the index selected by the LE Channel Selection Algorithm
        # #2 and synchronizes with the periodic advertisements. The AUX_SYNC_IND PDU shall have the
        # AdvMode field set to 00b with no ADI field. If the AUX_SYNC_IND PDU AdvData field does not
        # contain all the data submitted in step 5 (if any), it shall include an AuxPtr field.

        # 11. If the AUX_SYNC_IND PDU contains an AuxPtr field, the Lower Tester utilizes it to listen for an
        # AUX_CHAIN_IND PDU with the AdvMode field set to 00b and containing additional data
        # submitted in step 5. If the AUX_CHAIN_IND PDU contains an AuxPtr field this step is repeated
        # until an AUX_CHAIN_IND PDU is received with no AuxPtr field and all data has been received.

        # 12. Repeat steps 8–11 100 times.
        received_extended_advertising_pdus = 0
        received_periodic_advertising_pdus = 0
        for n in range(15):
            pdu = await self.expect_ll([
                ll.LeExtendedAdvertisingPdu(source_address=controller.address,
                                            advertising_address_type=ll.AddressType.PUBLIC,
                                            target_address_type=ll.AddressType.PUBLIC,
                                            connectable=False,
                                            scannable=False,
                                            directed=False,
                                            sid=0,
                                            tx_power=0,
                                            primary_phy=ll.PrimaryPhyType.LE_1M,
                                            secondary_phy=ll.SecondaryPhyType.NO_PACKETS,
                                            periodic_advertising_interval=0x100,
                                            advertising_data=[]),
                ll.LePeriodicAdvertisingPdu(source_address=controller.address,
                                            advertising_address_type=ll.AddressType.PUBLIC,
                                            sid=0,
                                            tx_power=0,
                                            advertising_interval=0x100,
                                            advertising_data=advertising_data)
            ])
            if isinstance(pdu, ll.LeExtendedAdvertisingPdu):
                received_extended_advertising_pdus += 1
            if isinstance(pdu, ll.LePeriodicAdvertisingPdu):
                received_periodic_advertising_pdus += 1

        # Note: the extended advertising interval is twice the periodic
        # advertising interval; the number of events received of each kind is
        # deterministic.
        self.assertTrue(received_extended_advertising_pdus == 5)
        self.assertTrue(received_periodic_advertising_pdus == 10)

        # 13. The Upper Tester disables extended advertising using the
        # HCI_LE_Set_Extended_Advertising_Enable command but maintains periodic advertising.
        controller.send_cmd(hci.LeSetExtendedAdvertisingEnable(enable=hci.Enable.DISABLED, enabled_sets=[]))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 14. The Lower Tester confirms that periodic advertising continues when extended advertising is
        # disabled by repeating steps 10–11 100 times.
        for n in range(10):
            await self.expect_ll(
                ll.LePeriodicAdvertisingPdu(source_address=controller.address,
                                            advertising_address_type=ll.AddressType.PUBLIC,
                                            sid=0,
                                            tx_power=0,
                                            advertising_interval=0x100,
                                            advertising_data=advertising_data))

        # 15. The Upper Tester disables periodic advertising using the
        # HCI_LE_Set_Periodic_Advertising_Enable command.
        controller.send_cmd(hci.LeSetPeriodicAdvertisingEnable(enable=False, include_adi=False, advertising_handle=0))

        await self.expect_evt(
            hci.LeSetPeriodicAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 16. The Upper Tester clears the advertising configuration using the HCI_LE_Clear_Advertising_Sets
        # command.
        controller.send_cmd(hci.LeClearAdvertisingSets())

        await self.expect_evt(hci.LeClearAdvertisingSetsComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
