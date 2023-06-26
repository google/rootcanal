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


def make_advertising_event_properties(properties: int) -> hci.AdvertisingEventProperties:
    return hci.AdvertisingEventProperties(connectable=(properties & 0x1) != 0,
                                          scannable=(properties & 0x2) != 0,
                                          directed=(properties & 0x4) != 0,
                                          high_duty_cycle=(properties & 0x8) != 0,
                                          legacy=(properties & 0x10) != 0,
                                          anonymous=(properties & 0x20) != 0,
                                          tx_power=(properties & 0x40) != 0)


@dataclass
class TestRound:
    advertising_event_properties: int
    data_length: int
    fragment_preference: FragmentPreference
    duration: int
    max_extended_advertising_events: int


class Test(ControllerTest):
    # Test parameters.
    LL_advertiser_advInterval_MIN = 0x200
    LL_advertiser_advInterval_MAX = 0x200
    LL_advertiser_Adv_Channel_Map = 0x7
    LL_initiator_connInterval = 0x200
    LL_initiator_connPeripheralLatency = 0x200
    LL_initiator_connSupervisionTimeout = 0x200

    # LL/DDI/ADV/BV-47-C [Extended Advertising, Non-Connectable – LE 1M PHY]
    async def test(self):
        controller = self.controller

        # 1. The Upper Tester sends an HCI_LE_Read_Maximum_Advertising_Data_Length command to the
        # IUT and expects the IUT to return a Maximum_Advertising_Data_Length between 0x001F and
        # 0x0672. The Upper Tester stores the Maximum_Advertising_Data_Length for future use.
        controller.send_cmd(hci.LeReadMaximumAdvertisingDataLength())

        event = await self.expect_cmd_complete(hci.LeReadMaximumAdvertisingDataLengthComplete)
        maximum_advertising_data_length = event.maximum_advertising_data_length

        # Test rounds.
        test_rounds = [
            TestRound(0x0, 0, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x0, 31, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x0, 474, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x0, 711, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x0, 948, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x0, maximum_advertising_data_length, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x0, maximum_advertising_data_length, FragmentPreference.CONTROLLER_SHOULD_NOT, 0x0, 0x0),
            TestRound(0x4, 0, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x4, 251, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x4, maximum_advertising_data_length, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x0),
            TestRound(0x0, 0, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x1f4, 0x0),
            TestRound(0x4, 0, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x1f4, 0x0),
            TestRound(0x0, 0, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x32),
            TestRound(0x4, 0, FragmentPreference.CONTROLLER_MAY_FRAGMENT, 0x0, 0x32),
        ]

        # 14. Repeat steps 2–13 for each Round shown in Table 4.6
        for test_round in test_rounds:
            await self.steps_2_13(maximum_advertising_data_length, **vars(test_round))

    async def steps_2_13(self, maximum_advertising_data_length: int, advertising_event_properties: int,
                         data_length: int, fragment_preference: FragmentPreference, duration: int,
                         max_extended_advertising_events: int):
        controller = self.controller
        advertising_event_properties = make_advertising_event_properties(advertising_event_properties)

        # 2. If the Data Length listed in Table 4.6 for the current Round is less than or equal to the
        # Maximum_Advertising_Data_Length proceed to step 3, otherwise skip to step 14.
        if data_length > maximum_advertising_data_length:
            return

        # 3. The Upper Tester sends an HCI_LE_Set_Extended_Advertising_Parameters command to the
        # IUT using all supported advertising channels and a selected advertising interval between the
        # minimum and maximum advertising intervals supported. Advertising_Event_Properties parameter
        # shall be set to the value specified in Table 4.6 for this round. The Primary_Advertising_PHY and
        # Secondary_Advertising_PHY shall be set to the values specified in Table 4.5. If the
        # Advertising_Event_Properties value for this Round specifies directed advertising, the
        # Peer_Address_Type shall be set to 0x00 (Public Device Address), and the Peer_Address shall be
        # set to the Lower Tester’s address.
        controller.send_cmd(
            hci.LeSetExtendedAdvertisingParameters(advertising_handle=0,
                                                   advertising_event_properties=advertising_event_properties,
                                                   primary_advertising_interval_min=self.LL_advertiser_advInterval_MIN,
                                                   primary_advertising_interval_max=self.LL_advertiser_advInterval_MAX,
                                                   primary_advertising_channel_map=self.LL_advertiser_Adv_Channel_Map,
                                                   own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                                                   advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES,
                                                   primary_advertising_phy=hci.PrimaryPhyType.LE_1M))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingParametersComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 4. The Upper Tester sends one or more HCI_LE_Set_Extended_Advertising_Data commands to the
        # IUT with values according to Table 4.6 and using random octets from 1 to 254 as the payload. If
        # the Data Length is greater than 251 the Upper Tester shall send multiple commands using one
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
                hci.LeSetExtendedAdvertisingData(advertising_handle=0,
                                                 operation=operation,
                                                 advertising_data=advertising_data[fragment_offset:fragment_offset +
                                                                                   fragment_length]))

            await self.expect_evt(
                hci.LeSetExtendedAdvertisingDataComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 5. The Upper Tester enables advertising using the HCI_LE_Set_Extended_Advertising_Enable
        # command. The Duration[0] parameter shall be set to the value specified in Table 4.6 for this
        # round. The Max_Extended_Advertising_Events[0] parameter shall be set to the value specified in
        # Table 4.6 for this round.
        controller.send_cmd(
            hci.LeSetExtendedAdvertisingEnable(enable=hci.Enable.ENABLED,
                                               enabled_sets=[
                                                   hci.EnabledSet(
                                                       advertising_handle=0,
                                                       duration=duration,
                                                       max_extended_advertising_events=max_extended_advertising_events)
                                               ]))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 6. The Lower Tester receives an ADV_EXT_IND packet from the IUT with AdvMode set to 00b. The
        # ADV_EXT_IND PDU shall not include the SuppInfo, SyncInfo, TxPower, ACAD, or AdvData
        # fields. If advertising data was set in step 4, the ADV_EXT_IND PDU shall include the AuxPtr field;
        # otherwise, the ADV_EXT_IND PDU may include the AuxPtr field. If the AuxPtr field is included,
        # the ADV_EXT_IND PDU shall also include the ADI field with the SID set to the value used in step
        # 3; otherwise that field shall not be included.

        # 7. If the AuxPtr is absent, skip to step 10.

        # 8. The Lower Tester utilizes the AuxPtr field to listen for an AUX_ADV_IND PDU on the secondary
        # advertising channel with the AdvMode field set to 00b. The AUX_ADV_IND PDU shall not include
        # the SuppInfo, SyncInfo, or TxPower fields. The AUX_ADV_IND PDU shall include the ADI field
        # matching the ADI field from step 6. If the AUX_ADV_IND PDU does not contain all the data
        # submitted in step 4 (if any), it shall include an AuxPtr field.

        # 9. If the AUX_ADV_IND PDU contains an AuxPtr field, the Lower Tester utilizes it to listen for an
        # AUX_CHAIN_IND PDU with the AdvMode field set to 00b. The AUX_CHAIN_IND PDU shall
        # include the ADI field matching the ADI field from step 6 and the AdvData field containing
        # additional data submitted in step 4. The AUX_CHAIN_IND PDU shall not include the AdvA,
        # TargetA, SuppInfo, TxPower, or SyncInfo fields. If the AUX_CHAIN_IND PDU contains an AuxPtr
        # field this step is repeated until an AUX_CHAIN_IND PDU is received with no AuxPtr field and all
        # data has been received.
        repeat = max_extended_advertising_events or 3
        for n in range(repeat):
            await self.expect_ll(
                ll.LeExtendedAdvertisingPdu(source_address=controller.address,
                                            advertising_address_type=ll.AddressType.PUBLIC,
                                            target_address_type=ll.AddressType.PUBLIC,
                                            connectable=int(advertising_event_properties.connectable),
                                            scannable=int(advertising_event_properties.scannable),
                                            directed=int(advertising_event_properties.directed),
                                            sid=0,
                                            tx_power=0,
                                            primary_phy=ll.PrimaryPhyType.LE_1M,
                                            secondary_phy=ll.SecondaryPhyType.NO_PACKETS,
                                            advertising_data=advertising_data))

        # 10. If the Max_Extended_Advertising_Events was set to a value different than 0, repeat steps 6–9
        # until the IUT stops advertising. Afterwards, the Lower Tester confirms that the IUT did not send
        # more than Max_Extended_Advertising_Events advertising events. Upper Tester shall receive LE
        # Advertising Set Terminated event with ErrorCode 0x43. Skip to step 13.
        if max_extended_advertising_events > 0:
            try:
                # Note: The test should timeout waiting for an advertising event
                # past Max Extended Advertising Events count.
                await asyncio.wait_for(self.controller.receive_ll(), timeout=1)
                self.assertTrue(False)
            except asyncio.exceptions.TimeoutError:
                pass

            await self.expect_evt(
                hci.LeAdvertisingSetTerminated(
                    status=ErrorCode.ADVERTISING_TIMEOUT,
                    advertising_handle=0,
                    connection_handle=0,
                    num_completed_extended_advertising_events=max_extended_advertising_events))

        # 11. Otherwise if Duration was set to a value different than 0, repeat steps 6–9 until the amount of
        # time specified for Duration has elapsed. Afterwards, the Lower Tester confirms that the IUT does
        # not start any additional advertising events. Upper Tester shall receive LE Advertising Set
        # Terminated event with ErrorCode 0x3C. Skip to step 13.
        elif duration > 0:
            try:
                # Note: The test should timeout waiting for a directed advertising event
                # past the direct advertising timeout.
                end_time = asyncio.get_running_loop().time() + duration / 100
                while asyncio.get_running_loop().time() < end_time:
                    await asyncio.wait_for(self.controller.receive_ll(), timeout=1)
                self.assertTrue(False)
            except asyncio.exceptions.TimeoutError:
                pass

            await self.expect_evt(
                hci.LeAdvertisingSetTerminated(status=ErrorCode.ADVERTISING_TIMEOUT,
                                               advertising_handle=0,
                                               connection_handle=0,
                                               num_completed_extended_advertising_events=0))

        # 12. Otherwise, repeat steps 6–9 until a number of advertising intervals (10) have been detected.

        # 13. The Upper Tester disables advertising using the HCI_LE_Set_Extended_Advertising_Enable
        # command.
        controller.send_cmd(hci.LeSetExtendedAdvertisingEnable(enable=hci.Enable.DISABLED, enabled_sets=[]))

        await self.expect_evt(
            hci.LeSetExtendedAdvertisingEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))
