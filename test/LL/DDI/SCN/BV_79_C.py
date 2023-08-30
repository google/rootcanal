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


class Test(ControllerTest):

    # LL/DDI/SCN/BV-79-C  [Extended Scanning, Passive, Periodic Advertising Report,
    #                      RSSI and TX_Power – LE 1M PHY]
    async def test(self):
        # Test rounds.
        # Note: some tests are skipped as no distinction is made between
        # ADV_EXT_IND, AUX_ADV_IND, AUX_CHAIN_IND.
        controller = self.controller
        lower_tester_address = Address('11:22:33:44:55:66')
        advertising_sid = 0x3
        tx_power = 0x0a
        periodic_advertising_interval = 0x100

        # 1. The Upper Tester sends an HCI_LE_Set_Extended_Scan_Parameters command to the IUT with
        # Scanning_PHYs set as specified in Table 4.35, Scan_Type[0] set to 0x00 (Passive Scanning),
        # Scan_Interval[0] set to 0x0010, Scan_Window[0] set to 0x0010, Own_Address_Type set to 0x00
        # (Public Device Address), and Scanning_Filter_Policy shall be set to 0x00 (Accept All) and
        # receives a successful HCI_Command_Complete event in return.
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
        # scanning with Filter_Duplicates, Duration, and Period are set to zero and receives a successful
        # HCI_Command_Complete event in return.
        controller.send_cmd(
            hci.LeSetExtendedScanEnable(enable=hci.Enable.ENABLED,
                                        filter_duplicates=hci.Enable.DISABLED,
                                        duration=0,
                                        period=0))

        await self.expect_evt(hci.LeSetExtendedScanEnableComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        for n in range(3):
            # 3. The Lower Tester begins advertising using ADV_EXT_IND and AUX_ADV_IND PDUs. The
            # ADV_EXT_IND PDUs include an AuxPtr that refers to the AUX_ADV_IND PDU on the secondary
            # advertising channel. The AUX_ADV_IND PDUs include the AdvA field containing the Lower
            # Tester address, and the SyncInfo field referring to the AUX_SYNC_IND PDU. The Lower Tester
            # continues advertising until directed to stop in the test procedure.
            controller.send_ll(ll.LeExtendedAdvertisingPdu(source_address=lower_tester_address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           connectable=False,
                                                           scannable=False,
                                                           directed=False,
                                                           sid=advertising_sid,
                                                           tx_power=tx_power,
                                                           primary_phy=ll.PrimaryPhyType.LE_1M,
                                                           secondary_phy=ll.SecondaryPhyType.NO_PACKETS,
                                                           periodic_advertising_interval=0x100,
                                                           advertising_data=[]),
                               rssi=0x10)

            # 4. The IUT sends an HCI_LE_Extended_Advertising_Report event to the Upper Tester containing a
            # nonzero Periodic_Advertising_Interval, Data Status in the Event_Type[i] field set to the value
            # 0b00 (Complete), and RSSI[i] set to a valid value.
            await self.expect_evt(
                hci.LeExtendedAdvertisingReport(responses=[
                    hci.LeExtendedAdvertisingResponse(
                        connectable=False,
                        scannable=False,
                        directed=False,
                        scan_response=False,
                        legacy=False,
                        data_status=hci.DataStatus.COMPLETE,
                        address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                        address=lower_tester_address,
                        primary_phy=hci.PrimaryPhyType.LE_1M,
                        secondary_phy=hci.SecondaryPhyType.NO_PACKETS,
                        advertising_sid=advertising_sid,
                        tx_power=tx_power,
                        rssi=0x10,
                        periodic_advertising_interval=periodic_advertising_interval,
                        direct_address_type=hci.DirectAdvertisingAddressType.NO_ADDRESS_PROVIDED,
                        direct_address=Address(),
                        advertising_data=[])
                ]))

        # 5. The Upper Tester sends an HCI_LE_Periodic_Advertising_Create_Sync command to the IUT to
        # synchronize with the Lower Tester’s periodic advertisements with Options set to 0x00 (Do not
        # Use List), Advertising_SID set to the Advertising_SID from step 3, Advertiser_Address_Type set
        # to 0x00 (Public Device Address), Advertiser_Address set to the Lower Tester’s address, Skip set
        # to the value 0x0003, Sync_Timeout set to (Skip + 3) x Periodic_Advertising_Interval from step 4,
        # and Sync_CTE_Type set to 0x00 and receives a successful HCI_Command_Complete event in
        # return.
        controller.send_cmd(
            hci.LePeriodicAdvertisingCreateSync(
                options=hci.PeriodicAdvertisingOptions(use_periodic_advertiser_list=False,
                                                       disable_reporting=False,
                                                       enable_duplicate_filtering=False),
                advertising_sid=advertising_sid,
                advertiser_address_type=hci.AdvertiserAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                advertiser_address=lower_tester_address,
                skip=0x3,
                sync_timeout=6 * periodic_advertising_interval,
                sync_cte_type=0))

        await self.expect_evt(
            hci.LePeriodicAdvertisingCreateSyncStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        # 6. The Lower Tester generates an AUX_SYNC_IND PDU on the secondary advertising channel with
        # AuxPtr set to a value referring to the first AUX_CHAIN_IND PDU in the train, TxPower set to 10,
        # and AdvData set to N octets of random data.
        controller.send_ll(
            ll.LePeriodicAdvertisingPdu(source_address=lower_tester_address,
                                        advertising_address_type=ll.AddressType.PUBLIC,
                                        sid=advertising_sid,
                                        tx_power=tx_power,
                                        advertising_interval=periodic_advertising_interval,
                                        advertising_data=[]))

        # 7. The IUT sends a successful HCI_LE_Periodic_Advertising_Sync_Established event to the Upper
        # Tester containing a Status of 0x00 (Success), Sync_Handle set to a valid value, and the
        # Advertising_SID received in step 3.
        await self.expect_evt(
            hci.LePeriodicAdvertisingSyncEstablished(
                status=ErrorCode.SUCCESS,
                sync_handle=0,
                advertising_sid=advertising_sid,
                advertiser_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                advertiser_address=lower_tester_address,
                advertiser_phy=hci.SecondaryPhyType.LE_1M,
                periodic_advertising_interval=periodic_advertising_interval,
                advertiser_clock_accuracy=hci.ClockAccuracy.PPM_500,
            ))

        for n in range(3):
            advertising_data_length = 256
            advertising_data = [random.randint(1, 254) for n in range(advertising_data_length)]

            # 8. The Lower Tester sends two AUX_CHAIN_IND PDUs to the IUT with AdvData set to min(249,
            # (Scan_Max_Data – N) / 2) octets of random data for each AUX_CHAIN_IND PDU and the
            # TxPower value of the AUX_CHAIN_IND PDUs set to 15. The PDUs should be sent as far apart
            # as practical.
            controller.send_ll(ll.LePeriodicAdvertisingPdu(source_address=lower_tester_address,
                                                           advertising_address_type=ll.AddressType.PUBLIC,
                                                           sid=advertising_sid,
                                                           tx_power=tx_power,
                                                           advertising_interval=periodic_advertising_interval,
                                                           advertising_data=advertising_data),
                               rssi=0x10)

            # 9. The IUT sends multiple HCI_LE_Periodic_Advertising_Report events to the Upper Tester with
            # Data Status in the Event_Type[i] field set to 0b01 (Incomplete, more data to come), TX_Power[i]
            # set to the value of the TxPower field for the AUX_SYNC_IND received in step 6, and RSSI[i] set
            # to a valid value. Subsequent reports with data and the status set to “Incomplete, more data to
            # come” or “complete” can have the TX_Power field set to 0x7F.
            offset = 0
            max_fragment_length = 247
            num_fragments = math.ceil(advertising_data_length / max_fragment_length) or 1
            for n in range(num_fragments):
                remaining_length = advertising_data_length - offset
                fragment_length = min(max_fragment_length, remaining_length)
                data_status = hci.DataStatus.CONTINUING if remaining_length > max_fragment_length else hci.DataStatus.COMPLETE
                await self.expect_evt(
                    hci.LePeriodicAdvertisingReport(sync_handle=0,
                                                    tx_power=tx_power,
                                                    rssi=0x10,
                                                    cte_type=hci.CteType.NO_CONSTANT_TONE_EXTENSION,
                                                    data_status=data_status,
                                                    data=advertising_data[offset:offset + fragment_length]))
                offset += fragment_length
