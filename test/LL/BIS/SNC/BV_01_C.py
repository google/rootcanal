# Copyright 2026 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from rootcanal.packets import hci
from rootcanal.packets import ll
from rootcanal.packets.hci import ErrorCode
from rootcanal.bluetooth import Address
from test.controller_test import ControllerTest


class Test(ControllerTest):

    Own_Address_Type = hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS
    Scanning_Filter_Policy = hci.LeScanningFilterPolicy.ACCEPT_ALL
    Scanning_Phys = 0x01
    Scan_Type = hci.LeScanType.ACTIVE
    Scan_Interval = 0x0010
    Scan_Window = 0x0010

    Extended_Advertising_SID = 0x01
    Periodic_Advertising_Interval = 0x0100
    TX_Power = 0x7F

    Periodic_Sync_Options = hci.PeriodicAdvertisingOptions(
        use_periodic_advertiser_list=False,
        disable_reporting=False,
        enable_duplicate_filtering=False,
    )
    Sync_Timeout = 0x0100
    Sync_CTE_Type = 0x00

    BIG_Handle = 0x01
    Encryption = hci.Enable.DISABLED
    Broadcast_Code = [0x00] * 16
    MSE = 0
    BIG_Sync_Timeout = 0x0100
    BIS_Indices = [1]

    # LL/BIS/SNC/BV-01-C [Broadcast Isochronous Stream Synchronization Setup]
    async def test(self):
        controller = self.controller
        peer_address = Address("11:22:33:44:55:66")

        # Set LE Event Mask to allow BIG Info reports.
        # This must be done after Reset (which occurs in asyncSetUp).
        controller.send_cmd(hci.LeSetEventMask(le_event_mask=0xffffffffffffffff))
        await self.expect_evt(
            hci.LeSetEventMaskComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1)
        )

        # Enable Scanning
        controller.send_cmd(
            hci.LeSetExtendedScanParameters(
                own_address_type=self.Own_Address_Type,
                scanning_filter_policy=self.Scanning_Filter_Policy,
                scanning_phys=self.Scanning_Phys,
                scanning_phy_parameters=[
                    hci.ScanningPhyParameters(
                        le_scan_type=self.Scan_Type,
                        le_scan_interval=self.Scan_Interval,
                        le_scan_window=self.Scan_Window,
                    )
                ],
            )
        )
        await self.expect_evt(
            hci.LeSetExtendedScanParametersComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        controller.send_cmd(
            hci.LeSetExtendedScanEnable(
                enable=hci.Enable.ENABLED,
                filter_duplicates=hci.FilterDuplicates.DISABLED,
                duration=0x0000,
                period=0x0000,
            )
        )
        await self.expect_evt(
            hci.LeSetExtendedScanEnableComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # 1. Lower Tester sends an Extended Advertising PDU.
        controller.send_ll(
            ll.LeExtendedAdvertisingPdu(
                source_address=peer_address,
                advertising_address_type=ll.AddressType.PUBLIC,
                target_address_type=ll.AddressType.PUBLIC,
                connectable=False,
                scannable=False,
                directed=False,
                sid=self.Extended_Advertising_SID,
                tx_power=self.TX_Power,
                primary_phy=ll.PhyType.LE_1M,
                secondary_phy=ll.PhyType.LE_1M,
                periodic_advertising_interval=self.Periodic_Advertising_Interval,
                advertising_data=[],
            )
        )

        # 2. The IUT receives the PDU and sends an HCI_LE_Extended_Advertising_Report event.
        await self.expect_evt(hci.LeExtendedAdvertisingReport, timeout=3.0)

        # 3. The Upper Tester sends an HCI_LE_Periodic_Advertising_Create_Sync command
        controller.send_cmd(
            hci.LePeriodicAdvertisingCreateSync(
                options=self.Periodic_Sync_Options,
                advertising_sid=self.Extended_Advertising_SID,
                advertiser_address_type=hci.AdvertiserAddressType.
                PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                advertiser_address=peer_address,
                skip=0x0000,
                sync_timeout=self.Sync_Timeout,
                sync_cte_type=self.Sync_CTE_Type,
            )
        )

        # receives an HCI_Command_Status event in response
        await self.expect_evt(
            hci.LePeriodicAdvertisingCreateSyncStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # Simulate Periodic Advertising PDU to establish sync
        controller.send_ll(
            ll.LePeriodicAdvertisingPdu(
                source_address=peer_address,
                advertising_address_type=ll.AddressType.PUBLIC,
                sid=self.Extended_Advertising_SID,
                tx_power=self.TX_Power,
                advertising_interval=self.Periodic_Advertising_Interval,
                big_info=ll.BigInfo(
                    num_bis=0,
                    nse=0,
                    iso_interval=0,
                    bn=0,
                    pto=0,
                    irc=0,
                    max_pdu=0,
                    sdu_interval=0,
                    max_sdu=0,
                    phy=0,
                    framing=0,
                    encryption=0,
                ),
                advertising_data=[],
            )
        )

        # 4. The IUT reports the reception of periodic advertising PDUs by providing an
        # HCI_LE_Periodic_Advertising_Sync_Established event to the Upper Tester.
        sync_established = await self.expect_evt(
            hci.LePeriodicAdvertisingSyncEstablishedV1(
                status=ErrorCode.SUCCESS,
                sync_handle=self.Any,
                advertising_sid=self.Extended_Advertising_SID,
                advertiser_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                advertiser_address=peer_address,
                advertiser_phy=hci.SecondaryPhyType.LE_1M,
                periodic_advertising_interval=self.Periodic_Advertising_Interval,
                advertiser_clock_accuracy=hci.ClockAccuracy.PPM_500,
            )
        )

        sync_handle = sync_established.sync_handle

        # 5. Lower Tester sends Periodic Advertising PDU with BIG Info.
        controller.send_ll(
            ll.LePeriodicAdvertisingPdu(
                source_address=peer_address,
                advertising_address_type=ll.AddressType.PUBLIC,
                sid=self.Extended_Advertising_SID,
                tx_power=self.TX_Power,
                advertising_interval=self.Periodic_Advertising_Interval,
                big_info=ll.BigInfo(
                    num_bis=1,
                    nse=2,
                    iso_interval=0x10,
                    bn=1,
                    pto=0,
                    irc=2,
                    max_pdu=251,
                    sdu_interval=10000,
                    max_sdu=251,
                    phy=1,
                    framing=hci.Enable.DISABLED,
                    encryption=hci.Enable.DISABLED,
                ),
                advertising_data=[0x01, 0x02],
            )
        )

        # 5/6. The IUT sends Periodic Advertising Report and BIGInfo Advertising Report.
        # Note: These can arrive in any order.
        periodic_report = hci.LePeriodicAdvertisingReportV1(
            sync_handle=sync_handle,
            tx_power=self.TX_Power,
            rssi=self.Any,
            cte_type=hci.CteType.NO_CONSTANT_TONE_EXTENSION,
            data_status=hci.DataStatus.COMPLETE,
            data=[0x01, 0x02],
        )
        big_info_report = hci.LeBigInfoAdvertisingReport(
            sync_handle=sync_handle,
            num_bis=1,
            nse=2,
            iso_interval=0x10,
            bn=1,
            pto=0,
            irc=2,
            max_pdu=251,
            sdu_interval=10000,
            max_sdu=251,
            phy=hci.SecondaryPhyType.LE_1M,
            framing=hci.Enable.DISABLED,
            encryption=hci.Enable.DISABLED,
        )

        # Matched and Drain until we get both (or just BIG info report if periodic report arrived earlier)
        big_info_received = False
        while not big_info_received:
            matched = await self.expect_evt([periodic_report, big_info_report])
            if isinstance(matched, hci.LeBigInfoAdvertisingReport):
                big_info_received = True

        # 7. The Upper Tester orders the IUT to synchronize to the Lower Tester’s BIG by sending an
        # HCI_LE_BIG_Create_Sync command
        controller.send_cmd(
            hci.LeBigCreateSync(
                big_handle=self.BIG_Handle,
                sync_handle=sync_handle,
                encryption=self.Encryption,
                broadcast_code=self.Broadcast_Code,
                mse=self.MSE,
                big_sync_timeout=self.BIG_Sync_Timeout,
                bis=self.BIS_Indices,
            )
        )

        # and receives an HCI_Command_Status event in response.
        big_create_sync_status = hci.LeBigCreateSyncStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
        status_received = False
        while not status_received:
            matched = await self.expect_evt([periodic_report, big_create_sync_status])
            if isinstance(matched, hci.LeBigCreateSyncStatus):
                status_received = True

        # 8. The IUT synchronizes to the BIG and the Upper Tester receives an
        # HCI_LE_BIG_Sync_Established event.
        big_sync_established = hci.LeBigSyncEstablished(
            status=ErrorCode.SUCCESS,
            big_handle=self.BIG_Handle,
            transport_latency_big=self.Any,
            nse=2,
            bn=1,
            pto=0,
            irc=2,
            max_pdu=251,
            iso_interval=0x10,
            connection_handle=[self.Any],
        )

        establishment_received = None
        while not establishment_received:
            matched = await self.expect_evt([periodic_report, big_sync_established])
            if isinstance(matched, hci.LeBigSyncEstablished):
                establishment_received = matched

        bis_connection_handle = establishment_received.connection_handle[0]

        # 9. The Upper Tester attempts to create an ISO input data path by sending an
        # HCI_LE_Setup_ISO_Data_Path command with the input path enabled to the IUT.
        # Spec: The IUT should respond with error code Command Disallowed (0x0C).
        controller.send_cmd(
            hci.LeSetupIsoDataPath(
                connection_handle=bis_connection_handle,
                data_path_direction=hci.DataPathDirection.INPUT,
                data_path_id=0,
                codec_id=0,
                controller_delay=0,
                codec_configuration=[],
            )
        )
        # Spec verification (Status match)
        status_received = False
        while not status_received:
            matched = await self.expect_evt([periodic_report, hci.LeSetupIsoDataPathComplete])
            if isinstance(matched, hci.LeSetupIsoDataPathComplete):
                self.assertEqual(matched.status, ErrorCode.COMMAND_DISALLOWED)
                status_received = True

        # 10. The Upper Tester sends an HCI_LE_Setup_ISO_Data_Path command to the IUT and
        # receives an HCI_Command_Complete event in response.
        # Spec: Should succeed with direction OUTPUT for a Sync Receiver.
        controller.send_cmd(
            hci.LeSetupIsoDataPath(
                connection_handle=bis_connection_handle,
                data_path_direction=hci.DataPathDirection.OUTPUT,
                data_path_id=0,
                codec_id=0,
                controller_delay=0,
                codec_configuration=[],
            )
        )
        status_received = False
        while not status_received:
            matched = await self.expect_evt([periodic_report, hci.LeSetupIsoDataPathComplete])
            if isinstance(matched, hci.LeSetupIsoDataPathComplete):
                self.assertEqual(matched.status, ErrorCode.SUCCESS)
                status_received = True

        # 11. The Lower Tester sends 50 BIS Data PDUs.
        # 12. For each BIS Data PDU, the IUT provides an HCI_ISO_Data packet to the Upper Tester.
        for _ in range(50):
            controller.send_ll(
                ll.LeBroadcastIsochronousPdu(
                    source_address=peer_address,
                    destination_address=controller.address,
                    big_id=self.BIG_Handle,
                    bis_id=1,
                    sequence_number=0,
                    data=b"\x01\x02\x03\x04",
                )
            )

            await self.expect_iso(
                hci.IsoWithoutTimestamp(
                    connection_handle=bis_connection_handle,
                    pb_flag=hci.IsoPacketBoundaryFlag.COMPLETE_SDU,
                    packet_sequence_number=0,
                    iso_sdu_length=4,
                    packet_status_flag=hci.IsoPacketStatusFlag.VALID,
                    payload=b"\x01\x02\x03\x04",
                )
            )

        # 13A.1 The Upper Tester sends an HCI_LE_BIG_Terminate_Sync to the IUT
        controller.send_cmd(hci.LeBigTerminateSync(big_handle=self.BIG_Handle))

        # and receives a successful HCI_Command_Complete event in response.
        status_received = False
        while not status_received:
            matched = await self.expect_evt([periodic_report, hci.LeBigTerminateSyncComplete])
            if isinstance(matched, hci.LeBigTerminateSyncComplete):
                self.assertEqual(matched.status, ErrorCode.SUCCESS)
                status_received = True
