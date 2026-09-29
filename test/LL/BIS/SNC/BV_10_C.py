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

import asyncio
from rootcanal.bluetooth import Address
from rootcanal.packets import hci
from rootcanal.packets import ll
from rootcanal.packets.hci import ErrorCode
from test.controller_test import ControllerTest


class Test(ControllerTest):

  BIG_Sync_Handle = 0x02
  Sync_Timeout = 0x4000
  Sync_CTE_Type = 0x00
  BIG_Sync_Timeout = 0x0100
  BIS_Indices = [1]
  Broadcast_Code = [0x00] * 16
  Encryption = hci.Enable.DISABLED

  Periodic_Sync_Options = hci.PeriodicAdvertisingOptions(
      use_periodic_advertiser_list=False,
      disable_reporting=False,
      enable_duplicate_filtering=False,
  )

  # LL/BIS/SNC/BV-10-C [Broadcast Isochronous Stream Termination]
  # Conformance Rule: Tests the Synced Receiver's ability to handle BIG termination.
  async def test(self):
    controller = self.controller
    peer_address = Address("11:11:11:11:11:11")

    # 1. Configure Scan Parameters on the IUT (Synced Receiver)
    controller.send_cmd(
        hci.LeSetExtendedScanParameters(
            own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
            scanning_filter_policy=hci.LeScanningFilterPolicy.ACCEPT_ALL,
            scanning_phys=0x01,
            scanning_phy_parameters=[
                hci.ScanningPhyParameters(
                    le_scan_type=hci.LeScanType.ACTIVE,
                    le_scan_interval=0x0010,
                    le_scan_window=0x0010,
                )
            ],
        )
    )
    await self.expect_cmd_complete(hci.LeSetExtendedScanParametersComplete)

    # Enable Extended Scanning
    controller.send_cmd(
        hci.LeSetExtendedScanEnable(
            enable=hci.Enable.ENABLED,
            filter_duplicates=hci.FilterDuplicates.DISABLED,
            duration=0,
            period=0,
        )
    )
    await self.expect_cmd_complete(hci.LeSetExtendedScanEnableComplete)

    # 2. Simulate Extended Advertising PDU from Peer to trigger scanner
    controller.send_ll(
        ll.LeExtendedAdvertisingPdu(
            source_address=peer_address,
            advertising_address_type=ll.AddressType.PUBLIC,
            target_address_type=ll.AddressType.PUBLIC,
            connectable=False,
            scannable=False,
            directed=False,
            sid=0x01,
            tx_power=0x7F,
            primary_phy=ll.PhyType.LE_1M,
            secondary_phy=ll.PhyType.LE_1M,
            periodic_advertising_interval=0x0100,
            advertising_data=[],
        )
    )
    await self.expect_evt(hci.LeExtendedAdvertisingReport, timeout=3.0)

    # 3. Establish Periodic Sync targeting the Peer
    controller.send_cmd(
        hci.LePeriodicAdvertisingCreateSync(
            options=self.Periodic_Sync_Options,
            advertising_sid=0x01,
            advertiser_address_type=hci.AdvertiserAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
            advertiser_address=peer_address,
            skip=0,
            sync_timeout=self.Sync_Timeout,
            sync_cte_type=self.Sync_CTE_Type,
        )
    )
    await self.expect_evt(
        hci.LePeriodicAdvertisingCreateSyncStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    # Simulate Periodic Advertising PDU from Peer to establish periodic sync
    controller.send_ll(
        ll.LePeriodicAdvertisingPdu(
            source_address=peer_address,
            advertising_address_type=ll.AddressType.PUBLIC,
            sid=0x01,
            tx_power=0x7F,
            advertising_interval=0x0100,
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

    sync_established = await self.expect_evt(
        hci.LePeriodicAdvertisingSyncEstablishedV1
    )
    self.assertEqual(sync_established.status, ErrorCode.SUCCESS)
    sync_handle = sync_established.sync_handle

    # 3A. Simulate Peer broadcasting BIGInfo over Periodic Advertising
    # This triggers the LeBigInfoAdvertisingReport event on the Host, required before LeBigCreateSync.
    controller.send_ll(
        ll.LePeriodicAdvertisingPdu(
            source_address=peer_address,
            advertising_address_type=ll.AddressType.PUBLIC,
            sid=0x01,
            tx_power=0x7F,
            advertising_interval=0x0100,
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
            advertising_data=[],
        )
    )

    periodic_report = hci.LePeriodicAdvertisingReportV1(
        sync_handle=sync_handle,
        tx_power=0x7F,
        rssi=self.Any,
        cte_type=hci.CteType.NO_CONSTANT_TONE_EXTENSION,
        data_status=hci.DataStatus.COMPLETE,
        data=[],
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

    # Wait for both the periodic report and the BIGInfo report to be scanned
    matched_periodic = False
    matched_big_info = False
    while not (matched_periodic and matched_big_info):
      evt = await self.expect_evt([periodic_report, big_info_report])
      if isinstance(evt, hci.LePeriodicAdvertisingReportV1):
        matched_periodic = True
      elif isinstance(evt, hci.LeBigInfoAdvertisingReport):
        matched_big_info = True

    # 4. Synchronize to the simulated BIG on the Peer (now that BigInfo is scanned!)
    controller.send_cmd(
        hci.LeBigCreateSync(
            big_handle=self.BIG_Sync_Handle,
            sync_handle=sync_handle,
            encryption=self.Encryption,
            broadcast_code=self.Broadcast_Code,
            mse=0,
            big_sync_timeout=self.BIG_Sync_Timeout,
            bis=self.BIS_Indices,
        )
    )

    # receives LeBigCreateSyncStatus in response
    await self.expect_evt(
        hci.LeBigCreateSyncStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    # expect LeBigSyncEstablished
    await self.expect_evt(
        hci.LeBigSyncEstablished(
            status=ErrorCode.SUCCESS,
            big_handle=self.BIG_Sync_Handle,
            transport_latency_big=self.Any,
            nse=self.Any,
            bn=self.Any,
            pto=self.Any,
            irc=self.Any,
            max_pdu=self.Any,
            iso_interval=self.Any,
            connection_handle=[self.Any],
        )
    )

    # 5. Spec Validation: Attempt to terminate the BIG using Synced Receiver's handle.
    # The Controller must reject this with Command Disallowed (0x0C).
    controller.send_cmd(
        hci.LeTerminateBig(
            big_handle=self.BIG_Sync_Handle,
            reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST,
        )
    )
    status_received = False
    while not status_received:
      matched = await self.expect_evt([hci.LeTerminateBigStatus])
      if isinstance(matched, hci.LeTerminateBigStatus):
        self.assertEqual(matched.status, ErrorCode.COMMAND_DISALLOWED)
        status_received = True

    # 6. Simulate Peer Broadcaster terminating the BIG over the air
    controller.send_ll(
        ll.LePeriodicAdvertisingPdu(
            source_address=peer_address,
            advertising_address_type=ll.AddressType.PUBLIC,
            sid=0x01,
            tx_power=0x7F,
            advertising_interval=0x0100,
            big_info=ll.BigInfo(
                num_bis=0,  # BIG Terminated!
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

    # 7. Verify that LeBigSyncLost is received cleanly on the IUT Synced Receiver
    # We loop expectations to ignore incoming background report/info packets
    sync_lost_received = False
    while not sync_lost_received:
      matched = await self.expect_evt([
          periodic_report,
          big_info_report,
          hci.LeBigSyncLost(
              big_handle=self.BIG_Sync_Handle,
              reason=ErrorCode.REMOTE_USER_TERMINATED_CONNECTION,
          ),
      ])
      if isinstance(matched, hci.LeBigSyncLost):
        sync_lost_received = True

    # 8. Disable Extended Scanning
    controller.send_cmd(
        hci.LeSetExtendedScanEnable(
            enable=hci.Enable.DISABLED,
            filter_duplicates=hci.FilterDuplicates.DISABLED,
            duration=0,
            period=0,
        )
    )
    status_received = False
    while not status_received:
      matched = await self.expect_evt([hci.LeSetExtendedScanEnableComplete])
      if isinstance(matched, hci.LeSetExtendedScanEnableComplete):
        self.assertEqual(matched.status, ErrorCode.SUCCESS)
        status_received = True

    await asyncio.sleep(0.1)

  def tearDown(self):
    # Drain all remaining Link Layer packets synchronously before stop() is called
    try:
      while True:
        self.controller.ll_queue.get_nowait()
    except asyncio.QueueEmpty:
      pass
    super().tearDown()
