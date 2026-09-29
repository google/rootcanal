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

from rootcanal.bluetooth import Address
from rootcanal.packets import hci
from rootcanal.packets import ll
from rootcanal.packets.hci import ErrorCode
from test.controller_test import ControllerTest


class Test(ControllerTest):

  BIG_Handle = 0x00
  Advertising_Handle = 0x00
  SDU_Interval = 10000  # 10ms
  Max_SDU = 100
  Max_Transport_Latency = 4000  # 40ms
  RTN = 2
  PHY = hci.SecondaryPhyType.LE_1M
  Packing = hci.Packing.SEQUENTIAL
  Framing = hci.Enable.DISABLED
  Encryption = hci.Enable.DISABLED
  Broadcast_Code = [0x00] * 16
  Num_BIS = 2
  Advertising_Interval_Min = 0x00A0
  Advertising_Interval_Max = 0x00A0
  Advertising_Channel_Map = 0x07
  Own_Address_Type = hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS
  Peer_Address_Type = hci.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS
  Peer_Address = Address("00:00:00:00:00:00")
  Advertising_Filter_Policy = hci.AdvertisingFilterPolicy.ALL_DEVICES
  Advertising_TX_Power = 0x7F
  Advertising_SID = 0x01
  Secondary_Advertising_Max_Skip = 0x00
  Secondary_Advertising_Phy = hci.SecondaryPhyType.LE_1M

  # LL/BIS/BRD/BV-01-C [Broadcast Isochronous Stream Setup Procedure, Broadcaster Initiated]
  async def test(self):
    controller = self.controller

    # Set Extended Advertising Parameters (Periodic Advertising without Responses)
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
    await self.expect_evt(
        hci.LeSetExtendedScanParametersComplete(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    controller.send_cmd(
        hci.LeSetExtendedAdvertisingParametersV1(
            advertising_handle=self.Advertising_Handle,
            advertising_event_properties=hci.AdvertisingEventProperties(
                connectable=False,
                scannable=False,
                directed=False,
                high_duty_cycle=False,
                legacy=False,
                anonymous=False,
                include_tx_power=False,
            ),
            primary_advertising_interval_min=self.Advertising_Interval_Min,
            primary_advertising_interval_max=self.Advertising_Interval_Max,
            primary_advertising_channel_map=self.Advertising_Channel_Map,
            own_address_type=self.Own_Address_Type,
            peer_address_type=self.Peer_Address_Type,
            peer_address=self.Peer_Address,
            advertising_filter_policy=self.Advertising_Filter_Policy,
            advertising_tx_power=self.Advertising_TX_Power,
            primary_advertising_phy=hci.PrimaryPhyType.LE_1M,
            secondary_advertising_max_skip=self.Secondary_Advertising_Max_Skip,
            secondary_advertising_phy=self.Secondary_Advertising_Phy,
            advertising_sid=self.Advertising_SID,
            scan_request_notification_enable=hci.Enable.DISABLED,
        )
    )
    await self.expect_evt(
        hci.LeSetExtendedAdvertisingParametersV1Complete(
            status=ErrorCode.SUCCESS,
            selected_tx_power=self.Advertising_TX_Power,
            num_hci_command_packets=1,
        )
    )

    # Set Periodic Advertising Parameters
    controller.send_cmd(
        hci.LeSetPeriodicAdvertisingParametersV1(
            advertising_handle=self.Advertising_Handle,
            periodic_advertising_interval_min=self.Advertising_Interval_Min,
            periodic_advertising_interval_max=self.Advertising_Interval_Max,
            include_tx_power=False,
        )
    )
    await self.expect_evt(
        hci.LeSetPeriodicAdvertisingParametersV1Complete(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    # Enable Periodic Advertising
    controller.send_cmd(
        hci.LeSetPeriodicAdvertisingEnable(
            enable=hci.Enable.ENABLED,
            include_adi=False,
            advertising_handle=self.Advertising_Handle,
        )
    )
    await self.expect_evt(
        hci.LeSetPeriodicAdvertisingEnableComplete(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    # Enable Extended Advertising
    controller.send_cmd(
        hci.LeSetExtendedAdvertisingEnable(
            enable=hci.Enable.ENABLED,
            enabled_sets=[
                hci.EnabledSet(
                    advertising_handle=self.Advertising_Handle,
                    duration=0,
                    max_extended_advertising_events=0,
                )
            ],
        )
    )
    await self.expect_evt(
        hci.LeSetExtendedAdvertisingEnableComplete(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    # --- Test Procedure ---

    # Step 1: Upper Tester sends HCI_LE_Create_BIG command to IUT
    controller.send_cmd(
        hci.LeCreateBig(
            big_handle=self.BIG_Handle,
            advertising_handle=self.Advertising_Handle,
            num_bis=self.Num_BIS,
            sdu_interval=self.SDU_Interval,
            max_sdu=self.Max_SDU,
            max_transport_latency=self.Max_Transport_Latency,
            rtn=self.RTN,
            phy=self.PHY,
            packing=self.Packing,
            framing=self.Framing,
            encryption=self.Encryption,
            broadcast_code=self.Broadcast_Code,
        )
    )

    # IUT responds with an HCI_Command_Status event
    await self.expect_evt(
        hci.LeCreateBigStatus(
            status=ErrorCode.SUCCESS, num_hci_command_packets=1
        )
    )

    # Step 2: IUT sends an HCI_LE_Create_BIG_Complete event
    create_big_complete = await self.expect_evt(
        hci.LeCreateBigComplete(
            status=ErrorCode.SUCCESS,
            big_handle=self.BIG_Handle,
            big_sync_delay=self.Any,
            transport_latency_big=self.Any,
            phy=self.PHY,
            nse=self.Any,
            bn=self.Any,
            pto=self.Any,
            irc=self.Any,
            max_pdu=self.Any,
            iso_interval=self.Any,
            connection_handle=[self.Any] * self.Num_BIS,
        )
    )

    bis_handles = create_big_complete.connection_handle

    # Step 6: Upper Tester sends an HCI_LE_Read_Buffer_Size [v2] command
    controller.send_cmd(hci.LeReadBufferSizeV2())
    await self.expect_evt(
        hci.LeReadBufferSizeV2Complete(
            status=ErrorCode.SUCCESS,
            num_hci_command_packets=1,
            le_buffer_size=self.Any,
            iso_buffer_size=self.Any,
        )
    )

    # Step 7: Setup data path for each BIS
    for bis_handle in bis_handles:
      controller.send_cmd(
          hci.LeSetupIsoDataPath(
              connection_handle=bis_handle,
              data_path_direction=hci.DataPathDirection.INPUT,
              data_path_id=0x00,
              codec_id=0,
              controller_delay=0,
              codec_configuration=[],
          )
      )

      await self.expect_evt(
          hci.LeSetupIsoDataPathComplete(
              status=ErrorCode.SUCCESS,
              num_hci_command_packets=1,
              connection_handle=bis_handle,
          )
      )

    # Step 8, 9: Send and verify ISO data for each BIS
    # We also expect the Link Layer packets to be sent out.
    for idx, bis_handle in enumerate(bis_handles):
      payload = [0x00] * 40
      controller.send_iso(
          hci.IsoWithoutTimestamp(
              connection_handle=bis_handle,
              pb_flag=hci.IsoPacketBoundaryFlag.COMPLETE_SDU,
              packet_sequence_number=0,
              iso_sdu_length=40,
              packet_status_flag=hci.IsoPacketStatusFlag.VALID,
              payload=bytes(payload),
          )
      )
      # Expect Host Notification
      await self.expect_evt(
          hci.NumberOfCompletedPackets(
              completed_packets=[
                  hci.CompletedPackets(
                      connection_handle=bis_handle,
                      host_num_of_completed_packets=1,
                  )
              ]
          )
      )

      # Expect Link Layer transmission.
      # Handle potential periodic advertising packets that might be sent concurrently.
      target_pdu = ll.LeBroadcastIsochronousPdu(
          source_address=controller.address,
          destination_address=Address("00:00:00:00:00:00"),
          big_id=self.BIG_Handle,
          bis_id=idx + 1,
          sequence_number=self.Any,
          data=payload,
      )

      # Use more general matchers for advertising PDUs
      matched_pdu = None
      while not isinstance(matched_pdu, ll.LeBroadcastIsochronousPdu):
        matched_pdu = await self.expect_ll([
            target_pdu,
            ll.LeExtendedAdvertisingPdu,
            ll.LePeriodicAdvertisingPdu,
        ])

    # Cleanup: Terminate BIG
    controller.send_cmd(
        hci.LeTerminateBig(
            big_handle=self.BIG_Handle,
            reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST,
        )
    )
    await self.expect_evt(
        hci.LeTerminateBigStatus(
            status=ErrorCode.SUCCESS,
            num_hci_command_packets=1,
        )
    )
    await self.expect_evt(
        hci.LeTerminateBigComplete(
            big_handle=self.BIG_Handle,
            reason=ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST,
        )
    )
