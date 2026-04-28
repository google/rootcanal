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
import enum
import os
import random
import sys
import typing
import unittest
from ctypes import *
from importlib import resources
from rootcanal.packets import hci, ll, llcp
from rootcanal.packets.hci import ErrorCode
from rootcanal.controller import Controller, LeFeatures
from typing import Optional, Tuple, Union


class Any:
    """Helper class that will match all other values.
     Use an element of this class in expected packets to match any value
    returned by the Controller stack."""

    def __eq__(self, other) -> bool:
        return True

    def __format__(self, format_spec: str) -> str:
        return "_"

    @property
    def name(self) -> str:
        return "_"


class ControllerTest(unittest.IsolatedAsyncioTestCase):
    """Helper class for writing controller tests using the python bindings.
    The test setups the controller sending the Reset command and configuring
    the event masks to allow all events. The local device address is
    always configured as 11:11:11:11:11:11."""

    Any = Any()

    def setUp(self):
        self.controller = Controller(hci.Address("11:11:11:11:11:11"))

    async def asyncSetUp(self):
        controller = self.controller

        # Start the controller timer.
        await controller.start()

        # Reset the controller and enable all events and LE events.
        controller.send_cmd(hci.Reset())
        await controller.expect_evt(
            hci.ResetComplete(status=ErrorCode.SUCCESS, num_hci_command_packets=1)
        )
        controller.send_cmd(hci.SetEventMask(event_mask=0xFFFFFFFFFFFFFFFF))
        await controller.expect_evt(
            hci.SetEventMaskComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )
        controller.send_cmd(hci.LeSetEventMask(le_event_mask=0xFFFFFFFFFFFFFFFF))
        await controller.expect_evt(
            hci.LeSetEventMaskComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # Load the local supported features to be able to disable tests
        # that rely on unsupported features.
        controller.send_cmd(hci.LeReadLocalSupportedFeaturesPage0())
        evt = await self.expect_cmd_complete(
            hci.LeReadLocalSupportedFeaturesPage0Complete
        )
        controller.le_features = LeFeatures(evt.le_features)

    async def expect_evt(
        self,
        expected_events: typing.Union[list, typing.Union[hci.Event, type]],
        timeout: int = 3,
    ) -> hci.Event:
        if not isinstance(expected_events, list):
            expected_events = [expected_events]

        async with asyncio.timeout(timeout):
            while True:
                packet = await self.controller.receive_evt()
                evt = hci.Event.parse_all(packet)

                for expected_evt in expected_events:
                    if isinstance(expected_evt, type) and isinstance(evt, expected_evt):
                        return evt
                    if isinstance(expected_evt, hci.Event) and evt == expected_evt:
                        return evt

                print("received unexpected event:")
                evt.show()
                print("expected events:")
                for expected_evt in expected_events:
                    if isinstance(expected_evt, type):
                        print(f"- {expected_evt.__name__}")
                    if isinstance(expected_evt, hci.Event):
                        print(f"- {expected_evt.__class__.__name__}")
                        expected_evt.show()

                self.assertTrue(False)

    async def expect_cmd_complete(
        self, expected_evt: type, timeout: int = 3
    ) -> hci.Event:
        evt = await self.expect_evt(expected_evt, timeout=timeout)
        assert evt.status == ErrorCode.SUCCESS
        assert evt.num_hci_command_packets == 1
        return evt

    async def expect_acl(self, expected_acl: hci.Acl, timeout: int = 3):
        packet = await asyncio.wait_for(self.controller.receive_acl(), timeout=timeout)
        acl = hci.Acl.parse_all(packet)

        if acl != expected_acl:
            print("received unexpected acl packet")
            print("expected packet:")
            expected_acl.show()
            print("received packet:")
            acl.show()
            self.assertTrue(False)

    async def expect_iso(self, expected_iso: hci.Iso, timeout: int = 3):
        packet = await asyncio.wait_for(self.controller.receive_iso(), timeout=timeout)
        iso = hci.Iso.parse_all(packet)

        if iso != expected_iso:
            print("received unexpected iso packet")
            print("expected packet:")
            expected_iso.show()
            print("received packet:")
            iso.show()
            self.assertTrue(False)

    async def expect_ll(
        self,
        expected_pdus: typing.Union[list, typing.Union[ll.LinkLayerPacket, type]],
        ignored_pdus: typing.Union[list, type] = [],
        timeout: int = 3,
    ) -> ll.LinkLayerPacket:
        if not isinstance(ignored_pdus, list):
            ignored_pdus = [ignored_pdus]

        if not isinstance(expected_pdus, list):
            expected_pdus = [expected_pdus]

        async with asyncio.timeout(timeout):
            while True:
                packet = await self.controller.receive_ll()
                pdu = ll.LinkLayerPacket.parse_all(packet)

                for ignored_pdu in ignored_pdus:
                    if isinstance(pdu, ignored_pdu):
                        continue

                for expected_pdu in expected_pdus:
                    if isinstance(expected_pdu, type) and isinstance(pdu, expected_pdu):
                        return pdu
                    if (
                        isinstance(expected_pdu, ll.LinkLayerPacket)
                        and pdu == expected_pdu
                    ):
                        return pdu

                print("received unexpected pdu:")
                pdu.show()
                print("expected pdus:")
                for expected_pdu in expected_pdus:
                    if isinstance(expected_pdu, type):
                        print(f"- {expected_pdu.__name__}")
                    if isinstance(expected_pdu, ll.LinkLayerPacket):
                        print(f"- {expected_pdu.__class__.__name__}")
                        expected_pdu.show()

                self.assertTrue(False)

    async def expect_llcp(
        self,
        source_address: hci.Address,
        destination_address: hci.Address,
        expected_pdu: llcp.LlcpPacket,
        timeout: int = 3,
    ) -> llcp.LlcpPacket:
        packet = await asyncio.wait_for(self.controller.receive_ll(), timeout=timeout)
        pdu = ll.LinkLayerPacket.parse_all(packet)

        if (
            pdu.type != ll.PacketType.LLCP
            or pdu.source_address != source_address
            or pdu.destination_address != destination_address
        ):
            print("received unexpected pdu:")
            pdu.show()
            print(f"expected pdu: {source_address} -> {destination_address}")
            expected_pdu.show()
            self.assertTrue(False)

        pdu = llcp.LlcpPacket.parse_all(pdu.payload)
        if pdu != expected_pdu:
            print("received unexpected pdu:")
            pdu.show()
            print("expected pdu:")
            expected_pdu.show()
            self.assertTrue(False)

        return pdu

    async def enable_connected_isochronous_stream_host_support(self):
        """Enable Connected Isochronous Stream Host Support in the LE Feature mask."""
        self.controller.send_cmd(
            hci.LeSetHostFeatureV1(
                bit_number=hci.LeHostFeatureBits.CONNECTED_ISO_STREAM_HOST_SUPPORT,
                bit_value=hci.Enable.ENABLED,
            )
        )

        await self.expect_evt(
            hci.LeSetHostFeatureV1Complete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

    async def enable_channel_sounding_host_support(self):
        """Enable Channel Sounding Host Support in the LE Feature mask."""
        self.controller.send_cmd(
            hci.LeSetHostFeatureV1(
                bit_number=hci.LeHostFeatureBits.CHANNEL_SOUNDING_HOST_SUPPORT,
                bit_value=hci.Enable.ENABLED,
            )
        )

        await self.expect_evt(
            hci.LeSetHostFeatureV1Complete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

    async def establish_le_connection_central(self, peer_address: hci.Address) -> int:
        """Establish a connection with the selected peer as Central.
        Returns the ACL connection handle for the opened link."""
        self.controller.send_cmd(
            hci.LeExtendedCreateConnectionV1(
                initiator_filter_policy=hci.InitiatorFilterPolicy.USE_PEER_ADDRESS,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                peer_address=peer_address,
                initiating_phys=0x1,
                initiating_phy_parameters=[
                    hci.InitiatingPhyParameters(
                        scan_interval=0x200,
                        scan_window=0x100,
                        connection_interval_min=0x200,
                        connection_interval_max=0x200,
                        max_latency=0x6,
                        supervision_timeout=0xC80,
                        min_ce_length=0,
                        max_ce_length=0,
                    )
                ],
            )
        )

        await self.expect_evt(
            hci.LeExtendedCreateConnectionV1Status(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        self.controller.send_ll(
            ll.LeLegacyAdvertisingPdu(
                source_address=peer_address,
                advertising_address_type=ll.AddressType.PUBLIC,
                advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                advertising_data=[],
            ),
            rssi=-16,
        )

        await self.expect_ll(
            ll.LeConnect(
                source_address=self.controller.address,
                destination_address=peer_address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.PUBLIC,
                conn_interval=0x200,
                conn_peripheral_latency=0x6,
                conn_supervision_timeout=0xC80,
            )
        )

        self.controller.send_ll(
            ll.LeConnectComplete(
                source_address=peer_address,
                destination_address=self.controller.address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.PUBLIC,
                conn_interval=0x200,
                conn_peripheral_latency=0x6,
                conn_supervision_timeout=0xC80,
            )
        )

        connection_complete = await self.expect_evt(
            hci.LeEnhancedConnectionCompleteV1(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                role=hci.Role.CENTRAL,
                peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                peer_address=peer_address,
                connection_interval=0x200,
                peripheral_latency=0x6,
                supervision_timeout=0xC80,
                central_clock_accuracy=hci.ClockAccuracy.PPM_500,
            )
        )

        acl_connection_handle = connection_complete.connection_handle
        await self.expect_evt(
            hci.LeChannelSelectionAlgorithm(
                connection_handle=acl_connection_handle,
                channel_selection_algorithm=hci.ChannelSelectionAlgorithm.ALGORITHM_1,
            )
        )

        return acl_connection_handle

    async def le_start_encryption(
        self, acl_connection_handle: int, peer_address: hci.Address
    ):
        """Start LE encryption procedure."""
        controller = self.controller
        controller.send_cmd(
            hci.LeStartEncryption(
                connection_handle=acl_connection_handle,
                rand=[0] * 8,
                ediv=0,
                ltk=[1] * 16,
            )
        )
        await self.expect_evt(
            hci.LeStartEncryptionStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )
        await self.expect_ll(
            ll.LeEncryptConnection(
                source_address=controller.address,
                destination_address=peer_address,
                rand=[0] * 8,
                ediv=0,
                ltk=[1] * 16,
            )
        )
        controller.send_ll(
            ll.LeEncryptConnectionResponse(
                source_address=peer_address,
                destination_address=controller.address,
                rand=[0] * 8,
                ediv=0,
                ltk=[1] * 16,
            )
        )

        await self.expect_evt(
            [
                hci.EncryptionChange(
                    status=ErrorCode.SUCCESS,
                    connection_handle=acl_connection_handle,
                    encryption_enabled=hci.EncryptionEnabled.ON,
                ),
                hci.EncryptionKeyRefreshComplete(
                    status=ErrorCode.SUCCESS, connection_handle=acl_connection_handle
                ),
            ]
        )

    async def establish_le_connection_peripheral(
        self, peer_address: hci.Address
    ) -> int:
        """Establish a connection with the selected peer as Peripheral.
        Returns the ACL connection handle for the opened link."""
        self.controller.send_cmd(
            hci.LeSetAdvertisingParameters(
                advertising_interval_min=0x200,
                advertising_interval_max=0x200,
                advertising_type=hci.AdvertisingType.ADV_IND,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                advertising_channel_map=0x7,
                advertising_filter_policy=hci.AdvertisingFilterPolicy.ALL_DEVICES,
            )
        )

        await self.expect_evt(
            hci.LeSetAdvertisingParametersComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        self.controller.send_cmd(hci.LeSetAdvertisingEnable(advertising_enable=True))

        await self.expect_evt(
            hci.LeSetAdvertisingEnableComplete(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        self.controller.send_ll(
            ll.LeConnect(
                source_address=peer_address,
                destination_address=self.controller.address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.PUBLIC,
                conn_interval=0x200,
                conn_peripheral_latency=0x200,
                conn_supervision_timeout=0x200,
            ),
            rssi=-16,
        )

        await self.expect_ll(
            ll.LeConnectComplete(
                source_address=self.controller.address,
                destination_address=peer_address,
                conn_interval=0x200,
                conn_peripheral_latency=0x200,
                conn_supervision_timeout=0x200,
            )
        )

        connection_complete = await self.expect_evt(
            hci.LeEnhancedConnectionCompleteV1(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                role=hci.Role.PERIPHERAL,
                peer_address_type=hci.AddressType.PUBLIC_DEVICE_ADDRESS,
                peer_address=peer_address,
                connection_interval=0x200,
                peripheral_latency=0x200,
                supervision_timeout=0x200,
                central_clock_accuracy=hci.ClockAccuracy.PPM_500,
            )
        )

        return connection_complete.connection_handle

    def tearDown(self):
        self.controller.stop()
