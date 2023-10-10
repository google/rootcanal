# Copyright 2023 The Android Open Source Project
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
from .packets import hci
from .packets import ll
from .packets import llcp
from .packets.hci import ErrorCode
from . import bluetooth
from . import binaries
import sys
import typing
import unittest
from typing import Optional, Tuple, Union

from ctypes import *

librootcanal_ffi_path = binaries.get_package_binary_resource_path("librootcanal_ffi.so")
rootcanal = cdll.LoadLibrary(librootcanal_ffi_path)
rootcanal.ffi_controller_new.restype = c_void_p

SEND_HCI_FUNC = CFUNCTYPE(None, c_int, POINTER(c_ubyte), c_size_t)
SEND_LL_FUNC = CFUNCTYPE(None, POINTER(c_ubyte), c_size_t, c_int, c_int)


class Idc(enum.IntEnum):
    Cmd = 1
    Acl = 2
    Sco = 3
    Evt = 4
    Iso = 5


class Phy(enum.IntEnum):
    LowEnergy = 0
    BrEdr = 1


class LeFeatures:
    def __init__(self, le_features: int):
        self.mask = le_features
        self.ll_privacy = (le_features & hci.LLFeaturesBits.LL_PRIVACY) != 0
        self.le_extended_advertising = (
            le_features & hci.LLFeaturesBits.LE_EXTENDED_ADVERTISING
        ) != 0
        self.le_periodic_advertising = (
            le_features & hci.LLFeaturesBits.LE_PERIODIC_ADVERTISING
        ) != 0


def generate_rpa(irk: bytes) -> hci.Address:
    rpa = bytearray(6)
    rpa_type = c_char * 6
    rootcanal.ffi_generate_rpa(c_char_p(irk), rpa_type.from_buffer(rpa))
    rpa.reverse()
    return hci.Address(bytes(rpa))


class Any:
    """Helper class that will match all other values.
    Use an instance of this class in expected packets to match any value
    returned by the Controller stack."""

    def __eq__(self, other) -> bool:
        return True

    def __format__(self, format_spec: str) -> str:
        return "_"


class Controller:
    """Binder class over RootCanal's ffi interfaces.
    The methods send_cmd, send_hci, send_ll are used to inject HCI or LL
    packets into the controller, and receive_hci, receive_ll to
    catch outgoing HCI packets of LL pdus."""

    def __init__(self, address: hci.Address):
        # Write the callbacks for handling HCI and LL send events.
        @SEND_HCI_FUNC
        def send_hci(idc: c_int, data: POINTER(c_ubyte), data_len: c_size_t):
            packet = []
            for n in range(data_len):
                packet.append(data[n])
            self.receive_hci_(int(idc), bytes(packet))

        @SEND_LL_FUNC
        def send_ll(
            data: POINTER(c_ubyte), data_len: c_size_t, phy: c_int, tx_power: c_int
        ):
            packet = []
            for n in range(data_len):
                packet.append(data[n])
            self.receive_ll_(bytes(packet), int(phy), int(tx_power))

        self.send_hci_callback = SEND_HCI_FUNC(send_hci)
        self.send_ll_callback = SEND_LL_FUNC(send_ll)

        # Create a c++ controller instance.
        self.instance = rootcanal.ffi_controller_new(
            c_char_p(address.address), self.send_hci_callback, self.send_ll_callback
        )

        self.address = address
        self.evt_queue = asyncio.Queue()
        self.acl_queue = asyncio.Queue()
        self.iso_queue = asyncio.Queue()
        self.ll_queue = asyncio.Queue()

    def __del__(self):
        rootcanal.ffi_controller_delete(c_void_p(self.instance))

    def receive_hci_(self, idc: int, packet: bytes):
        if idc == Idc.Evt:
            print(f"<-- received HCI event data={len(packet)}[..]")
            self.evt_queue.put_nowait(packet)
        elif idc == Idc.Acl:
            print(f"<-- received HCI ACL packet data={len(packet)}[..]")
            self.acl_queue.put_nowait(packet)
        elif idc == Idc.Iso:
            print(f"<-- received HCI ISO packet data={len(packet)}[..]")
            self.iso_queue.put_nowait(packet)
        else:
            print(f"ignoring HCI packet typ={idc}")

    def receive_ll_(self, packet: bytes, phy: int, tx_power: int):
        print(f"<-- received LL pdu data={len(packet)}[..]")
        self.ll_queue.put_nowait(packet)

    def send_cmd(self, cmd: hci.Command):
        print(f"--> sending HCI command {cmd.__class__.__name__}")
        data = cmd.serialize()
        rootcanal.ffi_controller_receive_hci(
            c_void_p(self.instance), c_int(Idc.Cmd), c_char_p(data), c_int(len(data))
        )

    def send_iso(self, iso: hci.Iso):
        print(f"--> sending HCI iso pdu data={len(iso.payload)}[..]")
        data = iso.serialize()
        rootcanal.ffi_controller_receive_hci(
            c_void_p(self.instance), c_int(Idc.Iso), c_char_p(data), c_int(len(data))
        )

    def send_ll(
        self, pdu: ll.LinkLayerPacket, phy: Phy = Phy.LowEnergy, rssi: int = -90
    ):
        print(f"--> sending LL pdu {pdu.__class__.__name__}")
        data = pdu.serialize()
        rootcanal.ffi_controller_receive_ll(
            c_void_p(self.instance),
            c_char_p(data),
            c_int(len(data)),
            c_int(phy),
            c_int(rssi),
        )

    def send_llcp(
        self,
        source_address: hci.Address,
        destination_address: hci.Address,
        pdu: llcp.LlcpPacket,
        phy: Phy = Phy.LowEnergy,
        rssi: int = -90,
    ):
        print(f"--> sending LLCP pdu {pdu.__class__.__name__}")
        ll_pdu = ll.Llcp(
            source_address=source_address,
            destination_address=destination_address,
            payload=pdu.serialize(),
        )
        data = ll_pdu.serialize()
        rootcanal.ffi_controller_receive_ll(
            c_void_p(self.instance),
            c_char_p(data),
            c_int(len(data)),
            c_int(phy),
            c_int(rssi),
        )

    async def start(self):
        async def timer():
            while True:
                await asyncio.sleep(0.005)
                rootcanal.ffi_controller_tick(c_void_p(self.instance))

        # Spawn the controller timer task.
        self.timer_task = asyncio.create_task(timer())

    def stop(self):
        # Cancel the controller timer task.
        del self.timer_task

        if self.evt_queue.qsize() > 0:
            try:
                print("evt queue not empty at stop():")
                while packet := self.evt_queue.get_nowait():
                    evt = hci.Event.parse_all(packet)
                    evt.show()
            except asyncio.QueueEmpty:
                pass
            raise Exception("evt queue not empty at stop()")

        if self.iso_queue.qsize() > 0:
            try:
                print("iso queue not empty at stop():")
                while packet := self.iso_queue.get_nowait():
                    iso = hci.Event.parse_all(packet)
                    iso.show()
            except asyncio.QueueEmpty:
                pass
            raise Exception("iso queue not empty at stop()")

        if self.ll_queue.qsize() > 0:
            try:
                print("ll queue not empty at stop():")
                while packet := self.ll_queue.get_nowait():
                    ll = hci.Event.parse_all(packet)
                    ll.show()
            except asyncio.QueueEmpty:
                pass
            raise Exception("ll queue not empty at stop()")

    async def receive_evt(self):
        return await self.evt_queue.get()

    async def receive_iso(self):
        return await self.iso_queue.get()

    async def receive_ll(self):
        return await self.ll_queue.get()

    async def expect_evt(self, expected_evt: hci.Event):
        packet = await self.receive_evt()
        evt = hci.Event.parse_all(packet)
        if evt != expected_evt:
            print("received unexpected event")
            print("expected event:")
            expected_evt.show()
            print("received event:")
            evt.show()
            raise Exception(f"unexpected evt {evt.__class__.__name__}")

    async def expect_evt(
        self, expected_evt: typing.Union[hci.Event, type], timeout: float = 3.0
    ) -> hci.Event:
        """Wait for an event being sent from the controller.

        Raises ValueError if the event does not match the expected type or value.
        Raises TimeoutError if no event is received after `timeout` seconds.
        Returns the received event on success.
        """
        packet = await asyncio.wait_for(self.receive_evt(), timeout=timeout)
        evt = hci.Event.parse_all(packet)

        if isinstance(expected_evt, type) and not isinstance(evt, expected_evt):
            raise ValueError(
                f"received unexpected event {evt.__class__.__name__},"
                + f" expected {expected_evt.__name__}"
            )

        if isinstance(expected_evt, hci.Event) and evt != expected_evt:
            raise ValueError(
                f"received unexpected event {evt.__class__.__name__},"
                + f" expected {expected_evt.__name__}"
            )

        return evt

    async def expect_cmd_complete(
        self, expected_evt: type, timeout: float = 3.0
    ) -> hci.Event:
        """Wait for an event being sent from the controller.

        Raises ValueError if the event does not match the expected type, or
        has an invalid status or number of completed packets.
        Raises TimeoutError if no event is received after `timeout` seconds.
        Returns the received event on success.
        """
        evt = await self.expect_evt(expected_evt, timeout=timeout)

        if evt.status != ErrorCode.SUCCESS:
            raise ValueError(
                "received command complete event with the"
                + f" error status {evt.status}"
            )

        if evt.num_hci_command_packets != 1:
            raise ValueError(
                "received command complete event with an invalid number"
                + f" of completed packets {evt.num_hci_command_packets}"
            )

        return evt

    async def expect_ll(
        self,
        expected_pdus: typing.Union[list, typing.Union[ll.LinkLayerPacket, type]],
        timeout: float = 3.0,
    ) -> ll.LinkLayerPacket:
        """Wait for a link layer packet being sent from the controller.

        Raises ValueError if the event does not match the expected types or values.
        Raises TimeoutError if no event is received after `timeout` seconds.
        Returns the received event on success.
        """
        if not isinstance(expected_pdus, list):
            expected_pdus = [expected_pdus]

        packet = await asyncio.wait_for(self.receive_ll(), timeout=timeout)
        pdu = ll.LinkLayerPacket.parse_all(packet)

        for expected_pdu in expected_pdus:
            if isinstance(expected_pdu, type) and isinstance(pdu, expected_pdu):
                return pdu
            if isinstance(expected_pdu, ll.LinkLayerPacket) and pdu == expected_pdu:
                return pdu

        raise ValueError(f"received unexpected pdu {pdu.__class__.__name__}")

    async def expect_llcp(
        self,
        source_address: hci.Address,
        destination_address: hci.Address,
        expected_pdu: typing.Union[llcp.LlcpPacket, type],
        timeout: float = 3.0,
    ) -> llcp.LlcpPacket:
        """Wait for a LLCP packet being sent from the controller.

        Raises ValueError if the event does not match the expected type or value.
        Raises TimeoutError if no event is received after `timeout` seconds.
        Returns the received event on success.
        """
        packet = await asyncio.wait_for(self.controller.receive_ll(), timeout=timeout)
        pdu = ll.LinkLayerPacket.parse_all(packet)

        if pdu.type != ll.PacketType.LLCP:
            raise ValueError(f"received unexpected pdu {pdu.__class__.__name__}")

        if (
            pdu.source_address != source_address
            or pdu.destination_address != destination_address
        ):
            raise ValueError(
                f"received unexpected pdu addressed from"
                + f" {source_address} to {destination_address}"
            )

        pdu = llcp.LlcpPacket.parse_all(pdu.payload)

        if isinstance(expected_pdu, type) and not isinstance(pdu, expected_pdu):
            raise ValueError(
                f"received unexpected pdu {pdu.__class__.__name__},"
                + f" expected {expected_pdu.__name__}"
            )

        if isinstance(expected_pdu, hci.LlcpPacket) and pdu != expected_pdu:
            raise ValueError(
                f"received unexpected pdu {pdu.__class__.__name__},"
                + f" expected {expected_pdu.__name__}"
            )

        return pdu

    async def expect_iso(self, expected_iso: hci.Iso, timeout: float = 3.0) -> hci.Iso:
        packet = await asyncio.wait_for(self.receive_iso(), timeout=timeout)
        iso = hci.Iso.parse_all(packet)

        if iso != expected_iso:
            raise ValueError("received unexpected iso packet")

        return iso
