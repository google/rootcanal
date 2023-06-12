#!/usr/bin/env python3

# Copyright 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Dump the configuration of a Bluetooth controller.

The script expects to find the generated module hci_packets
in PYTHONPATH.

The controller is expected to be available through HCI over TCP
at the port passed as parameter."""

import argparse
import asyncio
import collections
import sys

import hci_packets as hci

H4_IDC_CMD = 0x01
H4_IDC_ACL = 0x02
H4_IDC_SCO = 0x03
H4_IDC_EVT = 0x04
H4_IDC_ISO = 0x05

HCI_HEADER_SIZES = dict([(H4_IDC_CMD, 3), (H4_IDC_ACL, 4), (H4_IDC_SCO, 3), (H4_IDC_EVT, 2), (H4_IDC_ISO, 4)])


class Host:

    def __init__(self):
        self.evt_queue = collections.deque()
        self.evt_queue_event = asyncio.Event()

    async def connect(self, ip: str, port: int):
        reader, writer = await asyncio.open_connection(ip, port)
        self.reader = asyncio.create_task(self._read(reader))
        self.writer = writer

    async def _read(self, reader):
        try:
            while True:
                idc = await reader.readexactly(1)

                assert idc[0] in HCI_HEADER_SIZES
                header = await reader.readexactly(HCI_HEADER_SIZES[idc[0]])

                if idc[0] == H4_IDC_EVT:
                    evt = hci.Event.parse_all(header + (await reader.readexactly(header[1])))
                    #print(f"<< {evt.__class__.__name__}")
                    self.evt_queue.append(evt)
                    self.evt_queue_event.set()
                else:
                    assert False
        except Exception as exn:
            print(f"Reader interrupted: {exn}")
            return

    async def send_cmd(self, cmd: hci.Command):
        #print(f">> {cmd.__class__.__name__}")
        packet = bytes([H4_IDC_CMD]) + cmd.serialize()
        self.writer.write(packet)

    async def recv_evt(self) -> hci.Event:
        while not self.evt_queue:
            await self.evt_queue_event.wait()
            self.evt_queue_event.clear()
        return self.evt_queue.popleft()

    async def expect_evt(self, expected_evt: type) -> hci.Event:
        evt = await self.recv_evt()
        assert isinstance(evt, expected_evt)
        if not isinstance(evt, expected_evt):
            print("Received unexpected event:")
            evt.show()
            print(f"Expected event of type {expected_evt.__name__}")
            print(f"{list(evt.payload)}")
        return evt


async def br_edr_properties(host: Host):
    await host.send_cmd(hci.ReadLocalSupportedFeatures())
    page0 = await host.expect_evt(hci.ReadLocalSupportedFeaturesComplete)
    await host.send_cmd(hci.ReadLocalExtendedFeatures(page_number=1))
    page1 = await host.expect_evt(hci.ReadLocalExtendedFeaturesComplete)
    await host.send_cmd(hci.ReadLocalExtendedFeatures(page_number=2))
    page2 = await host.expect_evt(hci.ReadLocalExtendedFeaturesComplete)

    print(
        f"lmp_features: {{ 0x{page0.lmp_features:x}, 0x{page1.extended_lmp_features:x}, 0x{page2.extended_lmp_features:x} }}"
    )

    await host.send_cmd(hci.ReadBufferSize())
    evt = await host.expect_evt(hci.ReadBufferSizeComplete)

    print(f"acl_data_packet_length: {evt.acl_data_packet_length}")
    print(f"total_num_acl_data_packets: {evt.total_num_acl_data_packets}")
    print(f"sco_data_packet_length: {evt.synchronous_data_packet_length}")
    print(f"total_num_sco_data_packets: {evt.total_num_synchronous_data_packets}")

    await host.send_cmd(hci.ReadNumberOfSupportedIac())
    evt = await host.expect_evt(hci.ReadNumberOfSupportedIacComplete)

    print(f"num_supported_iac: {evt.num_support_iac}")


async def le_properties(host: Host):
    await host.send_cmd(hci.LeReadLocalSupportedFeatures())
    evt = await host.expect_evt(hci.LeReadLocalSupportedFeaturesComplete)

    print(f"le_features: 0x{evt.le_features:x}")

    await host.send_cmd(hci.LeReadBufferSizeV2())
    evt = await host.expect_evt(hci.LeReadBufferSizeV2Complete)

    print(f"le_acl_data_packet_length: {evt.le_buffer_size.le_data_packet_length}")
    print(f"total_num_le_acl_data_packets: {evt.le_buffer_size.total_num_le_packets}")
    print(f"iso_data_packet_length: {evt.iso_buffer_size.le_data_packet_length}")
    print(f"total_num_iso_data_packets: {evt.iso_buffer_size.total_num_le_packets}")

    await host.send_cmd(hci.LeReadFilterAcceptListSize())
    evt = await host.expect_evt(hci.LeReadFilterAcceptListSizeComplete)

    print(f"le_filter_accept_list_size: {evt.filter_accept_list_size}")

    await host.send_cmd(hci.LeReadResolvingListSize())
    evt = await host.expect_evt(hci.LeReadResolvingListSizeComplete)

    print(f"le_resolving_list_size: {evt.resolving_list_size}")

    await host.send_cmd(hci.LeReadSupportedStates())
    evt = await host.expect_evt(hci.LeReadSupportedStatesComplete)

    print(f"le_supported_states: 0x{evt.le_states:x}")

    await host.send_cmd(hci.LeReadMaximumAdvertisingDataLength())
    evt = await host.expect_evt(hci.LeReadMaximumAdvertisingDataLengthComplete)

    print(f"le_max_advertising_data_length: {evt.maximum_advertising_data_length}")

    await host.send_cmd(hci.LeReadNumberOfSupportedAdvertisingSets())
    evt = await host.expect_evt(hci.LeReadNumberOfSupportedAdvertisingSetsComplete)

    print(f"le_num_supported_advertising_sets: {evt.number_supported_advertising_sets}")

    await host.send_cmd(hci.LeReadPeriodicAdvertiserListSize())
    evt = await host.expect_evt(hci.LeReadPeriodicAdvertiserListSizeComplete)

    print(f"le_periodic_advertiser_list_size: {evt.periodic_advertiser_list_size}")


async def run(tcp_port: int):
    host = Host()
    await host.connect('127.0.0.1', tcp_port)

    await host.send_cmd(hci.Reset())
    await host.expect_evt(hci.ResetComplete)

    await host.send_cmd(hci.ReadLocalVersionInformation())
    evt = await host.expect_evt(hci.ReadLocalVersionInformationComplete)

    print(f"hci_version: {evt.local_version_information.hci_version}")
    print(f"hci_subversion: 0x{evt.local_version_information.hci_revision:x}")
    print(f"lmp_version: {evt.local_version_information.lmp_version}")
    print(f"lmp_subversion: 0x{evt.local_version_information.lmp_subversion:x}")
    print(f"company_identifier: 0x{evt.local_version_information.manufacturer_name:x}")

    await host.send_cmd(hci.ReadLocalSupportedCommands())
    evt = await host.expect_evt(hci.ReadLocalSupportedCommandsComplete)

    print(f"supported_commands: {{ {', '.join([f'0x{b:x}' for b in evt.supported_commands])} }}")

    try:
        await br_edr_properties(host)
    except Exception:
        pass

    try:
        await le_properties(host)
    except Exception:
        pass


def main() -> int:
    """Generate cxx PDL backend."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tcp_port', type=int, help='HCI port')
    return asyncio.run(run(**vars(parser.parse_args())))


if __name__ == '__main__':
    sys.exit(main())
