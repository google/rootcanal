# Copyright (C) 2026 Google LLC
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
import unittest
from hci_packets import ErrorCode
from py.bluetooth import Address
from py.controller import ControllerTest


class Test(ControllerTest):

    # Verify that encryption can be enabled and that the LTK is stored
    # in the connection object (and thus survives even if multiple
    # encryption attempts are made on the same connection, or across
    # different connections).
    async def test_le_encryption_success(self):
        controller = self.controller
        peer_address = Address("aa:bb:cc:dd:ee:01")

        # 1. Connect
        controller.send_cmd(
            hci.LeCreateConnection(
                le_scan_interval=0x40,
                le_scan_window=0x40,
                initiator_filter_policy=hci.InitiatorFilterPolicy.USE_PEER_ADDRESS,
                peer_address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                peer_address=peer_address,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                connection_interval_min=0x20,
                connection_interval_max=0x20,
                max_latency=0,
                supervision_timeout=0x100,
                min_ce_length=0,
                max_ce_length=0,
            )
        )

        await self.expect_evt(
            hci.LeCreateConnectionStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # Send advertising PDU to trigger the connection
        controller.send_ll(
            ll.LeLegacyAdvertisingPdu(
                source_address=peer_address,
                advertising_address_type=ll.AddressType.RANDOM,
                advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                advertising_data=[],
            )
        )

        # Expect LeConnect from the controller
        await self.expect_ll(
            ll.LeConnect(
                source_address=controller.address,
                destination_address=peer_address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.RANDOM,
                conn_interval=0x20,
                conn_peripheral_latency=0,
                conn_supervision_timeout=0x100,
            )
        )

        # Peer sends LeConnectComplete back
        controller.send_ll(
            ll.LeConnectComplete(
                source_address=peer_address,
                destination_address=controller.address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.RANDOM,
                conn_interval=0x20,
                conn_peripheral_latency=0,
                conn_supervision_timeout=0x100,
            )
        )

        # Wait for LeEnhancedConnectionCompleteV1
        evt = await self.expect_evt(
            hci.LeEnhancedConnectionCompleteV1(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                role=hci.Role.CENTRAL,
                peer_address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                peer_address=peer_address,
                connection_interval=0x20,
                peripheral_latency=0,
                supervision_timeout=0x100,
                central_clock_accuracy=hci.ClockAccuracy.PPM_500,
            )
        )
        handle = evt.connection_handle

        # 2. Start Encryption
        ltk = [
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
        ]
        rand = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        ediv = 0x1234

        controller.send_cmd(
            hci.LeStartEncryption(
                connection_handle=handle, rand=rand, ediv=ediv, ltk=ltk
            )
        )

        await self.expect_evt(
            hci.LeStartEncryptionStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        # Expect LL_ENCRYPT_CONNECTION
        await self.expect_ll(
            ll.LeEncryptConnection(
                source_address=controller.address,
                destination_address=peer_address,
                rand=rand,
                ediv=ediv,
                ltk=ltk,
            )
        )

        # 3. Peripheral responds with SUCCESS status
        controller.send_ll(
            ll.LeEncryptConnectionResponse(
                source_address=peer_address,
                destination_address=controller.address,
                status=0,  # SUCCESS
                rand=[0] * 8,
                ediv=0,
                ltk=ltk,
            )
        )

        # Expect Encryption Change event
        await self.expect_evt(
            hci.EncryptionChange(
                status=ErrorCode.SUCCESS,
                connection_handle=handle,
                encryption_enabled=hci.EncryptionEnabled.ON,
            )
        )

    async def test_le_encryption_key_missing(self):
        controller = self.controller
        peer_address = Address("aa:bb:cc:dd:ee:02")

        # 1. Connect
        controller.send_cmd(
            hci.LeCreateConnection(
                le_scan_interval=0x40,
                le_scan_window=0x40,
                initiator_filter_policy=hci.InitiatorFilterPolicy.USE_PEER_ADDRESS,
                peer_address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                peer_address=peer_address,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                connection_interval_min=0x20,
                connection_interval_max=0x20,
                max_latency=0,
                supervision_timeout=0x100,
                min_ce_length=0,
                max_ce_length=0,
            )
        )

        await self.expect_evt(
            hci.LeCreateConnectionStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        controller.send_ll(
            ll.LeLegacyAdvertisingPdu(
                source_address=peer_address,
                advertising_address_type=ll.AddressType.RANDOM,
                advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                advertising_data=[],
            )
        )

        await self.expect_ll(
            ll.LeConnect(
                source_address=controller.address,
                destination_address=peer_address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.RANDOM,
                conn_interval=0x20,
                conn_peripheral_latency=0,
                conn_supervision_timeout=0x100,
            )
        )

        controller.send_ll(
            ll.LeConnectComplete(
                source_address=peer_address,
                destination_address=controller.address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.RANDOM,
                conn_interval=0x20,
                conn_peripheral_latency=0,
                conn_supervision_timeout=0x100,
            )
        )

        evt = await self.expect_evt(
            hci.LeEnhancedConnectionCompleteV1(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                role=hci.Role.CENTRAL,
                peer_address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                peer_address=peer_address,
                connection_interval=0x20,
                peripheral_latency=0,
                supervision_timeout=0x100,
                central_clock_accuracy=hci.ClockAccuracy.PPM_500,
            )
        )
        handle = evt.connection_handle

        # 2. Start Encryption
        ltk = [
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x11,
        ]  # Different LTK
        rand = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        ediv = 0x1234

        controller.send_cmd(
            hci.LeStartEncryption(
                connection_handle=handle, rand=rand, ediv=ediv, ltk=ltk
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
                rand=rand,
                ediv=ediv,
                ltk=ltk,
            )
        )

        # 3. Peripheral responds with PIN_OR_KEY_MISSING status
        controller.send_ll(
            ll.LeEncryptConnectionResponse(
                source_address=peer_address,
                destination_address=controller.address,
                status=int(ErrorCode.PIN_OR_KEY_MISSING),
                rand=[0] * 8,
                ediv=0,
                ltk=[0] * 16,
            )
        )

        # Expect Encryption Change event with FAILURE
        await self.expect_evt(
            hci.EncryptionChange(
                status=ErrorCode.PIN_OR_KEY_MISSING,
                connection_handle=handle,
                encryption_enabled=hci.EncryptionEnabled.OFF,
            )
        )

    async def test_le_encryption_authentication_failure(self):
        controller = self.controller
        peer_address = Address("aa:bb:cc:dd:ee:03")

        # 1. Connect
        controller.send_cmd(
            hci.LeCreateConnection(
                le_scan_interval=0x40,
                le_scan_window=0x40,
                initiator_filter_policy=hci.InitiatorFilterPolicy.USE_PEER_ADDRESS,
                peer_address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                peer_address=peer_address,
                own_address_type=hci.OwnAddressType.PUBLIC_DEVICE_ADDRESS,
                connection_interval_min=0x20,
                connection_interval_max=0x20,
                max_latency=0,
                supervision_timeout=0x100,
                min_ce_length=0,
                max_ce_length=0,
            )
        )

        await self.expect_evt(
            hci.LeCreateConnectionStatus(
                status=ErrorCode.SUCCESS, num_hci_command_packets=1
            )
        )

        controller.send_ll(
            ll.LeLegacyAdvertisingPdu(
                source_address=peer_address,
                advertising_address_type=ll.AddressType.RANDOM,
                advertising_type=ll.LegacyAdvertisingType.ADV_IND,
                advertising_data=[],
            )
        )

        await self.expect_ll(
            ll.LeConnect(
                source_address=controller.address,
                destination_address=peer_address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.RANDOM,
                conn_interval=0x20,
                conn_peripheral_latency=0,
                conn_supervision_timeout=0x100,
            )
        )

        controller.send_ll(
            ll.LeConnectComplete(
                source_address=peer_address,
                destination_address=controller.address,
                initiating_address_type=ll.AddressType.PUBLIC,
                advertising_address_type=ll.AddressType.RANDOM,
                conn_interval=0x20,
                conn_peripheral_latency=0,
                conn_supervision_timeout=0x100,
            )
        )

        evt = await self.expect_evt(
            hci.LeEnhancedConnectionCompleteV1(
                status=ErrorCode.SUCCESS,
                connection_handle=self.Any,
                role=hci.Role.CENTRAL,
                peer_address_type=hci.AddressType.RANDOM_DEVICE_ADDRESS,
                peer_address=peer_address,
                connection_interval=0x20,
                peripheral_latency=0,
                supervision_timeout=0x100,
                central_clock_accuracy=hci.ClockAccuracy.PPM_500,
            )
        )
        handle = evt.connection_handle

        # 2. Start Encryption
        ltk = [0x01] * 16
        rand = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        ediv = 0x1234

        controller.send_cmd(
            hci.LeStartEncryption(
                connection_handle=handle, rand=rand, ediv=ediv, ltk=ltk
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
                rand=rand,
                ediv=ediv,
                ltk=ltk,
            )
        )

        # 3. Peripheral responds with a DIFFERENT LTK
        controller.send_ll(
            ll.LeEncryptConnectionResponse(
                source_address=peer_address,
                destination_address=controller.address,
                status=0,  # SUCCESS
                rand=[0] * 8,
                ediv=0,
                ltk=[0x02] * 16,
            )
        )

        # Expect Encryption Change event with AUTHENTICATION_FAILURE
        await self.expect_evt(
            hci.EncryptionChange(
                status=ErrorCode.AUTHENTICATION_FAILURE,
                connection_handle=handle,
                encryption_enabled=hci.EncryptionEnabled.OFF,
            )
        )
