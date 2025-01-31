# Copyright 2024 Google LLC
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

    # HCI/AEN/BV-06-C [Public Keys]
    #
    # Verify that the IUT can generate a P-256 Public-Private key pair and
    # return the P-256 Public Key
    async def test(self):
        controller = self.controller

        controller.send_cmd(hci.LeReadLocalP256PublicKey())

        await self.expect_evt(hci.LeReadLocalP256PublicKeyStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        first = await self.expect_evt(
            hci.LeReadLocalP256PublicKeyComplete(status=ErrorCode.SUCCESS,
                                                 key_x_coordinate=self.Any,
                                                 key_y_coordinate=self.Any))

        controller.send_cmd(hci.LeReadLocalP256PublicKey())

        await self.expect_evt(hci.LeReadLocalP256PublicKeyStatus(status=ErrorCode.SUCCESS, num_hci_command_packets=1))

        second = await self.expect_evt(
            hci.LeReadLocalP256PublicKeyComplete(status=ErrorCode.SUCCESS,
                                                 key_x_coordinate=self.Any,
                                                 key_y_coordinate=self.Any))

        self.assertTrue(
            (first.key_x_coordinate, first.key_y_coordinate) != (second.key_x_coordinate, second.key_y_coordinate))
