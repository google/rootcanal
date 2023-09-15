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

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(init=False)
class Address:
    address: bytes = field(default=bytes([0, 0, 0, 0, 0, 0]))

    def __init__(self, address=None):
        if not address:
            self.address = bytes([0, 0, 0, 0, 0, 0])
        elif isinstance(address, Address):
            self.address = address.address
        elif isinstance(address, str):
            self.address = bytes([int(b, 16) for b in address.split(':')])
        elif isinstance(address, (bytes, list)) and len(address) == 6:
            self.address = bytes(address)
        elif isinstance(address, bytes):
            address = address.decode('utf-8')
            self.address = bytes([int(b, 16) for b in address.split(':')])
        else:
            raise Exception(f'unsupported address type: {address}')

    def parse(span: bytes) -> Tuple['Address', bytes]:
        assert len(span) >= 6
        return (Address(bytes(reversed(span[:6]))), span[6:])

    def parse_all(span: bytes) -> 'Address':
        assert len(span) == 6
        return Address(bytes(reversed(span)))

    def serialize(self) -> bytes:
        return bytes(reversed(self.address))

    def is_resolvable(self) -> bool:
        return (self.address[0] & 0xc0) == 0x40

    def is_non_resolvable(self) -> bool:
        return (self.address[0] & 0xc0) == 0x00

    def is_static_identity(self) -> bool:
        return (self.address[0] & 0xc0) == 0xc0

    def __repr__(self) -> str:
        return ':'.join([f'{b:02x}' for b in self.address])

    @property
    def size(self) -> int:
        return 6


@dataclass
class ClassOfDevice:
    class_of_device: int = 0

    def parse(span: bytes) -> Tuple['Address', bytes]:
        assert len(span) >= 3
        return (ClassOfDevice(int.from_bytes(span[:3], byteorder='little')), span[3:])

    def parse_all(span: bytes) -> 'Address':
        assert len(span) == 3
        return ClassOfDevice(int.from_bytes(span, byteorder='little'))

    def serialize(self) -> bytes:
        return int.to_bytes(self.class_of_device, length=3, byteorder='little')

    @property
    def size(self) -> int:
        return 3
