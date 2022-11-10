from dataclasses import dataclass, field
from typing import Tuple


@dataclass
class Address:
    address: bytes = field(default=bytes([0, 0, 0, 0, 0, 0]))

    def __post_init__(self):
        self.address = bytes(self.address)

    def from_str(address: str) -> 'Address':
        return Address(bytes([int(b, 16) for b in address.split(':')]))

    def parse(span: bytes) -> Tuple['Address', bytes]:
        assert len(span) > 6
        return (Address(bytes(reversed(span[:6]))), span[6:])

    def parse_all(span: bytes) -> 'Address':
        assert (len(span) == 6)
        return Address(bytes(reversed(span)))

    def serialize(self) -> bytes:
        return bytes(reversed(self.address))

    def __repr__(self) -> str:
        return ':'.join([f'{b:02x}' for b in self.address])

    @property
    def size(self) -> int:
        return 6


@dataclass
class ClassOfDevice:

    def parse(span: bytes) -> Tuple['Address', bytes]:
        assert False

    def parse_all(span: bytes) -> 'Address':
        assert False

    def serialize(self) -> bytes:
        assert False

    @property
    def size(self) -> int:
        assert False
