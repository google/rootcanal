pub mod hci {
    #![allow(clippy::all)]
    #![allow(unused)]
    #![allow(missing_docs)]

    pub const EMPTY_ADDRESS: Address = Address { bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00] };
    pub const ANY_ADDRESS: Address = Address { bytes: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] };

    /// A Bluetooth address
    #[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, Debug)]
    pub struct Address {
        pub bytes: [u8; 6],
    }

    impl Address {
        pub fn is_empty(&self) -> bool {
            *self == EMPTY_ADDRESS
        }
    }

    impl fmt::Display for Address {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                self.bytes[5],
                self.bytes[4],
                self.bytes[3],
                self.bytes[2],
                self.bytes[1],
                self.bytes[0]
            )
        }
    }

    #[derive(Debug, Clone)]
    pub struct InvalidAddressError;

    impl TryFrom<&[u8]> for Address {
        type Error = InvalidAddressError;

        fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
            match <[u8; 6]>::try_from(slice) {
                Ok(bytes) => Ok(Self { bytes }),
                Err(_) => Err(InvalidAddressError),
            }
        }
    }

    impl From<Address> for [u8; 6] {
        fn from(addr: Address) -> [u8; 6] {
            addr.bytes
        }
    }

    #[derive(Clone, Eq, Copy, PartialEq, Hash, Ord, PartialOrd, Debug)]
    pub struct ClassOfDevice {
        pub bytes: [u8; 3],
    }

    impl fmt::Display for ClassOfDevice {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{:03X}-{:01X}-{:02X}",
                ((self.bytes[2] as u16) << 4) | ((self.bytes[1] as u16) >> 4),
                self.bytes[1] & 0x0F,
                self.bytes[0]
            )
        }
    }

    #[derive(Debug, Clone)]
    pub struct InvalidClassOfDeviceError;

    impl TryFrom<&[u8]> for ClassOfDevice {
        type Error = InvalidClassOfDeviceError;

        fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
            match <[u8; 3]>::try_from(slice) {
                Ok(bytes) => Ok(Self { bytes }),
                Err(_) => Err(InvalidClassOfDeviceError),
            }
        }
    }

    impl From<ClassOfDevice> for [u8; 3] {
        fn from(cod: ClassOfDevice) -> [u8; 3] {
            cod.bytes
        }
    }

    include!(concat!(env!("OUT_DIR"), "/hci_packets.rs"));

    pub fn command_remote_device_address(command: &CommandPacket) -> Option<Address> {
        #[allow(unused_imports)]
        use Option::None;
        use SecurityCommandChild::*; // Overwrite `None` variant of `Child` enum

        match command.specialize() {
            CommandChild::SecurityCommand(command) => match command.specialize() {
                LinkKeyRequestReply(packet) => Some(packet.get_bd_addr()),
                LinkKeyRequestNegativeReply(packet) => Some(packet.get_bd_addr()),
                PinCodeRequestReply(packet) => Some(packet.get_bd_addr()),
                PinCodeRequestNegativeReply(packet) => Some(packet.get_bd_addr()),
                IoCapabilityRequestReply(packet) => Some(packet.get_bd_addr()),
                IoCapabilityRequestNegativeReply(packet) => Some(packet.get_bd_addr()),
                UserConfirmationRequestReply(packet) => Some(packet.get_bd_addr()),
                UserConfirmationRequestNegativeReply(packet) => Some(packet.get_bd_addr()),
                UserPasskeyRequestReply(packet) => Some(packet.get_bd_addr()),
                UserPasskeyRequestNegativeReply(packet) => Some(packet.get_bd_addr()),
                RemoteOobDataRequestReply(packet) => Some(packet.get_bd_addr()),
                RemoteOobDataRequestNegativeReply(packet) => Some(packet.get_bd_addr()),
                SendKeypressNotification(packet) => Some(packet.get_bd_addr()),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn command_connection_handle(command: &CommandPacket) -> Option<u16> {
        use ConnectionManagementCommandChild::*;
        #[allow(unused_imports)]
        use Option::None; // Overwrite `None` variant of `Child` enum

        match command.specialize() {
            CommandChild::AclCommand(command) => match command.specialize() {
                AclCommandChild::ConnectionManagementCommand(command) => {
                    match command.specialize() {
                        AuthenticationRequested(packet) => Some(packet.get_connection_handle()),
                        SetConnectionEncryption(packet) => Some(packet.get_connection_handle()),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }
}

pub mod lmp {
    #![allow(clippy::all)]
    #![allow(unused)]
    #![allow(missing_docs)]

    include!(concat!(env!("OUT_DIR"), "/lmp_packets.rs"));
}
