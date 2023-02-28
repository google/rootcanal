pub mod hci {
    #![allow(clippy::all)]
    #![allow(unused)]
    #![allow(missing_docs)]

    include!(concat!(env!("OUT_DIR"), "/hci_packets.rs"));

    pub const EMPTY_ADDRESS: Address = Address(0x000000000000);
    pub const ANY_ADDRESS: Address = Address(0xffffffffffff);

    impl fmt::Display for Address {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let bytes = u64::to_le_bytes(self.0);
            write!(
                f,
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                bytes[5], bytes[4], bytes[3], bytes[2], bytes[1], bytes[0],
            )
        }
    }

    impl From<&[u8; 6]> for Address {
        fn from(bytes: &[u8; 6]) -> Self {
            Self(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], 0, 0,
            ]))
        }
    }

    impl From<Address> for [u8; 6] {
        fn from(Address(addr): Address) -> Self {
            let bytes = u64::to_le_bytes(addr);
            bytes[0..6].try_into().unwrap()
        }
    }

    impl Address {
        pub fn is_empty(&self) -> bool {
            *self == EMPTY_ADDRESS
        }
    }

    impl fmt::Display for ClassOfDevice {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{:03X}-{:01X}-{:02X}",
                (self.0 >> 12) & 0xfff,
                (self.0 >> 8) & 0xf,
                self.0 & 0xff,
            )
        }
    }

    pub fn command_remote_device_address(command: &Command) -> Option<Address> {
        use CommandChild::*;
        #[allow(unused_imports)]
        use Option::None; // Overwrite `None` variant of `Child` enum

        match command.specialize() {
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
        }
    }

    pub fn command_connection_handle(command: &Command) -> Option<u16> {
        use CommandChild::*;
        #[allow(unused_imports)]
        use Option::None; // Overwrite `None` variant of `Child` enum

        match command.specialize() {
            AuthenticationRequested(packet) => Some(packet.get_connection_handle()),
            SetConnectionEncryption(packet) => Some(packet.get_connection_handle()),
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

pub mod llcp {
    #![allow(clippy::all)]
    #![allow(unused)]
    #![allow(missing_docs)]

    include!(concat!(env!("OUT_DIR"), "/llcp_packets.rs"));
}
