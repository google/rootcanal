// Copyright 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod hci {
    #![allow(clippy::all)]
    #![allow(unused)]
    #![allow(missing_docs)]
    #![allow(non_camel_case_types)]

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

    pub fn command_remote_device_address(command: &Command) -> Option<Address> {
        use CommandChild::*;

        match command.specialize() {
            Ok(LinkKeyRequestReply(packet)) => Some(packet.bd_addr()),
            Ok(LinkKeyRequestNegativeReply(packet)) => Some(packet.bd_addr()),
            Ok(PinCodeRequestReply(packet)) => Some(packet.bd_addr()),
            Ok(PinCodeRequestNegativeReply(packet)) => Some(packet.bd_addr()),
            Ok(IoCapabilityRequestReply(packet)) => Some(packet.bd_addr()),
            Ok(IoCapabilityRequestNegativeReply(packet)) => Some(packet.bd_addr()),
            Ok(UserConfirmationRequestReply(packet)) => Some(packet.bd_addr()),
            Ok(UserConfirmationRequestNegativeReply(packet)) => Some(packet.bd_addr()),
            Ok(UserPasskeyRequestReply(packet)) => Some(packet.bd_addr()),
            Ok(UserPasskeyRequestNegativeReply(packet)) => Some(packet.bd_addr()),
            Ok(RemoteOobDataRequestReply(packet)) => Some(packet.bd_addr()),
            Ok(RemoteOobDataRequestNegativeReply(packet)) => Some(packet.bd_addr()),
            Ok(SendKeypressNotification(packet)) => Some(packet.bd_addr()),
            _ => Option::None,
        }
    }

    pub fn command_connection_handle(command: &Command) -> Option<u16> {
        use CommandChild::*;

        match command.specialize() {
            Ok(AuthenticationRequested(packet)) => Some(packet.connection_handle()),
            Ok(SetConnectionEncryption(packet)) => Some(packet.connection_handle()),
            _ => Option::None,
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
