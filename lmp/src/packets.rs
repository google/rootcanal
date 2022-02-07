pub mod hci {
    pub use bt_packets::custom_types::*;
    pub use bt_packets::hci::*;

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
