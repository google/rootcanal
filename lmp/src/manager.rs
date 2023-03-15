use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::future::Future;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll};

use thiserror::Error;

use crate::ffi::LinkManagerOps;
use crate::future::noop_waker;
use crate::packets::{hci, lmp};
use crate::procedure;

use hci::Packet as _;
use lmp::Packet as _;

/// Number of hci command packets used
/// in Command Complete and Command Status
#[allow(non_upper_case_globals)]
pub const num_hci_command_packets: u8 = 1;

struct Link {
    peer: Cell<hci::Address>,
    // Only store one HCI packet as our Num_HCI_Command_Packets
    // is always 1
    hci: Cell<Option<hci::CommandPacket>>,
    lmp: RefCell<VecDeque<lmp::PacketPacket>>,
}

impl Default for Link {
    fn default() -> Self {
        Link {
            peer: Cell::new(hci::EMPTY_ADDRESS),
            hci: Default::default(),
            lmp: Default::default(),
        }
    }
}

impl Link {
    fn ingest_lmp(&self, packet: lmp::PacketPacket) {
        self.lmp.borrow_mut().push_back(packet);
    }

    fn ingest_hci(&self, command: hci::CommandPacket) {
        assert!(self.hci.replace(Some(command)).is_none(), "HCI flow control violation");
    }

    fn poll_hci_command<C: TryFrom<hci::CommandPacket>>(&self) -> Poll<C> {
        let command = self.hci.take();

        if let Some(command) = command.clone().and_then(|c| c.try_into().ok()) {
            Poll::Ready(command)
        } else {
            self.hci.set(command);
            Poll::Pending
        }
    }

    fn poll_lmp_packet<P: TryFrom<lmp::PacketPacket>>(&self) -> Poll<P> {
        let mut queue = self.lmp.borrow_mut();
        let packet = queue.front().and_then(|packet| packet.clone().try_into().ok());

        if let Some(packet) = packet {
            queue.pop_front();
            Poll::Ready(packet)
        } else {
            Poll::Pending
        }
    }

    fn reset(&self) {
        self.peer.set(hci::EMPTY_ADDRESS);
        self.hci.set(None);
        self.lmp.borrow_mut().clear();
    }
}

#[derive(Error, Debug)]
pub enum LinkManagerError {
    #[error("Unknown peer")]
    UnknownPeer,
    #[error("Unhandled HCI packet")]
    UnhandledHciPacket,
    #[error("Maximum number of links reached")]
    MaxNumberOfLink,
}

/// Max number of Bluetooth Peers
pub const MAX_PEER_NUMBER: usize = 7;

pub struct LinkManager {
    ops: LinkManagerOps,
    links: [Link; MAX_PEER_NUMBER],
    procedures: RefCell<[Option<Pin<Box<dyn Future<Output = ()>>>>; MAX_PEER_NUMBER]>,
}

impl LinkManager {
    pub fn new(ops: LinkManagerOps) -> Self {
        Self { ops, links: Default::default(), procedures: Default::default() }
    }

    fn get_link(&self, peer: hci::Address) -> Option<&Link> {
        self.links.iter().find(|link| link.peer.get() == peer)
    }

    pub fn ingest_lmp(
        &self,
        from: hci::Address,
        packet: lmp::PacketPacket,
    ) -> Result<(), LinkManagerError> {
        if let Some(link) = self.get_link(from) {
            link.ingest_lmp(packet);
        };
        Ok(())
    }

    /// Send a command complete or command status event
    /// with the specified error code.
    fn send_command_complete_event(
        &self,
        command: &hci::CommandPacket,
        status: hci::ErrorCode,
    ) -> Result<(), LinkManagerError> {
        use hci::ConnectionManagementCommandChild::*;
        use hci::SecurityCommandChild::*;
        #[allow(unused_imports)]
        use Option::None; // Overwrite `None` variant of `Child` enum

        let event: hci::EventPacket = match command.specialize() {
            hci::CommandChild::SecurityCommand(command) => match command.specialize() {
                LinkKeyRequestReply(packet) => hci::LinkKeyRequestReplyCompleteBuilder {
                    status,
                    bd_addr: packet.get_bd_addr(),
                    num_hci_command_packets,
                }
                .into(),
                LinkKeyRequestNegativeReply(packet) => {
                    hci::LinkKeyRequestNegativeReplyCompleteBuilder {
                        status,
                        bd_addr: packet.get_bd_addr(),
                        num_hci_command_packets,
                    }
                    .into()
                }
                PinCodeRequestReply(packet) => hci::PinCodeRequestReplyCompleteBuilder {
                    status,
                    bd_addr: packet.get_bd_addr(),
                    num_hci_command_packets,
                }
                .into(),
                PinCodeRequestNegativeReply(packet) => {
                    hci::PinCodeRequestNegativeReplyCompleteBuilder {
                        status,
                        bd_addr: packet.get_bd_addr(),
                        num_hci_command_packets,
                    }
                    .into()
                }
                IoCapabilityRequestReply(packet) => hci::IoCapabilityRequestReplyCompleteBuilder {
                    status,
                    bd_addr: packet.get_bd_addr(),
                    num_hci_command_packets,
                }
                .into(),
                IoCapabilityRequestNegativeReply(packet) => {
                    hci::IoCapabilityRequestNegativeReplyCompleteBuilder {
                        status,
                        bd_addr: packet.get_bd_addr(),
                        num_hci_command_packets,
                    }
                    .into()
                }
                UserConfirmationRequestReply(packet) => {
                    hci::UserConfirmationRequestReplyCompleteBuilder {
                        status,
                        bd_addr: packet.get_bd_addr(),
                        num_hci_command_packets,
                    }
                    .into()
                }
                UserConfirmationRequestNegativeReply(packet) => {
                    hci::UserConfirmationRequestNegativeReplyCompleteBuilder {
                        status,
                        bd_addr: packet.get_bd_addr(),
                        num_hci_command_packets,
                    }
                    .into()
                }
                UserPasskeyRequestReply(packet) => hci::UserPasskeyRequestReplyCompleteBuilder {
                    status,
                    bd_addr: packet.get_bd_addr(),
                    num_hci_command_packets,
                }
                .into(),
                UserPasskeyRequestNegativeReply(packet) => {
                    hci::UserPasskeyRequestNegativeReplyCompleteBuilder {
                        status,
                        bd_addr: packet.get_bd_addr(),
                        num_hci_command_packets,
                    }
                    .into()
                }
                RemoteOobDataRequestReply(packet) => {
                    hci::RemoteOobDataRequestReplyCompleteBuilder {
                        status,
                        bd_addr: packet.get_bd_addr(),
                        num_hci_command_packets,
                    }
                    .into()
                }
                RemoteOobDataRequestNegativeReply(packet) => {
                    hci::RemoteOobDataRequestNegativeReplyCompleteBuilder {
                        status,
                        bd_addr: packet.get_bd_addr(),
                        num_hci_command_packets,
                    }
                    .into()
                }
                SendKeypressNotification(packet) => hci::SendKeypressNotificationCompleteBuilder {
                    status,
                    bd_addr: packet.get_bd_addr(),
                    num_hci_command_packets,
                }
                .into(),
                _ => return Err(LinkManagerError::UnhandledHciPacket),
            },
            hci::CommandChild::AclCommand(command) => match command.specialize() {
                hci::AclCommandChild::ConnectionManagementCommand(command) => {
                    match command.specialize() {
                        AuthenticationRequested(_) => hci::AuthenticationRequestedStatusBuilder {
                            status,
                            num_hci_command_packets,
                        }
                        .into(),
                        SetConnectionEncryption(_) => hci::SetConnectionEncryptionStatusBuilder {
                            status,
                            num_hci_command_packets,
                        }
                        .into(),
                        _ => return Err(LinkManagerError::UnhandledHciPacket),
                    }
                }
                _ => return Err(LinkManagerError::UnhandledHciPacket),
            },
            _ => return Err(LinkManagerError::UnhandledHciPacket),
        };
        self.ops.send_hci_event(&event.to_vec());
        Ok(())
    }

    pub fn ingest_hci(&self, command: hci::CommandPacket) -> Result<(), LinkManagerError> {
        // Try to find the matching link from the command arguments
        let link = hci::command_connection_handle(&command)
            .and_then(|handle| self.ops.get_address(handle))
            .or_else(|| hci::command_remote_device_address(&command))
            .and_then(|peer| self.get_link(peer));

        if let Some(link) = link {
            link.ingest_hci(command);
            Ok(())
        } else {
            self.send_command_complete_event(&command, hci::ErrorCode::InvalidHciCommandParameters)
        }
    }

    pub fn add_link(self: &Rc<Self>, peer: hci::Address) -> Result<(), LinkManagerError> {
        let index = self.links.iter().position(|link| link.peer.get().is_empty());

        if let Some(index) = index {
            self.links[index].peer.set(peer);
            let context = LinkContext { index: index as u8, manager: Rc::downgrade(self) };
            self.procedures.borrow_mut()[index] = Some(Box::pin(procedure::run(context)));
            Ok(())
        } else {
            Err(LinkManagerError::UnhandledHciPacket)
        }
    }

    pub fn remove_link(&self, peer: hci::Address) -> Result<(), LinkManagerError> {
        let index = self.links.iter().position(|link| link.peer.get() == peer);

        if let Some(index) = index {
            self.links[index].reset();
            self.procedures.borrow_mut()[index] = None;
            Ok(())
        } else {
            Err(LinkManagerError::UnknownPeer)
        }
    }

    pub fn tick(&self) {
        let waker = noop_waker();

        for procedures in self.procedures.borrow_mut().iter_mut().filter_map(Option::as_mut) {
            let _ = procedures.as_mut().poll(&mut Context::from_waker(&waker));
        }
    }

    fn link(&self, idx: u8) -> &Link {
        &self.links[idx as usize]
    }
}

struct LinkContext {
    index: u8,
    manager: Weak<LinkManager>,
}

impl procedure::Context for LinkContext {
    fn poll_hci_command<C: TryFrom<hci::CommandPacket>>(&self) -> Poll<C> {
        if let Some(manager) = self.manager.upgrade() {
            manager.link(self.index).poll_hci_command()
        } else {
            Poll::Pending
        }
    }

    fn poll_lmp_packet<P: TryFrom<lmp::PacketPacket>>(&self) -> Poll<P> {
        if let Some(manager) = self.manager.upgrade() {
            manager.link(self.index).poll_lmp_packet()
        } else {
            Poll::Pending
        }
    }

    fn send_hci_event<E: Into<hci::EventPacket>>(&self, event: E) {
        if let Some(manager) = self.manager.upgrade() {
            manager.ops.send_hci_event(&event.into().to_vec())
        }
    }

    fn send_lmp_packet<P: Into<lmp::PacketPacket>>(&self, packet: P) {
        if let Some(manager) = self.manager.upgrade() {
            manager.ops.send_lmp_packet(self.peer_address(), &packet.into().to_vec())
        }
    }

    fn peer_address(&self) -> hci::Address {
        if let Some(manager) = self.manager.upgrade() {
            manager.link(self.index).peer.get()
        } else {
            hci::EMPTY_ADDRESS
        }
    }

    fn peer_handle(&self) -> u16 {
        if let Some(manager) = self.manager.upgrade() {
            manager.ops.get_handle(self.peer_address())
        } else {
            0
        }
    }

    fn extended_features(&self, features_page: u8) -> u64 {
        if let Some(manager) = self.manager.upgrade() {
            manager.ops.extended_features(features_page)
        } else {
            0
        }
    }
}
