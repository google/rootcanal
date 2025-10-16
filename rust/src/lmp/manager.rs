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

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::future::Future;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll};

use pdl_runtime::Packet as _;
use thiserror::Error;

use crate::ffi::ControllerOps;
use crate::future::noop_waker;
use crate::lmp::procedure;
use crate::num_hci_command_packets;
use crate::packets::{hci, lmp};

struct Link {
    peer: Cell<hci::Address>,
    // Only store one HCI packet as our Num_HCI_Command_Packets
    // is always 1
    hci: Cell<Option<hci::Command>>,
    lmp: RefCell<VecDeque<lmp::LmpPacket>>,
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
    fn ingest_lmp(&self, packet: lmp::LmpPacket) {
        self.lmp.borrow_mut().push_back(packet);
    }

    fn ingest_hci(&self, command: hci::Command) {
        assert!(self.hci.replace(Some(command)).is_none(), "HCI flow control violation");
    }

    fn poll_hci_command<C: TryFrom<hci::Command>>(&self) -> Poll<C> {
        let command = self.hci.take();

        if let Some(command) = command.clone().and_then(|c| c.try_into().ok()) {
            Poll::Ready(command)
        } else {
            self.hci.set(command);
            Poll::Pending
        }
    }

    fn poll_lmp_packet<P: TryFrom<lmp::LmpPacket>>(&self) -> Poll<P> {
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
    ops: ControllerOps,
    links: [Link; MAX_PEER_NUMBER],
    procedures: RefCell<[Option<Pin<Box<dyn Future<Output = ()>>>>; MAX_PEER_NUMBER]>,
}

impl LinkManager {
    pub fn new(ops: ControllerOps) -> Self {
        Self { ops, links: Default::default(), procedures: Default::default() }
    }

    fn get_link(&self, peer: hci::Address) -> Option<&Link> {
        self.links.iter().find(|link| link.peer.get() == peer)
    }

    pub fn ingest_lmp(
        &self,
        from: hci::Address,
        packet: lmp::LmpPacket,
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
        command: &hci::Command,
        status: hci::ErrorCode,
    ) -> Result<(), LinkManagerError> {
        use hci::CommandChild::*;

        let event: hci::Event = match command.specialize() {
            Ok(LinkKeyRequestReply(packet)) => hci::LinkKeyRequestReplyComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(LinkKeyRequestNegativeReply(packet)) => hci::LinkKeyRequestNegativeReplyComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(PinCodeRequestReply(packet)) => hci::PinCodeRequestReplyComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(PinCodeRequestNegativeReply(packet)) => hci::PinCodeRequestNegativeReplyComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(IoCapabilityRequestReply(packet)) => hci::IoCapabilityRequestReplyComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(IoCapabilityRequestNegativeReply(packet)) => {
                hci::IoCapabilityRequestNegativeReplyComplete {
                    status,
                    bd_addr: packet.bd_addr(),
                    num_hci_command_packets,
                }
                .try_into()
            }
            Ok(UserConfirmationRequestReply(packet)) => hci::UserConfirmationRequestReplyComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(UserConfirmationRequestNegativeReply(packet)) => {
                hci::UserConfirmationRequestNegativeReplyComplete {
                    status,
                    bd_addr: packet.bd_addr(),
                    num_hci_command_packets,
                }
                .try_into()
            }
            Ok(UserPasskeyRequestReply(packet)) => hci::UserPasskeyRequestReplyComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(UserPasskeyRequestNegativeReply(packet)) => {
                hci::UserPasskeyRequestNegativeReplyComplete {
                    status,
                    bd_addr: packet.bd_addr(),
                    num_hci_command_packets,
                }
                .try_into()
            }
            Ok(RemoteOobDataRequestReply(packet)) => hci::RemoteOobDataRequestReplyComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(RemoteOobDataRequestNegativeReply(packet)) => {
                hci::RemoteOobDataRequestNegativeReplyComplete {
                    status,
                    bd_addr: packet.bd_addr(),
                    num_hci_command_packets,
                }
                .try_into()
            }
            Ok(SendKeypressNotification(packet)) => hci::SendKeypressNotificationComplete {
                status,
                bd_addr: packet.bd_addr(),
                num_hci_command_packets,
            }
            .try_into(),
            Ok(AuthenticationRequested(_)) => {
                hci::AuthenticationRequestedStatus { status, num_hci_command_packets }.try_into()
            }
            Ok(SetConnectionEncryption(_)) => {
                hci::SetConnectionEncryptionStatus { status, num_hci_command_packets }.try_into()
            }
            _ => return Err(LinkManagerError::UnhandledHciPacket),
        }
        .expect("failed to serialize response event");
        self.ops.send_hci_event(&event.encode_to_vec().unwrap());
        Ok(())
    }

    pub fn ingest_hci(&self, command: hci::Command) -> Result<(), LinkManagerError> {
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
            // Send HCI command complete or status event for the pending HCI comamnd
            // if any. Failing to do that would break flow control expectations for the host.
            if let Some(command) = self.links[index].hci.replace(None) {
                self.send_command_complete_event(&command, hci::ErrorCode::UnknownConnection)?;
            }

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
    fn poll_hci_command<C: TryFrom<hci::Command>>(&self) -> Poll<C> {
        if let Some(manager) = self.manager.upgrade() {
            manager.link(self.index).poll_hci_command()
        } else {
            Poll::Pending
        }
    }

    fn poll_lmp_packet<P: TryFrom<lmp::LmpPacket>>(&self) -> Poll<P> {
        if let Some(manager) = self.manager.upgrade() {
            manager.link(self.index).poll_lmp_packet()
        } else {
            Poll::Pending
        }
    }

    fn send_hci_event<E: TryInto<hci::Event> + pdl_runtime::Packet>(&self, event: E) {
        if let Some(manager) = self.manager.upgrade() {
            manager.ops.send_hci_event(&event.encode_to_vec().unwrap())
        }
    }

    fn send_lmp_packet<P: TryInto<lmp::LmpPacket> + pdl_runtime::Packet>(&self, packet: P) {
        if let Some(manager) = self.manager.upgrade() {
            manager.ops.send_lmp_packet(self.peer_address(), &packet.encode_to_vec().unwrap())
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
            manager.ops.get_extended_features(features_page)
        } else {
            0
        }
    }
}
