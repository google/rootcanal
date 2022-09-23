use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::future::Future;
use std::pin::Pin;
use std::task::{self, Poll};

use num_traits::ToPrimitive;

use crate::ec::PrivateKey;
use crate::packets::{hci, lmp};

use crate::procedure::Context;

#[derive(Default)]
pub struct TestContext {
    pub in_lmp_packets: RefCell<VecDeque<lmp::PacketPacket>>,
    pub out_lmp_packets: RefCell<VecDeque<lmp::PacketPacket>>,
    pub hci_events: RefCell<VecDeque<hci::EventPacket>>,
    pub hci_commands: RefCell<VecDeque<hci::CommandPacket>>,
    private_key: RefCell<Option<PrivateKey>>,
    features_pages: [u64; 3],
    peer_features_pages: [u64; 3],
}

impl TestContext {
    pub fn new() -> Self {
        Self::default()
            .with_page_1_feature(hci::LMPFeaturesPage1Bits::SecureSimplePairingHostSupport)
            .with_peer_page_1_feature(hci::LMPFeaturesPage1Bits::SecureSimplePairingHostSupport)
    }

    pub fn with_page_1_feature(mut self, feature: hci::LMPFeaturesPage1Bits) -> Self {
        self.features_pages[1] |= feature.to_u64().unwrap();
        self
    }

    pub fn with_page_2_feature(mut self, feature: hci::LMPFeaturesPage2Bits) -> Self {
        self.features_pages[2] |= feature.to_u64().unwrap();
        self
    }

    pub fn with_peer_page_1_feature(mut self, feature: hci::LMPFeaturesPage1Bits) -> Self {
        self.peer_features_pages[1] |= feature.to_u64().unwrap();
        self
    }

    pub fn with_peer_page_2_feature(mut self, feature: hci::LMPFeaturesPage2Bits) -> Self {
        self.peer_features_pages[2] |= feature.to_u64().unwrap();
        self
    }
}

impl Context for TestContext {
    fn poll_hci_command<C: TryFrom<hci::CommandPacket>>(&self) -> Poll<C> {
        let command =
            self.hci_commands.borrow().front().and_then(|command| command.clone().try_into().ok());

        if let Some(command) = command {
            self.hci_commands.borrow_mut().pop_front();
            Poll::Ready(command)
        } else {
            Poll::Pending
        }
    }

    fn poll_lmp_packet<P: TryFrom<lmp::PacketPacket>>(&self) -> Poll<P> {
        let packet =
            self.in_lmp_packets.borrow().front().and_then(|packet| packet.clone().try_into().ok());

        if let Some(packet) = packet {
            self.in_lmp_packets.borrow_mut().pop_front();
            Poll::Ready(packet)
        } else {
            Poll::Pending
        }
    }

    fn send_hci_event<E: Into<hci::EventPacket>>(&self, event: E) {
        self.hci_events.borrow_mut().push_back(event.into());
    }

    fn send_lmp_packet<P: Into<lmp::PacketPacket>>(&self, packet: P) {
        self.out_lmp_packets.borrow_mut().push_back(packet.into());
    }

    fn peer_address(&self) -> hci::Address {
        hci::Address { bytes: [0; 6] }
    }

    fn peer_handle(&self) -> u16 {
        0x42
    }

    fn peer_extended_features(&self, features_page: u8) -> Option<u64> {
        Some(self.peer_features_pages[features_page as usize])
    }

    fn extended_features(&self, features_page: u8) -> u64 {
        self.features_pages[features_page as usize]
    }

    fn get_private_key(&self) -> Option<PrivateKey> {
        self.private_key.borrow().clone()
    }

    fn set_private_key(&self, key: &PrivateKey) {
        *self.private_key.borrow_mut() = Some(key.clone())
    }
}

pub fn poll(future: Pin<&mut impl Future<Output = ()>>) -> Poll<()> {
    let waker = crate::future::noop_waker();
    future.poll(&mut task::Context::from_waker(&waker))
}
