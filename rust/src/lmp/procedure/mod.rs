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

use std::convert::TryFrom;
use std::future::Future;
use std::pin::Pin;
use std::task::{self, Poll};

use crate::lmp::ec::PrivateKey;
use crate::packets::{hci, lmp};

pub trait Context {
    fn poll_hci_command<C: TryFrom<hci::Command>>(&self) -> Poll<C>;
    fn poll_lmp_packet<P: TryFrom<lmp::LmpPacket>>(&self) -> Poll<P>;

    fn send_hci_event<E: Into<hci::Event>>(&self, event: E);
    fn send_lmp_packet<P: Into<lmp::LmpPacket>>(&self, packet: P);

    fn peer_address(&self) -> hci::Address;
    fn peer_handle(&self) -> u16;

    fn peer_extended_features(&self, _features_page: u8) -> Option<u64> {
        None
    }

    fn extended_features(&self, features_page: u8) -> u64;

    fn receive_hci_command<C: TryFrom<hci::Command>>(&self) -> ReceiveFuture<'_, Self, C> {
        ReceiveFuture(Self::poll_hci_command, self)
    }

    fn receive_lmp_packet<P: TryFrom<lmp::LmpPacket>>(&self) -> ReceiveFuture<'_, Self, P> {
        ReceiveFuture(Self::poll_lmp_packet, self)
    }

    fn send_accepted_lmp_packet<P: Into<lmp::LmpPacket>>(
        &self,
        packet: P,
    ) -> SendAcceptedLmpPacketFuture<'_, Self> {
        let packet = packet.into();
        let opcode = packet.get_opcode();
        self.send_lmp_packet(packet);

        SendAcceptedLmpPacketFuture(self, opcode)
    }

    fn get_private_key(&self) -> Option<PrivateKey> {
        None
    }

    fn set_private_key(&self, _key: &PrivateKey) {}
}

/// Future for Context::receive_hci_command and Context::receive_lmp_packet
pub struct ReceiveFuture<'a, C: ?Sized, P>(fn(&'a C) -> Poll<P>, &'a C);

impl<'a, C, O> Future for ReceiveFuture<'a, C, O>
where
    C: Context,
{
    type Output = O;

    fn poll(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        (self.0)(self.1)
    }
}

/// Future for Context::receive_hci_command and Context::receive_lmp_packet
pub struct SendAcceptedLmpPacketFuture<'a, C: ?Sized>(&'a C, lmp::Opcode);

impl<'a, C> Future for SendAcceptedLmpPacketFuture<'a, C>
where
    C: Context,
{
    type Output = Result<(), u8>;

    fn poll(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let accepted = self.0.poll_lmp_packet::<lmp::Accepted>();
        if let Poll::Ready(accepted) = accepted {
            if accepted.get_accepted_opcode() == self.1 {
                return Poll::Ready(Ok(()));
            }
        }

        let not_accepted = self.0.poll_lmp_packet::<lmp::NotAccepted>();
        if let Poll::Ready(not_accepted) = not_accepted {
            if not_accepted.get_not_accepted_opcode() == self.1 {
                return Poll::Ready(Err(not_accepted.get_error_code()));
            }
        }

        Poll::Pending
    }
}

pub mod authentication;
mod encryption;
pub mod features;
pub mod legacy_pairing;
pub mod secure_simple_pairing;

macro_rules! run_procedures {
    ($(
        $idx:tt { $procedure:expr }
    )+) => {{
        $(
            let $idx = async { loop { $procedure.await; } };
            crate::future::pin!($idx);
        )+

        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Poll, Context};

        #[allow(non_camel_case_types)]
        struct Join<'a, $($idx),+> {
            $($idx: Pin<&'a mut $idx>),+
        }

        #[allow(non_camel_case_types)]
        impl<'a, $($idx: Future<Output = ()>),+> Future for Join<'a, $($idx),+> {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                $(assert!(self.$idx.as_mut().poll(cx).is_pending());)+
                Poll::Pending
            }
        }

        Join {
            $($idx),+
        }.await
    }}
}

pub async fn run(ctx: impl Context) {
    run_procedures! {
        a { authentication::initiate(&ctx) }
        b { authentication::respond(&ctx) }
        c { encryption::initiate(&ctx) }
        d { encryption::respond(&ctx) }
        e { features::respond(&ctx) }
    }
}
