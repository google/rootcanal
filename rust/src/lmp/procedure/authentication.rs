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

//! Bluetooth Core, Vol 2, Part C, 4.2.1

use crate::either::Either;
use crate::lmp::procedure::{features, legacy_pairing, secure_simple_pairing, Context};
use crate::num_hci_command_packets;
use crate::packets::{hci, lmp};

pub async fn send_challenge(
    ctx: &impl Context,
    transaction_id: u8,
    _link_key: [u8; 16],
) -> Result<(), ()> {
    let random_number = [0; 16];
    ctx.send_lmp_packet(lmp::AuRand { transaction_id, random_number });

    match ctx
        .receive_lmp_packet::<Either<lmp::Sres, lmp::NotAccepted>>()
        .await
    {
        Either::Left(_response) => Ok(()),
        Either::Right(_) => Err(()),
    }
}

pub async fn receive_challenge(ctx: &impl Context, _link_key: [u8; 16]) {
    let _random_number = *ctx
        .receive_lmp_packet::<lmp::AuRand>()
        .await
        .random_number();
    ctx.send_lmp_packet(lmp::Sres { transaction_id: 0, authentication_rsp: [0; 4] });
}

pub async fn initiate(ctx: &impl Context) {
    let _ = ctx
        .receive_hci_command::<hci::AuthenticationRequested>()
        .await;
    ctx.send_hci_event(hci::AuthenticationRequestedStatus {
        num_hci_command_packets,
        status: hci::ErrorCode::Success,
    });

    ctx.send_hci_event(hci::LinkKeyRequest { bd_addr: ctx.peer_address() });

    let status = match ctx
        .receive_hci_command::<Either<hci::LinkKeyRequestReply, hci::LinkKeyRequestNegativeReply>>()
        .await
    {
        Either::Left(_reply) => {
            ctx.send_hci_event(hci::LinkKeyRequestReplyComplete {
                num_hci_command_packets,
                status: hci::ErrorCode::Success,
                bd_addr: ctx.peer_address(),
            });

            // Send the initial challenge to determine if the remote device has saved the link key,
            // or deleted the bond. The authentication request fails with error PIN_OR_KEY_MISSING
            // if the remote rejects the challenge.
            match send_challenge(ctx, 0, *_reply.link_key()).await {
                Err(_) => hci::ErrorCode::PinOrKeyMissing,
                Ok(_) => hci::ErrorCode::Success,
            }
        }
        Either::Right(_) => {
            ctx.send_hci_event(hci::LinkKeyRequestNegativeReplyComplete {
                num_hci_command_packets,
                status: hci::ErrorCode::Success,
                bd_addr: ctx.peer_address(),
            });

            let result = if features::supported_on_both_page1(
                ctx,
                hci::LMPFeaturesPage1Bits::SecureSimplePairingHostSupport,
            )
            .await
            {
                secure_simple_pairing::initiate(ctx).await
            } else {
                legacy_pairing::initiate(ctx).await
            };

            match result {
                Ok(_) => hci::ErrorCode::Success,
                Err(_) => hci::ErrorCode::AuthenticationFailure,
            }
        }
    };

    ctx.send_hci_event(hci::AuthenticationComplete {
        status,
        connection_handle: ctx.peer_handle(),
    });
}

pub async fn respond(ctx: &impl Context) {
    match ctx
        .receive_lmp_packet::<Either<lmp::AuRand, Either<lmp::IoCapabilityReq, lmp::InRand>>>()
        .await
    {
        Either::Left(_random_number) => {
            // Request the Link Key from the host stack.
            ctx.send_hci_event(hci::LinkKeyRequest { bd_addr: ctx.peer_address() });

            match ctx
                .receive_hci_command::<Either<hci::LinkKeyRequestReply, hci::LinkKeyRequestNegativeReply>>()
                .await
            {
                Either::Left(_reply) => {
                    ctx.send_hci_event(
                        hci::LinkKeyRequestReplyComplete {
                            num_hci_command_packets,
                            status: hci::ErrorCode::Success,
                            bd_addr: ctx.peer_address(),
                        }
                    );

                    // TODO: Resolve authentication challenge
                    // Currently the Link Key is always considered valid.
                    // Send the expected LMP_SRES response.
                    ctx.send_lmp_packet(
                        lmp::Sres {
                            transaction_id: 0,
                            authentication_rsp: [0; 4]
                        }
                    );

                    // Authentication is successul at this point.
                }
                Either::Right(_) => {
                    ctx.send_hci_event(
                        hci::LinkKeyRequestNegativeReplyComplete {
                            num_hci_command_packets,
                            status: hci::ErrorCode::Success,
                            bd_addr: ctx.peer_address(),
                        }
                    );

                    // Respond with LMP_NOT_ACCEPTED to indicate that the
                    // Link Key is missing.
                    ctx.send_lmp_packet(lmp::NotAccepted {
                        not_accepted_opcode: lmp::Opcode::AuRand,
                        error_code: hci::ErrorCode::PinOrKeyMissing as u8,
                        transaction_id: 0
                    })
                }
            }
        }
        Either::Right(pairing) => {
            let _result = match pairing {
                Either::Left(io_capability_request) => {
                    secure_simple_pairing::respond(ctx, io_capability_request).await
                }
                Either::Right(in_rand) => legacy_pairing::respond(ctx, in_rand).await,
            };
        }
    }
}
