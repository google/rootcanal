// Bluetooth Core, Vol 2, Part C, 4.2.1

use crate::either::Either;
use crate::num_hci_command_packets;
use crate::packets::{hci, lmp};
use crate::procedure::features;
use crate::procedure::legacy_pairing;
use crate::procedure::secure_simple_pairing;
use crate::procedure::Context;

pub async fn send_challenge(
    ctx: &impl Context,
    transaction_id: u8,
    _link_key: [u8; 16],
) -> Result<(), ()> {
    let random_number = [0; 16];
    ctx.send_lmp_packet(lmp::AuRandBuilder { transaction_id, random_number }.build());

    match ctx.receive_lmp_packet::<Either<lmp::SresPacket, lmp::NotAcceptedPacket>>().await {
        Either::Left(_response) => Ok(()),
        Either::Right(_) => Err(()),
    }
}

pub async fn receive_challenge(ctx: &impl Context, _link_key: [u8; 16]) {
    let _random_number = *ctx.receive_lmp_packet::<lmp::AuRandPacket>().await.get_random_number();
    ctx.send_lmp_packet(lmp::SresBuilder { transaction_id: 0, authentication_rsp: [0; 4] }.build());
}

pub async fn initiate(ctx: &impl Context) {
    let _ = ctx.receive_hci_command::<hci::AuthenticationRequestedPacket>().await;
    ctx.send_hci_event(
        hci::AuthenticationRequestedStatusBuilder {
            num_hci_command_packets,
            status: hci::ErrorCode::Success,
        }
        .build(),
    );

    ctx.send_hci_event(hci::LinkKeyRequestBuilder { bd_addr: ctx.peer_address() }.build());

    let status = match ctx.receive_hci_command::<Either<
        hci::LinkKeyRequestReplyPacket,
        hci::LinkKeyRequestNegativeReplyPacket,
    >>().await {
        Either::Left(_reply) => {
            ctx.send_hci_event(
                hci::LinkKeyRequestReplyCompleteBuilder {
                    num_hci_command_packets,
                    status: hci::ErrorCode::Success,
                    bd_addr: ctx.peer_address(),
                }
                .build(),
            );
            hci::ErrorCode::Success
        },
        Either::Right(_) => {
            ctx.send_hci_event(
                hci::LinkKeyRequestNegativeReplyCompleteBuilder {
                    num_hci_command_packets,
                    status: hci::ErrorCode::Success,
                    bd_addr: ctx.peer_address(),
                }
                .build(),
            );

            let result = if features::supported_on_both_page1(ctx, hci::LMPFeaturesPage1Bits::SecureSimplePairingHostSupport).await {
                secure_simple_pairing::initiate(ctx).await
            } else {
                legacy_pairing::initiate(ctx).await
            };

            match result {
                Ok(_) => hci::ErrorCode::Success,
                Err(_) => hci::ErrorCode::AuthenticationFailure
            }
        }
    };

    ctx.send_hci_event(
        hci::AuthenticationCompleteBuilder { status, connection_handle: ctx.peer_handle() }.build(),
    );
}

pub async fn respond(ctx: &impl Context) {
    match ctx.receive_lmp_packet::<Either<
        lmp::AuRandPacket,
        Either<lmp::IoCapabilityReqPacket, lmp::InRandPacket>
    >>()
    .await
    {
        Either::Left(_random_number) => {
            // TODO: Resolve authentication challenge
            // TODO: Ask for link key
            ctx.send_lmp_packet(lmp::SresBuilder { transaction_id: 0, authentication_rsp: [0; 4] }.build());
        },
        Either::Right(pairing) => {
            let _result = match pairing {
                Either::Left(io_capability_request) =>
                    secure_simple_pairing::respond(ctx, io_capability_request).await,
                Either::Right(in_rand) =>
                    legacy_pairing::respond(ctx, in_rand).await,
            };
        }
    }
}
