// Bluetooth Core, Vol 2, Part C, 4.2.7

use std::convert::TryInto;

use num_traits::{FromPrimitive, ToPrimitive};

use crate::either::Either;
use crate::packets::{hci, lmp};
use crate::procedure::Context;

use crate::num_hci_command_packets;

fn has_mitm(requirements: hci::AuthenticationRequirements) -> bool {
    use hci::AuthenticationRequirements::*;

    match requirements {
        NoBonding | DedicatedBonding | GeneralBonding => false,
        NoBondingMitmProtection | DedicatedBondingMitmProtection | GeneralBondingMitmProtection => {
            true
        }
    }
}

enum AuthenticationMethod {
    OutOfBand,
    NumericComparaison,
    PasskeyEntry,
}

#[derive(Clone, Copy)]
struct AuthenticationParams {
    io_capability: hci::IoCapability,
    oob_data_present: hci::OobDataPresent,
    authentication_requirements: hci::AuthenticationRequirements,
}

// Bluetooth Core, Vol 2, Part C, 4.2.7.3
fn authentication_method(
    initiator: AuthenticationParams,
    responder: AuthenticationParams,
) -> AuthenticationMethod {
    use hci::IoCapability::*;
    use hci::OobDataPresent::*;

    if initiator.oob_data_present != NotPresent || responder.oob_data_present != NotPresent {
        AuthenticationMethod::OutOfBand
    } else if !has_mitm(initiator.authentication_requirements)
        && !has_mitm(responder.authentication_requirements)
    {
        AuthenticationMethod::NumericComparaison
    } else if (initiator.io_capability == KeyboardOnly
        && responder.io_capability != NoInputNoOutput)
        || (responder.io_capability == KeyboardOnly && initiator.io_capability != NoInputNoOutput)
    {
        AuthenticationMethod::PasskeyEntry
    } else {
        AuthenticationMethod::NumericComparaison
    }
}

const P192_PUBLIC_KEY_SIZE: usize = 48;

async fn send_public_key(ctx: &impl Context, transaction_id: u8, key: &[u8; P192_PUBLIC_KEY_SIZE]) {
    // TODO: handle error
    let _ = ctx
        .send_accepted_lmp_packet(
            lmp::EncapsulatedHeaderBuilder {
                transaction_id,
                major_type: 1,
                minor_type: 1,
                payload_length: P192_PUBLIC_KEY_SIZE as u8,
            }
            .build(),
        )
        .await;

    for chunk in key.chunks(16) {
        // TODO: handle error
        let _ = ctx
            .send_accepted_lmp_packet(
                lmp::EncapsulatedPayloadBuilder { transaction_id, data: chunk.try_into().unwrap() }
                    .build(),
            )
            .await;
    }
}

async fn receive_public_key(ctx: &impl Context, transaction_id: u8) -> [u8; P192_PUBLIC_KEY_SIZE] {
    let _ = ctx.receive_lmp_packet::<lmp::EncapsulatedHeaderPacket>().await;
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder { transaction_id, accepted_opcode: lmp::Opcode::EncapsulatedHeader }
            .build(),
    );

    let mut key = [0; P192_PUBLIC_KEY_SIZE];

    for chunk in key.chunks_mut(16) {
        let payload = ctx.receive_lmp_packet::<lmp::EncapsulatedPayloadPacket>().await;
        chunk.copy_from_slice(payload.get_data().as_slice());
        ctx.send_lmp_packet(
            lmp::AcceptedBuilder {
                transaction_id,
                accepted_opcode: lmp::Opcode::EncapsulatedPayload,
            }
            .build(),
        );
    }

    key
}

const COMMITMENT_VALUE_SIZE: usize = 16;
const NONCE_SIZE: usize = 16;

async fn receive_commitment(ctx: &impl Context, skip_first: bool) {
    let commitment_value = [0; COMMITMENT_VALUE_SIZE];

    if !skip_first {
        let confirm = ctx.receive_lmp_packet::<lmp::SimplePairingConfirmPacket>().await;
        if confirm.get_commitment_value() != &commitment_value {
            todo!();
        }
    }

    ctx.send_lmp_packet(
        lmp::SimplePairingConfirmBuilder { transaction_id: 0, commitment_value }.build(),
    );

    let _pairing_number = ctx.receive_lmp_packet::<lmp::SimplePairingNumberPacket>().await;
    // TODO: check pairing number
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder {
            transaction_id: 0,
            accepted_opcode: lmp::Opcode::SimplePairingNumber,
        }
        .build(),
    );

    let nonce = [0; NONCE_SIZE];

    // TODO: handle error
    let _ = ctx
        .send_accepted_lmp_packet(
            lmp::SimplePairingNumberBuilder { transaction_id: 0, nonce }.build(),
        )
        .await;
}

async fn send_commitment(ctx: &impl Context, skip_first: bool) {
    let commitment_value = [0; COMMITMENT_VALUE_SIZE];

    if !skip_first {
        ctx.send_lmp_packet(
            lmp::SimplePairingConfirmBuilder { transaction_id: 0, commitment_value }.build(),
        );
    }

    let confirm = ctx.receive_lmp_packet::<lmp::SimplePairingConfirmPacket>().await;

    if confirm.get_commitment_value() != &commitment_value {
        todo!();
    }
    let nonce = [0; NONCE_SIZE];

    // TODO: handle error
    let _ = ctx
        .send_accepted_lmp_packet(
            lmp::SimplePairingNumberBuilder { transaction_id: 0, nonce }.build(),
        )
        .await;

    let _pairing_number = ctx.receive_lmp_packet::<lmp::SimplePairingNumberPacket>().await;
    // TODO: check pairing number
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder {
            transaction_id: 0,
            accepted_opcode: lmp::Opcode::SimplePairingNumber,
        }
        .build(),
    );
}

async fn user_confirmation_request(ctx: &impl Context) -> Result<(), ()> {
    ctx.send_hci_event(
        hci::UserConfirmationRequestBuilder { bd_addr: ctx.peer_address(), numeric_value: 0 }
            .build(),
    );

    match ctx
        .receive_hci_command::<Either<
            hci::UserConfirmationRequestReplyPacket,
            hci::UserConfirmationRequestNegativeReplyPacket,
        >>()
        .await
    {
        Either::Left(_) => {
            ctx.send_hci_event(
                hci::UserConfirmationRequestReplyCompleteBuilder {
                    num_hci_command_packets,
                    status: hci::ErrorCode::Success,
                    bd_addr: ctx.peer_address(),
                }
                .build(),
            );
            Ok(())
        }
        Either::Right(_) => {
            ctx.send_hci_event(
                hci::UserConfirmationRequestNegativeReplyCompleteBuilder {
                    num_hci_command_packets,
                    status: hci::ErrorCode::Success,
                    bd_addr: ctx.peer_address(),
                }
                .build(),
            );
            Err(())
        }
    }
}

async fn user_passkey_request(ctx: &impl Context) -> Result<(), ()> {
    ctx.send_hci_event(hci::UserPasskeyRequestBuilder { bd_addr: ctx.peer_address() }.build());

    loop {
        match ctx
            .receive_hci_command::<Either<
                Either<
                    hci::UserPasskeyRequestReplyPacket,
                    hci::UserPasskeyRequestNegativeReplyPacket,
                >,
                hci::SendKeypressNotificationPacket,
            >>()
            .await
        {
            Either::Left(Either::Left(_)) => {
                ctx.send_hci_event(
                    hci::UserPasskeyRequestReplyCompleteBuilder {
                        num_hci_command_packets,
                        status: hci::ErrorCode::Success,
                        bd_addr: ctx.peer_address(),
                    }
                    .build(),
                );
                return Ok(());
            }
            Either::Left(Either::Right(_)) => {
                ctx.send_hci_event(
                    hci::UserPasskeyRequestNegativeReplyCompleteBuilder {
                        num_hci_command_packets,
                        status: hci::ErrorCode::Success,
                        bd_addr: ctx.peer_address(),
                    }
                    .build(),
                );
                return Err(());
            }
            Either::Right(_) => {
                ctx.send_hci_event(
                    hci::SendKeypressNotificationCompleteBuilder {
                        num_hci_command_packets,
                        status: hci::ErrorCode::Success,
                        bd_addr: ctx.peer_address(),
                    }
                    .build(),
                );
                // TODO: send LmpKeypressNotification
            }
        }
    }
}

async fn remote_oob_data_request(ctx: &impl Context) -> Result<(), ()> {
    ctx.send_hci_event(hci::RemoteOobDataRequestBuilder { bd_addr: ctx.peer_address() }.build());

    match ctx
        .receive_hci_command::<Either<
            hci::RemoteOobDataRequestReplyPacket,
            hci::RemoteOobDataRequestNegativeReplyPacket,
        >>()
        .await
    {
        Either::Left(_) => {
            ctx.send_hci_event(
                hci::RemoteOobDataRequestReplyCompleteBuilder {
                    num_hci_command_packets,
                    status: hci::ErrorCode::Success,
                    bd_addr: ctx.peer_address(),
                }
                .build(),
            );
            Ok(())
        }
        Either::Right(_) => {
            ctx.send_hci_event(
                hci::RemoteOobDataRequestNegativeReplyCompleteBuilder {
                    num_hci_command_packets,
                    status: hci::ErrorCode::Success,
                    bd_addr: ctx.peer_address(),
                }
                .build(),
            );
            Err(())
        }
    }
}

const CONFIRMATION_VALUE_SIZE: usize = 16;
const PASSKEY_ENTRY_REPEAT_NUMBER: usize = 20;

pub async fn initiate(ctx: &impl Context) -> Result<(), ()> {
    let initiator = {
        ctx.send_hci_event(hci::IoCapabilityRequestBuilder { bd_addr: ctx.peer_address() }.build());
        let reply = ctx.receive_hci_command::<hci::IoCapabilityRequestReplyPacket>().await;
        ctx.send_hci_event(
            hci::IoCapabilityRequestReplyCompleteBuilder {
                num_hci_command_packets,
                status: hci::ErrorCode::Success,
                bd_addr: ctx.peer_address(),
            }
            .build(),
        );

        ctx.send_lmp_packet(
            lmp::IoCapabilityReqBuilder {
                transaction_id: 0,
                io_capabilities: reply.get_io_capability().to_u8().unwrap(),
                oob_authentication_data: reply.get_oob_present().to_u8().unwrap(),
                authentication_requirement: reply
                    .get_authentication_requirements()
                    .to_u8()
                    .unwrap(),
            }
            .build(),
        );

        AuthenticationParams {
            io_capability: reply.get_io_capability(),
            oob_data_present: reply.get_oob_present(),
            authentication_requirements: reply.get_authentication_requirements(),
        }
    };
    let responder = {
        let response = ctx.receive_lmp_packet::<lmp::IoCapabilityResPacket>().await;

        let io_capability = hci::IoCapability::from_u8(response.get_io_capabilities()).unwrap();
        let oob_data_present =
            hci::OobDataPresent::from_u8(response.get_oob_authentication_data()).unwrap();
        let authentication_requirements =
            hci::AuthenticationRequirements::from_u8(response.get_authentication_requirement())
                .unwrap();

        ctx.send_hci_event(
            hci::IoCapabilityResponseBuilder {
                bd_addr: ctx.peer_address(),
                io_capability,
                oob_data_present,
                authentication_requirements,
            }
            .build(),
        );

        AuthenticationParams { io_capability, oob_data_present, authentication_requirements }
    };

    // Public Key Exchange
    {
        let public_key = [0; P192_PUBLIC_KEY_SIZE];
        send_public_key(ctx, 0, &public_key).await;
        let _key = receive_public_key(ctx, 0).await;
    }

    // Authentication Stage 1
    let result: Result<(), ()> = async {
        match authentication_method(initiator, responder) {
            AuthenticationMethod::NumericComparaison => {
                send_commitment(ctx, true).await;

                let _user_confirmation = user_confirmation_request(ctx).await?;
                Ok(())
            }
            AuthenticationMethod::PasskeyEntry => {
                if initiator.io_capability == hci::IoCapability::KeyboardOnly {
                    let _user_passkey = user_passkey_request(ctx).await?;
                } else {
                    ctx.send_hci_event(
                        hci::UserPasskeyNotificationBuilder {
                            bd_addr: ctx.peer_address(),
                            passkey: 0,
                        }
                        .build(),
                    );
                }
                for _ in 0..PASSKEY_ENTRY_REPEAT_NUMBER {
                    send_commitment(ctx, false).await;
                }
                Ok(())
            }
            AuthenticationMethod::OutOfBand => {
                if initiator.oob_data_present != hci::OobDataPresent::NotPresent {
                    let _remote_oob_data = remote_oob_data_request(ctx).await?;
                }

                send_commitment(ctx, false).await;
                Ok(())
            }
        }
    }
    .await;

    if result.is_err() {
        ctx.send_lmp_packet(lmp::NumericComparaisonFailedBuilder { transaction_id: 0 }.build());
        ctx.send_hci_event(
            hci::SimplePairingCompleteBuilder {
                status: hci::ErrorCode::AuthenticationFailure,
                bd_addr: ctx.peer_address(),
            }
            .build(),
        );
        return Err(());
    }

    // Authentication Stage 2
    {
        let confirmation_value = [0; CONFIRMATION_VALUE_SIZE];

        let result = ctx
            .send_accepted_lmp_packet(
                lmp::DhkeyCheckBuilder { transaction_id: 0, confirmation_value }.build(),
            )
            .await;

        if result.is_err() {
            ctx.send_hci_event(
                hci::SimplePairingCompleteBuilder {
                    status: hci::ErrorCode::AuthenticationFailure,
                    bd_addr: ctx.peer_address(),
                }
                .build(),
            );
            return Err(());
        }
    }

    {
        // TODO: check dhkey
        let _dhkey = ctx.receive_lmp_packet::<lmp::DhkeyCheckPacket>().await;
        ctx.send_lmp_packet(
            lmp::AcceptedBuilder { transaction_id: 0, accepted_opcode: lmp::Opcode::DhkeyCheck }
                .build(),
        );
    }

    ctx.send_hci_event(
        hci::SimplePairingCompleteBuilder {
            status: hci::ErrorCode::Success,
            bd_addr: ctx.peer_address(),
        }
        .build(),
    );

    Ok(())
}

pub async fn respond(ctx: &impl Context, request: lmp::IoCapabilityReqPacket) -> Result<(), ()> {
    let initiator = {
        let io_capability = hci::IoCapability::from_u8(request.get_io_capabilities()).unwrap();
        let oob_data_present =
            hci::OobDataPresent::from_u8(request.get_oob_authentication_data()).unwrap();
        let authentication_requirements =
            hci::AuthenticationRequirements::from_u8(request.get_authentication_requirement())
                .unwrap();

        ctx.send_hci_event(
            hci::IoCapabilityResponseBuilder {
                bd_addr: ctx.peer_address(),
                io_capability,
                oob_data_present,
                authentication_requirements,
            }
            .build(),
        );

        AuthenticationParams { io_capability, oob_data_present, authentication_requirements }
    };

    let responder = {
        ctx.send_hci_event(hci::IoCapabilityRequestBuilder { bd_addr: ctx.peer_address() }.build());
        let reply = ctx.receive_hci_command::<hci::IoCapabilityRequestReplyPacket>().await;
        ctx.send_hci_event(
            hci::IoCapabilityRequestReplyCompleteBuilder {
                num_hci_command_packets,
                status: hci::ErrorCode::Success,
                bd_addr: ctx.peer_address(),
            }
            .build(),
        );

        ctx.send_lmp_packet(
            lmp::IoCapabilityResBuilder {
                transaction_id: 0,
                io_capabilities: reply.get_io_capability().to_u8().unwrap(),
                oob_authentication_data: reply.get_oob_present().to_u8().unwrap(),
                authentication_requirement: reply
                    .get_authentication_requirements()
                    .to_u8()
                    .unwrap(),
            }
            .build(),
        );
        AuthenticationParams {
            io_capability: reply.get_io_capability(),
            oob_data_present: reply.get_oob_present(),
            authentication_requirements: reply.get_authentication_requirements(),
        }
    };

    // Public Key Exchange
    {
        let public_key = [0; P192_PUBLIC_KEY_SIZE];
        let _key = receive_public_key(ctx, 0).await;
        send_public_key(ctx, 0, &public_key).await;
    }

    // Authentication Stage 1

    let negative_user_confirmation = match authentication_method(initiator, responder) {
        AuthenticationMethod::NumericComparaison => {
            receive_commitment(ctx, true).await;

            let user_confirmation = user_confirmation_request(ctx).await;
            user_confirmation.is_err()
        }
        AuthenticationMethod::PasskeyEntry => {
            if responder.io_capability == hci::IoCapability::KeyboardOnly {
                // TODO: handle error
                let _user_passkey = user_passkey_request(ctx).await;
            } else {
                ctx.send_hci_event(
                    hci::UserPasskeyNotificationBuilder { bd_addr: ctx.peer_address(), passkey: 0 }
                        .build(),
                );
            }
            for _ in 0..PASSKEY_ENTRY_REPEAT_NUMBER {
                receive_commitment(ctx, false).await;
            }
            false
        }
        AuthenticationMethod::OutOfBand => {
            if responder.oob_data_present != hci::OobDataPresent::NotPresent {
                // TODO: handle error
                let _remote_oob_data = remote_oob_data_request(ctx).await;
            }

            receive_commitment(ctx, false).await;
            false
        }
    };

    let _dhkey = match ctx
        .receive_lmp_packet::<Either<lmp::NumericComparaisonFailedPacket, lmp::DhkeyCheckPacket>>()
        .await
    {
        Either::Left(_) => {
            // Numeric comparaison failed
            ctx.send_hci_event(
                hci::SimplePairingCompleteBuilder {
                    status: hci::ErrorCode::AuthenticationFailure,
                    bd_addr: ctx.peer_address(),
                }
                .build(),
            );
            return Err(());
        }
        Either::Right(dhkey) => dhkey,
    };

    if negative_user_confirmation {
        ctx.send_lmp_packet(
            lmp::NotAcceptedBuilder {
                transaction_id: 0,
                not_accepted_opcode: lmp::Opcode::DhkeyCheck,
                error_code: hci::ErrorCode::AuthenticationFailure.to_u8().unwrap(),
            }
            .build(),
        );
        ctx.send_hci_event(
            hci::SimplePairingCompleteBuilder {
                status: hci::ErrorCode::AuthenticationFailure,
                bd_addr: ctx.peer_address(),
            }
            .build(),
        );
        return Err(());
    }
    // Authentication Stage 2

    let confirmation_value = [0; CONFIRMATION_VALUE_SIZE];

    ctx.send_lmp_packet(
        lmp::AcceptedBuilder { transaction_id: 0, accepted_opcode: lmp::Opcode::DhkeyCheck }
            .build(),
    );

    // TODO: handle error
    let _ = ctx
        .send_accepted_lmp_packet(
            lmp::DhkeyCheckBuilder { transaction_id: 0, confirmation_value }.build(),
        )
        .await;

    ctx.send_hci_event(
        hci::SimplePairingCompleteBuilder {
            status: hci::ErrorCode::Success,
            bd_addr: ctx.peer_address(),
        }
        .build(),
    );

    Ok(())
}
