// Bluetooth Core, Vol 2, Part C, 4.2.2

use crate::packets::{hci, lmp};
use crate::procedure::{authentication, Context};

use crate::num_hci_command_packets;

pub async fn initiate(ctx: &impl Context) -> Result<(), ()> {
    ctx.send_hci_event(hci::PinCodeRequestBuilder { bd_addr: ctx.peer_address() }.build());

    let _pin_code = ctx.receive_hci_command::<hci::PinCodeRequestReplyPacket>().await;

    ctx.send_hci_event(
        hci::PinCodeRequestReplyCompleteBuilder {
            num_hci_command_packets: 1,
            status: hci::ErrorCode::Success,
            bd_addr: ctx.peer_address(),
        }
        .build(),
    );

    // TODO: handle result
    let _ = ctx
        .send_accepted_lmp_packet(
            lmp::InRandBuilder { transaction_id: 0, random_number: [0; 16] }.build(),
        )
        .await;

    ctx.send_lmp_packet(lmp::CombKeyBuilder { transaction_id: 0, random_number: [0; 16] }.build());

    let _ = ctx.receive_lmp_packet::<lmp::CombKeyPacket>().await;

    // Post pairing authentication
    let link_key = [0; 16];
    let auth_result = authentication::send_challenge(ctx, 0, link_key).await;
    authentication::receive_challenge(ctx, link_key).await;

    if auth_result.is_err() {
        return Err(());
    }
    ctx.send_hci_event(
        hci::LinkKeyNotificationBuilder {
            bd_addr: ctx.peer_address(),
            key_type: hci::KeyType::Combination,
            link_key,
        }
        .build(),
    );

    Ok(())
}

pub async fn respond(ctx: &impl Context, _request: lmp::InRandPacket) -> Result<(), ()> {
    ctx.send_hci_event(hci::PinCodeRequestBuilder { bd_addr: ctx.peer_address() }.build());

    let _pin_code = ctx.receive_hci_command::<hci::PinCodeRequestReplyPacket>().await;

    ctx.send_hci_event(
        hci::PinCodeRequestReplyCompleteBuilder {
            num_hci_command_packets,
            status: hci::ErrorCode::Success,
            bd_addr: ctx.peer_address(),
        }
        .build(),
    );

    ctx.send_lmp_packet(
        lmp::AcceptedBuilder { transaction_id: 0, accepted_opcode: lmp::Opcode::InRand }.build(),
    );

    let _ = ctx.receive_lmp_packet::<lmp::CombKeyPacket>().await;

    ctx.send_lmp_packet(lmp::CombKeyBuilder { transaction_id: 0, random_number: [0; 16] }.build());

    // Post pairing authentication
    let link_key = [0; 16];
    authentication::receive_challenge(ctx, link_key).await;
    let auth_result = authentication::send_challenge(ctx, 0, link_key).await;

    if auth_result.is_err() {
        return Err(());
    }
    ctx.send_hci_event(
        hci::LinkKeyNotificationBuilder {
            bd_addr: ctx.peer_address(),
            key_type: hci::KeyType::Combination,
            link_key,
        }
        .build(),
    );

    Ok(())
}
