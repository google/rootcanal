// Bluetooth Core, Vol 2, Part C, 4.2.2

use crate::packets::{hci, lmp};
use crate::procedure::Context;

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

    Ok(())
}
