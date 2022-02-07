// Bluetooth Core, Vol 2, Part C, 4.2.5

use crate::num_hci_command_packets;
use crate::packets::{hci, lmp};
use crate::procedure::Context;

pub async fn initiate(ctx: &impl Context) {
    // TODO: handle turn off
    let _ = ctx.receive_hci_command::<hci::SetConnectionEncryptionPacket>().await;
    ctx.send_hci_event(
        hci::SetConnectionEncryptionStatusBuilder {
            num_hci_command_packets,
            status: hci::ErrorCode::Success,
        }
        .build(),
    );

    // TODO: handle failure
    let _ = ctx
        .send_accepted_lmp_packet(
            lmp::EncryptionModeReqBuilder { transaction_id: 0, encryption_mode: 0x1 }.build(),
        )
        .await;

    // TODO: handle failure
    let _ = ctx
        .send_accepted_lmp_packet(
            lmp::EncryptionKeySizeReqBuilder { transaction_id: 0, key_size: 16 }.build(),
        )
        .await;

    // TODO: handle failure
    let _ = ctx
        .send_accepted_lmp_packet(
            lmp::StartEncryptionReqBuilder { transaction_id: 0, random_number: [0; 16] }.build(),
        )
        .await;

    ctx.send_hci_event(
        hci::EncryptionChangeBuilder {
            status: hci::ErrorCode::Success,
            connection_handle: ctx.peer_handle(),
            encryption_enabled: hci::EncryptionEnabled::On,
        }
        .build(),
    );
}

pub async fn respond(ctx: &impl Context) {
    // TODO: handle
    let _ = ctx.receive_lmp_packet::<lmp::EncryptionModeReqPacket>().await;
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder { transaction_id: 0, accepted_opcode: lmp::Opcode::EncryptionModeReq }
            .build(),
    );

    let _ = ctx.receive_lmp_packet::<lmp::EncryptionKeySizeReqPacket>().await;
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder {
            transaction_id: 0,
            accepted_opcode: lmp::Opcode::EncryptionKeySizeReq,
        }
        .build(),
    );

    let _ = ctx.receive_lmp_packet::<lmp::StartEncryptionReqPacket>().await;
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder {
            transaction_id: 0,
            accepted_opcode: lmp::Opcode::StartEncryptionReq,
        }
        .build(),
    );

    ctx.send_hci_event(
        hci::EncryptionChangeBuilder {
            status: hci::ErrorCode::Success,
            connection_handle: ctx.peer_handle(),
            encryption_enabled: hci::EncryptionEnabled::On,
        }
        .build(),
    );
}
