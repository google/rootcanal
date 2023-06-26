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

//! Bluetooth Core, Vol 2, Part C, 4.2.2

use crate::lmp::procedure::{authentication, Context};
use crate::packets::{hci, lmp};

use crate::num_hci_command_packets;

pub async fn initiate(ctx: &impl Context) -> Result<(), ()> {
    ctx.send_hci_event(hci::PinCodeRequestBuilder { bd_addr: ctx.peer_address() }.build());

    let _pin_code = ctx.receive_hci_command::<hci::PinCodeRequestReply>().await;

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

    let _ = ctx.receive_lmp_packet::<lmp::CombKey>().await;

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

pub async fn respond(ctx: &impl Context, _request: lmp::InRand) -> Result<(), ()> {
    ctx.send_hci_event(hci::PinCodeRequestBuilder { bd_addr: ctx.peer_address() }.build());

    let _pin_code = ctx.receive_hci_command::<hci::PinCodeRequestReply>().await;

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

    let _ = ctx.receive_lmp_packet::<lmp::CombKey>().await;

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
