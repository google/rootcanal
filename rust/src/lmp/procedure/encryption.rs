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

//! Bluetooth Core, Vol 2, Part C, 4.2.5

use super::features;
use crate::lmp::procedure::Context;
use crate::num_hci_command_packets;
use crate::packets::{hci, lmp};

use hci::LMPFeaturesPage1Bits::SecureConnectionsHostSupport;
use hci::LMPFeaturesPage2Bits::SecureConnectionsControllerSupport;

pub async fn initiate(ctx: &impl Context) {
    // TODO: handle turn off
    let _ = ctx.receive_hci_command::<hci::SetConnectionEncryption>().await;
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

    let aes_ccm = features::supported_on_both_page1(ctx, SecureConnectionsHostSupport).await
        && features::supported_on_both_page2(ctx, SecureConnectionsControllerSupport).await;

    ctx.send_hci_event(
        hci::EncryptionChangeBuilder {
            status: hci::ErrorCode::Success,
            connection_handle: ctx.peer_handle(),
            encryption_enabled: if aes_ccm {
                hci::EncryptionEnabled::BrEdrAesCcm
            } else {
                hci::EncryptionEnabled::On
            },
        }
        .build(),
    );
}

pub async fn respond(ctx: &impl Context) {
    // TODO: handle
    let _ = ctx.receive_lmp_packet::<lmp::EncryptionModeReq>().await;
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder { transaction_id: 0, accepted_opcode: lmp::Opcode::EncryptionModeReq }
            .build(),
    );

    let _ = ctx.receive_lmp_packet::<lmp::EncryptionKeySizeReq>().await;
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder {
            transaction_id: 0,
            accepted_opcode: lmp::Opcode::EncryptionKeySizeReq,
        }
        .build(),
    );

    let _ = ctx.receive_lmp_packet::<lmp::StartEncryptionReq>().await;
    ctx.send_lmp_packet(
        lmp::AcceptedBuilder {
            transaction_id: 0,
            accepted_opcode: lmp::Opcode::StartEncryptionReq,
        }
        .build(),
    );

    let aes_ccm = features::supported_on_both_page1(ctx, SecureConnectionsHostSupport).await
        && features::supported_on_both_page2(ctx, SecureConnectionsControllerSupport).await;

    ctx.send_hci_event(
        hci::EncryptionChangeBuilder {
            status: hci::ErrorCode::Success,
            connection_handle: ctx.peer_handle(),
            encryption_enabled: if aes_ccm {
                hci::EncryptionEnabled::BrEdrAesCcm
            } else {
                hci::EncryptionEnabled::On
            },
        }
        .build(),
    );
}

#[cfg(test)]
mod tests {
    use super::initiate;
    use super::respond;
    use crate::lmp::procedure::Context;
    use crate::lmp::test::{sequence, TestContext};

    use crate::packets::hci::LMPFeaturesPage1Bits::SecureConnectionsHostSupport;
    use crate::packets::hci::LMPFeaturesPage2Bits::SecureConnectionsControllerSupport;

    #[test]
    fn accept_encryption() {
        let context = TestContext::new();
        let procedure = respond;

        include!("../../../test/ENC/BV-01-C.in");
    }

    #[test]
    fn initiate_encryption() {
        let context = TestContext::new();
        let procedure = initiate;

        include!("../../../test/ENC/BV-05-C.in");
    }

    #[test]
    fn accept_aes_ccm_encryption_request() {
        let context = TestContext::new()
            .with_page_1_feature(SecureConnectionsHostSupport)
            .with_page_2_feature(SecureConnectionsControllerSupport)
            .with_peer_page_1_feature(SecureConnectionsHostSupport)
            .with_peer_page_2_feature(SecureConnectionsControllerSupport);
        let procedure = respond;

        include!("../../../test/ENC/BV-26-C.in");
    }

    #[test]
    fn initiate_aes_ccm_encryption() {
        let context = TestContext::new()
            .with_page_1_feature(SecureConnectionsHostSupport)
            .with_page_2_feature(SecureConnectionsControllerSupport)
            .with_peer_page_1_feature(SecureConnectionsHostSupport)
            .with_peer_page_2_feature(SecureConnectionsControllerSupport);
        let procedure = initiate;

        include!("../../../test/ENC/BV-34-C.in");
    }
}
