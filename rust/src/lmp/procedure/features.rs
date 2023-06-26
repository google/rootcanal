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

//! Bluetooth Core, Vol 2, Part C, 4.3.4

use crate::lmp::procedure::Context;
use crate::packets::lmp;

pub async fn initiate(ctx: &impl Context, features_page: u8) -> u64 {
    ctx.send_lmp_packet(
        lmp::FeaturesReqExtBuilder {
            transaction_id: 0,
            features_page,
            max_supported_page: 1,
            extended_features: ctx.extended_features(features_page).to_le_bytes(),
        }
        .build(),
    );

    u64::from_le_bytes(
        *ctx.receive_lmp_packet::<lmp::FeaturesResExt>().await.get_extended_features(),
    )
}

pub async fn respond(ctx: &impl Context) {
    let req = ctx.receive_lmp_packet::<lmp::FeaturesReqExt>().await;
    let features_page = req.get_features_page();

    ctx.send_lmp_packet(
        lmp::FeaturesResExtBuilder {
            transaction_id: 0,
            features_page,
            max_supported_page: 1,
            extended_features: ctx.extended_features(features_page).to_le_bytes(),
        }
        .build(),
    );
}

async fn supported_on_both_page(ctx: &impl Context, page_number: u8, feature_mask: u64) -> bool {
    let local_supported = ctx.extended_features(page_number) & feature_mask != 0;
    // Lazy peer features
    let peer_supported = async move {
        let page = if let Some(page) = ctx.peer_extended_features(page_number) {
            page
        } else {
            crate::lmp::procedure::features::initiate(ctx, page_number).await
        };
        page & feature_mask != 0
    };
    local_supported && peer_supported.await
}

pub async fn supported_on_both_page1(
    ctx: &impl Context,
    feature: crate::packets::hci::LMPFeaturesPage1Bits,
) -> bool {
    supported_on_both_page(ctx, 1, feature.into()).await
}

pub async fn supported_on_both_page2(
    ctx: &impl Context,
    feature: crate::packets::hci::LMPFeaturesPage2Bits,
) -> bool {
    supported_on_both_page(ctx, 2, feature.into()).await
}
