// Bluetooth Core, Vol 2, Part C, 4.3.4

use crate::packets::lmp;
use crate::procedure::Context;

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
        *ctx.receive_lmp_packet::<lmp::FeaturesResExtPacket>().await.get_extended_features(),
    )
}

pub async fn respond(ctx: &impl Context) {
    let req = ctx.receive_lmp_packet::<lmp::FeaturesReqExtPacket>().await;
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
