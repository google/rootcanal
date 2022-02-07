use std::convert::TryFrom;

use crate::packets::{hci, lmp};

pub enum Either<L, R> {
    Left(L),
    Right(R),
}

macro_rules! impl_try_from {
    ($T: path) => {
        impl<L, R> TryFrom<$T> for Either<L, R>
        where
            L: TryFrom<$T>,
            R: TryFrom<$T>,
        {
            type Error = ();

            fn try_from(value: $T) -> Result<Self, Self::Error> {
                let left = L::try_from(value.clone());
                if let Ok(left) = left {
                    return Ok(Either::Left(left));
                }
                let right = R::try_from(value);
                if let Ok(right) = right {
                    return Ok(Either::Right(right));
                }
                Err(())
            }
        }
    };
}

impl_try_from!(lmp::PacketPacket);
impl_try_from!(hci::CommandPacket);
