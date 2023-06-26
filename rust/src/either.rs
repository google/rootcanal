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

impl_try_from!(lmp::LmpPacket);
impl_try_from!(hci::Command);
