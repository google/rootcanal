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

macro_rules! sequence_body {
        ($ctx:ident, ) => { None };
        ($ctx:ident, Lower Tester -> IUT: $packet:ident {
            $($name:ident: $value:expr),* $(,)?
        } $($tail:tt)*) => {{
            use crate::packets::lmp::*;

            let builder = paste! {
                $packet {
                    $($name: $value),*
                }
            };
            $ctx.0.in_lmp_packets.borrow_mut().push_back(builder.try_into().unwrap());

            let poll = crate::lmp::test::poll($ctx.1.as_mut());

            assert!($ctx.0.in_lmp_packets.borrow().is_empty(), "{} was not consumed by procedure", stringify!($packet));

            println!("Lower Tester -> IUT: {}", stringify!($packet));

            sequence_body!($ctx, $($tail)*).or(Some(poll))
        }};
        ($ctx:ident, Upper Tester -> IUT: $packet:ident {
            $($name:ident: $value:expr),* $(,)?
        } $($tail:tt)*) => {{
            use crate::packets::hci::*;

            let builder = paste! {
                $packet {
                    $($name: $value),*
                }
            };
            $ctx.0.hci_commands.borrow_mut().push_back(builder.try_into().unwrap());

            let poll = crate::lmp::test::poll($ctx.1.as_mut());

            assert!($ctx.0.hci_commands.borrow().is_empty(), "{} was not consumed by procedure", stringify!($packet));

            println!("Upper Tester -> IUT: {}", stringify!($packet));

            sequence_body!($ctx, $($tail)*).or(Some(poll))
        }};
        ($ctx:ident, IUT -> Upper Tester: $packet:ident {
            $($name:ident: $expected_value:expr),* $(,)?
        } $($tail:tt)*) => {{
            use crate::packets::hci::*;

            paste! {
                let packet: $packet = $ctx.0.hci_events.borrow_mut().pop_front().expect("No hci packet").try_into().unwrap();
            }

            $(
                let value = paste! { packet.$name() };
                assert_eq!(value.clone(), $expected_value);
            )*

            println!("IUT -> Upper Tester: {}", stringify!($packet));

            sequence_body!($ctx, $($tail)*)
        }};
        ($ctx:ident, IUT -> Lower Tester: $packet:ident {
            $($name:ident: $expected_value:expr),* $(,)?
        } $($tail:tt)*) => {{
            use crate::packets::lmp::*;

            paste! {
                let packet: $packet = $ctx.0.out_lmp_packets.borrow_mut().pop_front().expect("No lmp packet").try_into().unwrap();
            }

            $(
                let value = paste! { packet.$name() };
                assert_eq!(value.clone(), $expected_value);
            )*

            println!("IUT -> Lower Tester: {}", stringify!($packet));

            sequence_body!($ctx, $($tail)*)
        }};
        ($ctx:ident, repeat $number:literal times with ($var:ident in $iterable:expr) {
            $($inner:tt)*
        } $($tail:tt)*) => {{
            println!("repeat {}", $number);
            for (_, $var) in (0..$number).into_iter().zip($iterable) {
                sequence_body!($ctx, $($inner)*);
            }
            println!("endrepeat");

            sequence_body!($ctx, $($tail)*)
        }};
        ($ctx:ident, repeat $number:literal times {
            $($inner:tt)*
        } $($tail:tt)*) => {{
            println!("repeat {}", $number);
            for _ in 0..$number {
                sequence_body!($ctx, $($inner)*);
            }
            println!("endrepeat");

            sequence_body!($ctx, $($tail)*)
        }};
    }

macro_rules! sequence {
        ($procedure_fn:path, $context:path, $($tail:tt)*) => ({
            use paste::paste;
            use std::convert::TryInto;

            let procedure = $procedure_fn(&$context);

            use crate::future::pin;
            pin!(procedure);

            let mut ctx = (&$context, procedure);
            use crate::lmp::test::sequence_body;
            let last_poll = sequence_body!(ctx, $($tail)*).unwrap();

            assert!(last_poll.is_ready());
            assert!($context.in_lmp_packets.borrow().is_empty());
            assert!($context.out_lmp_packets.borrow().is_empty());
            assert!($context.hci_commands.borrow().is_empty());
            assert!($context.hci_events.borrow().is_empty());
        });
    }

pub(crate) use {sequence, sequence_body};
