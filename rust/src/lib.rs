//! Link Manager implemented in Rust

mod either;
mod ffi;
mod future;
mod llcp;
mod lmp;
mod packets;

pub use ffi::*;

/// Number of hci command packets used
/// in Command Complete and Command Status
#[allow(non_upper_case_globals)]
pub const num_hci_command_packets: u8 = 1;
