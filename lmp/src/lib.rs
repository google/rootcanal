//! Link Manager implemented in Rust

mod ec;
mod either;
mod ffi;
mod future;
mod manager;
mod packets;
mod procedure;

#[cfg(test)]
mod test;

pub use ffi::*;
pub use manager::num_hci_command_packets;
