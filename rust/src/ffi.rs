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

// TODO(b/290018030): Remove this and add proper safety comments.
#![allow(clippy::undocumented_unsafe_blocks)]

use std::convert::TryFrom;
use std::mem::ManuallyDrop;
use std::rc::Rc;
use std::slice;

use crate::llcp::manager::LinkLayer;
use crate::lmp::manager::LinkManager;
use crate::packets::{hci, llcp, lmp};

/// Link Manager callbacks
#[repr(C)]
#[derive(Clone)]
pub struct ControllerOps {
    user_pointer: *mut (),
    get_handle: unsafe extern "C" fn(user: *mut (), address: *const [u8; 6]) -> u16,
    get_address: unsafe extern "C" fn(user: *mut (), handle: u16, result: *mut [u8; 6]),
    get_extended_features: unsafe extern "C" fn(user: *mut (), features_page: u8) -> u64,
    get_le_features: unsafe extern "C" fn(user: *mut ()) -> u64,
    get_le_event_mask: unsafe extern "C" fn(user: *mut ()) -> u64,
    send_hci_event: unsafe extern "C" fn(user: *mut (), data: *const u8, len: usize),
    send_lmp_packet:
        unsafe extern "C" fn(user: *mut (), to: *const [u8; 6], data: *const u8, len: usize),
    send_llcp_packet: unsafe extern "C" fn(user: *mut (), handle: u16, data: *const u8, len: usize),
}

impl ControllerOps {
    pub(crate) fn get_address(&self, handle: u16) -> Option<hci::Address> {
        let mut result = [0; 6];
        unsafe { (self.get_address)(self.user_pointer, handle, &mut result as *mut _) };
        let addr = hci::Address::from(&result);
        (addr != hci::EMPTY_ADDRESS).then_some(addr)
    }

    pub(crate) fn get_handle(&self, addr: hci::Address) -> u16 {
        let addr_bytes: [u8; 6] = addr.into();
        unsafe { (self.get_handle)(self.user_pointer, &addr_bytes as *const _) }
    }

    pub(crate) fn get_extended_features(&self, features_page: u8) -> u64 {
        unsafe { (self.get_extended_features)(self.user_pointer, features_page) }
    }

    pub(crate) fn get_le_features(&self) -> u64 {
        unsafe { (self.get_le_features)(self.user_pointer) }
    }

    #[allow(dead_code)]
    pub(crate) fn get_le_event_mask(&self) -> u64 {
        unsafe { (self.get_le_event_mask)(self.user_pointer) }
    }

    pub(crate) fn send_hci_event(&self, packet: &[u8]) {
        unsafe { (self.send_hci_event)(self.user_pointer, packet.as_ptr(), packet.len()) }
    }

    pub(crate) fn send_lmp_packet(&self, to: hci::Address, packet: &[u8]) {
        let to_bytes: [u8; 6] = to.into();
        unsafe {
            (self.send_lmp_packet)(
                self.user_pointer,
                &to_bytes as *const _,
                packet.as_ptr(),
                packet.len(),
            )
        }
    }

    pub(crate) fn send_llcp_packet(&self, handle: u16, packet: &[u8]) {
        unsafe { (self.send_llcp_packet)(self.user_pointer, handle, packet.as_ptr(), packet.len()) }
    }
}

/// Create a new link manager instance
/// # Arguments
/// * `ops` - Function callbacks required by the link manager
#[no_mangle]
pub extern "C" fn link_manager_create(ops: ControllerOps) -> *const LinkManager {
    Rc::into_raw(Rc::new(LinkManager::new(ops)))
}

/// Register a new link with a peer inside the link manager
/// # Arguments
/// * `lm` - link manager pointer
/// * `peer` - peer address as array of 6 bytes
/// # Safety
/// - This should be called from the thread of creation
/// - `lm` must be a valid pointer
/// - `peer` must be valid for reads for 6 bytes
#[no_mangle]
pub unsafe extern "C" fn link_manager_add_link(
    lm: *const LinkManager,
    peer: *const [u8; 6],
) -> bool {
    let lm = ManuallyDrop::new(unsafe { Rc::from_raw(lm) });
    unsafe { lm.add_link(hci::Address::from(&*peer)).is_ok() }
}

/// Unregister a link with a peer inside the link manager
/// Returns true if successful
/// # Arguments
/// * `lm` - link manager pointer
/// * `peer` - peer address as array of 6 bytes
/// # Safety
/// - This should be called from the thread of creation
/// - `lm` must be a valid pointer
/// - `peer` must be valid for reads for 6 bytes
#[no_mangle]
pub unsafe extern "C" fn link_manager_remove_link(
    lm: *const LinkManager,
    peer: *const [u8; 6],
) -> bool {
    let lm = ManuallyDrop::new(unsafe { Rc::from_raw(lm) });
    unsafe { lm.remove_link(hci::Address::from(&*peer)).is_ok() }
}

/// Run the Link Manager procedures
/// # Arguments
/// * `lm` - link manager pointer
/// # Safety
/// - This should be called from the thread of creation
/// - `lm` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn link_manager_tick(lm: *const LinkManager) {
    let lm = ManuallyDrop::new(unsafe { Rc::from_raw(lm) });
    lm.as_ref().tick();
}

/// Process an HCI packet with the link manager
/// Returns true if successful
/// # Arguments
/// * `lm` - link manager pointer
/// * `data` - HCI packet data
/// * `len` - HCI packet len
/// # Safety
/// - This should be called from the thread of creation
/// - `lm` must be a valid pointer
/// - `data` must be valid for reads of len `len`
#[no_mangle]
pub unsafe extern "C" fn link_manager_ingest_hci(
    lm: *const LinkManager,
    data: *const u8,
    len: usize,
) -> bool {
    let lm = ManuallyDrop::new(unsafe { Rc::from_raw(lm) });
    let data = unsafe { slice::from_raw_parts(data, len) };

    if let Ok(packet) = hci::Command::parse(data) {
        lm.ingest_hci(packet).is_ok()
    } else {
        false
    }
}

/// Process an LMP packet from a peer with the link manager
/// Returns true if successful
/// # Arguments
/// * `lm` - link manager pointer
/// * `from` - Address of peer as array of 6 bytes
/// * `data` - HCI packet data
/// * `len` - HCI packet len
/// # Safety
/// - This should be called from the thread of creation
/// - `lm` must be a valid pointers
/// - `from` must be valid pointer for reads for 6 bytes
/// - `data` must be valid for reads of len `len`
#[no_mangle]
pub unsafe extern "C" fn link_manager_ingest_lmp(
    lm: *const LinkManager,
    from: *const [u8; 6],
    data: *const u8,
    len: usize,
) -> bool {
    let lm = ManuallyDrop::new(unsafe { Rc::from_raw(lm) });
    let data = unsafe { slice::from_raw_parts(data, len) };

    if let Ok(packet) = lmp::LmpPacket::parse(data) {
        unsafe { lm.ingest_lmp(hci::Address::from(&*from), packet).is_ok() }
    } else {
        false
    }
}

/// Deallocate the link manager instance
/// # Arguments
/// * `lm` - link manager pointer
/// # Safety
/// - This should be called from the thread of creation
/// - `lm` must be a valid pointers and must not be reused afterwards
#[no_mangle]
pub unsafe extern "C" fn link_manager_destroy(lm: *const LinkManager) {
    unsafe {
        let _ = Rc::from_raw(lm);
    }
}

/// Create a new link manager instance
/// # Arguments
/// * `ops` - Function callbacks required by the link manager
#[no_mangle]
pub extern "C" fn link_layer_create(ops: ControllerOps) -> *const LinkLayer {
    Rc::into_raw(Rc::new(LinkLayer::new(ops)))
}

/// Register a new link with a peer inside the link layer
/// # Arguments
/// * `ll` - link layer pointer
/// * `handle` - connection handle for the link
/// * `peer_address` - peer address as array of 6 bytes
/// * `role` - connection role (peripheral or centrl) for the link
/// # Safety
/// - This should be called from the thread of creation
/// - `ll` must be a valid pointer
/// - `peer` must be valid for reads for 6 bytes
/// - `role` must be 0 (central) or 1 (peripheral)
#[no_mangle]
pub unsafe extern "C" fn link_layer_add_link(
    ll: *const LinkLayer,
    handle: u16,
    peer_address: *const [u8; 6],
    role: u8,
) -> bool {
    let mut ll = ManuallyDrop::new(unsafe { Rc::from_raw(ll) });
    let ll = Rc::get_mut(&mut ll).unwrap();
    let role = hci::Role::try_from(role).unwrap_or(hci::Role::Peripheral);
    unsafe { ll.add_link(handle, hci::Address::from(&*peer_address), role).is_ok() }
}

/// Unregister a link with a peer inside the link layer
/// Returns true if successful
/// # Arguments
/// * `ll` - link layer pointer
/// * `peer` - peer address as array of 6 bytes
/// # Safety
/// - This should be called from the thread of creation
/// - `ll` must be a valid pointer
/// - `peer` must be valid for reads for 6 bytes
#[no_mangle]
pub unsafe extern "C" fn link_layer_remove_link(ll: *const LinkLayer, handle: u16) -> bool {
    let mut ll = ManuallyDrop::new(unsafe { Rc::from_raw(ll) });
    let ll = Rc::get_mut(&mut ll).unwrap();
    ll.remove_link(handle).is_ok()
}

/// Run the Link Manager procedures
/// # Arguments
/// * `ll` - link layer pointer
/// # Safety
/// - This should be called from the thread of creation
/// - `ll` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn link_layer_tick(ll: *const LinkLayer) {
    let mut ll = ManuallyDrop::new(unsafe { Rc::from_raw(ll) });
    let ll = Rc::get_mut(&mut ll).unwrap();
    ll.tick();
}

/// Process an HCI packet with the link layer
/// Returns true if successful
/// # Arguments
/// * `ll` - link layer pointer
/// * `data` - HCI packet data
/// * `len` - HCI packet len
/// # Safety
/// - This should be called from the thread of creation
/// - `ll` must be a valid pointer
/// - `data` must be valid for reads of len `len`
#[no_mangle]
pub unsafe extern "C" fn link_layer_ingest_hci(
    ll: *const LinkLayer,
    data: *const u8,
    len: usize,
) -> bool {
    let mut ll = ManuallyDrop::new(unsafe { Rc::from_raw(ll) });
    let ll = Rc::get_mut(&mut ll).unwrap();
    let data = unsafe { slice::from_raw_parts(data, len) };

    if let Ok(packet) = hci::Command::parse(data) {
        ll.ingest_hci(packet).is_ok()
    } else {
        false
    }
}

/// Process an LLCP packet from a peer with the link layer
/// Returns true if successful
/// # Arguments
/// * `ll` - link layer pointer
/// * `handle` - ACL handle of the connection
/// * `data` - HCI packet data
/// * `len` - HCI packet len
/// # Safety
/// - This should be called from the thread of creation
/// - `ll` must be a valid pointers
/// - `data` must be valid for reads of len `len`
#[no_mangle]
pub unsafe extern "C" fn link_layer_ingest_llcp(
    ll: *const LinkLayer,
    handle: u16,
    data: *const u8,
    len: usize,
) -> bool {
    let mut ll = ManuallyDrop::new(unsafe { Rc::from_raw(ll) });
    let ll = Rc::get_mut(&mut ll).unwrap();
    let data = unsafe { slice::from_raw_parts(data, len) };

    if let Ok(packet) = llcp::LlcpPacket::parse(data) {
        ll.ingest_llcp(handle, packet).is_ok()
    } else {
        false
    }
}

/// Query the connection handle for a CIS established with
/// the input CIS and CIG identifiers.
/// Returns true if successful
/// # Arguments
/// * `ll` - link layer pointer
/// * `cig_id` - Identifier of the established Cig
/// * `cis_id` - Identifier of the established Cis
/// * `cis_connection_handle` - Returns the handle of the CIS if connected
/// # Safety
/// - This should be called from the thread of creation
/// - `ll` must be a valid pointers
#[no_mangle]
pub unsafe extern "C" fn link_layer_get_cis_connection_handle(
    ll: *const LinkLayer,
    cig_id: u8,
    cis_id: u8,
    cis_connection_handle: *mut u16,
) -> bool {
    let mut ll = ManuallyDrop::new(unsafe { Rc::from_raw(ll) });
    let ll = Rc::get_mut(&mut ll).unwrap();
    ll.get_cis_connection_handle(cig_id, cis_id)
        .map(|handle| unsafe {
            *cis_connection_handle = handle;
        })
        .is_some()
}

/// Query the CIS and CIG identifiers for a CIS established with
/// the input CIS connection handle.
/// Returns true if successful
/// # Arguments
/// * `ll` - link layer pointer
/// * `cis_connection_handle` - CIS connection handle
/// * `cig_id` - Returns the CIG identifier
/// * `cis_id` - Returns the CIS identifier
/// # Safety
/// - This should be called from the thread of creation
/// - `ll` must be a valid pointers
#[no_mangle]
pub unsafe extern "C" fn link_layer_get_cis_information(
    ll: *const LinkLayer,
    cis_connection_handle: u16,
    acl_connection_handle: *mut u16,
    cig_id: *mut u8,
    cis_id: *mut u8,
    max_sdu_tx: *mut u16,
) -> bool {
    let mut ll = ManuallyDrop::new(unsafe { Rc::from_raw(ll) });
    let ll = Rc::get_mut(&mut ll).unwrap();
    ll.get_cis(cis_connection_handle)
        .map(|cis| {
            if let Some(handle) = cis.acl_connection_handle {
                unsafe {
                    *acl_connection_handle = handle;
                }
            }
            unsafe {
                *cig_id = cis.cig_id;
                *cis_id = cis.cis_id;
                *max_sdu_tx = cis.max_sdu_tx().unwrap_or(0);
            }
        })
        .is_some()
}

/// Deallocate the link layer instance
/// # Arguments
/// * `ll` - link layer pointer
/// # Safety
/// - This should be called from the thread of creation
/// - `ll` must be a valid pointers and must not be reused afterwards
#[no_mangle]
pub unsafe extern "C" fn link_layer_destroy(ll: *const LinkLayer) {
    unsafe {
        let _ = Rc::from_raw(ll);
    }
}
