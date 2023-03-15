use std::mem::ManuallyDrop;
use std::rc::Rc;
use std::slice;

use crate::manager::LinkManager;
use crate::packets::{hci, lmp};

/// Link Manager callbacks
#[repr(C)]
#[derive(Clone)]
pub struct LinkManagerOps {
    user_pointer: *mut (),
    get_handle: unsafe extern "C" fn(user: *mut (), address: *const [u8; 6]) -> u16,
    get_address: unsafe extern "C" fn(user: *mut (), handle: u16, result: *mut [u8; 6]),
    extended_features: unsafe extern "C" fn(user: *mut (), features_page: u8) -> u64,
    send_hci_event: unsafe extern "C" fn(user: *mut (), data: *const u8, len: usize),
    send_lmp_packet:
        unsafe extern "C" fn(user: *mut (), to: *const [u8; 6], data: *const u8, len: usize),
}

impl LinkManagerOps {
    pub(crate) fn get_address(&self, handle: u16) -> Option<hci::Address> {
        let mut result = hci::EMPTY_ADDRESS;
        unsafe { (self.get_address)(self.user_pointer, handle, &mut result.bytes as *mut _) };
        if result == hci::EMPTY_ADDRESS {
            None
        } else {
            Some(result)
        }
    }

    pub(crate) fn get_handle(&self, addr: hci::Address) -> u16 {
        unsafe { (self.get_handle)(self.user_pointer, &addr.bytes as *const _) }
    }

    pub(crate) fn extended_features(&self, features_page: u8) -> u64 {
        unsafe { (self.extended_features)(self.user_pointer, features_page) }
    }

    pub(crate) fn send_hci_event(&self, packet: &[u8]) {
        unsafe { (self.send_hci_event)(self.user_pointer, packet.as_ptr(), packet.len()) }
    }

    pub(crate) fn send_lmp_packet(&self, to: hci::Address, packet: &[u8]) {
        unsafe {
            (self.send_lmp_packet)(
                self.user_pointer,
                &to.bytes as *const _,
                packet.as_ptr(),
                packet.len(),
            )
        }
    }
}

/// Create a new link manager instance
/// # Arguments
/// * `ops` - Function callbacks required by the link manager
#[no_mangle]
pub extern "C" fn link_manager_create(ops: LinkManagerOps) -> *const LinkManager {
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
    let lm = ManuallyDrop::new(Rc::from_raw(lm));
    lm.add_link(hci::Address { bytes: *peer }).is_ok()
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
    let lm = ManuallyDrop::new(Rc::from_raw(lm));
    lm.remove_link(hci::Address { bytes: *peer }).is_ok()
}

/// Run the Link Manager procedures
/// # Arguments
/// * `lm` - link manager pointer
/// # Safety
/// - This should be called from the thread of creation
/// - `lm` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn link_manager_tick(lm: *const LinkManager) {
    let lm = ManuallyDrop::new(Rc::from_raw(lm));
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
    let lm = ManuallyDrop::new(Rc::from_raw(lm));
    let data = slice::from_raw_parts(data, len);

    if let Ok(packet) = hci::CommandPacket::parse(data) {
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
    let lm = ManuallyDrop::new(Rc::from_raw(lm));
    let data = slice::from_raw_parts(data, len);

    if let Ok(packet) = lmp::PacketPacket::parse(data) {
        lm.ingest_lmp(hci::Address { bytes: *from }, packet).is_ok()
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
    let _ = Rc::from_raw(lm);
}
