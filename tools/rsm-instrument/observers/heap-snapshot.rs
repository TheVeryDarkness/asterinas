// SPDX-License-Identifier: MPL-2.0

//! Keeps the seven most recent read sizes in a serialized workload.
//! Sizes above 255 are recorded as 255. The eighth byte is the next write position.

use std::alloc::{Layout, alloc, dealloc};

use rsm_apis::{
    rsm_heap_read_byte, rsm_heap_write_byte, rsm_map_get_or_create, rsm_map_restore_bytes,
    rsm_map_save_bytes,
};

#[rsm::export]
pub fn main(_hook: u64, phase: u64, _id: u64, _fd: u64, _buf: u64, len: u64) -> u32 {
    if phase != 0 {
        return 0;
    }
    let window = rsm_map_get_or_create(0, 1);
    if window == 0 {
        return 0;
    }
    const LAYOUT: Layout = Layout::new::<[u8; 8]>();
    // SAFETY: The layout has nonzero size. The host rejects exhaustion before
    // returning to native code. A successful restore initializes all eight bytes.
    let bytes = unsafe { alloc(LAYOUT) };
    if !rsm_map_restore_bytes(window, bytes) {
        return 0;
    }
    let index = rsm_heap_read_byte(bytes, 7);
    if index < 7 {
        let size = if len < 255 { len as u8 } else { 255 };
        let next = if index == 6 { 0 } else { (index + 1) as u8 };
        if rsm_heap_write_byte(bytes, index as usize, size) && rsm_heap_write_byte(bytes, 7, next) {
            rsm_map_save_bytes(window, bytes);
        }
    }
    // SAFETY: Restore succeeded on this live allocation. The map owns its copy.
    unsafe { dealloc(bytes, LAYOUT) };
    0
}
