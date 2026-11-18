// SPDX-License-Identifier: MPL-2.0

//! Counts successful one-byte allocations made through Rust's global allocator.

use std::alloc::{Layout, alloc, dealloc};

use rsm_apis::{
    print_kernel, rsm_heap_read_byte, rsm_heap_write_byte, rsm_map_fetch_add, rsm_map_get_or_create,
};

#[rsm::export]
pub fn main(hook_id: u64, _phase: u64, _invocation: u64, _fd: u64, _buf: u64, len: u64) -> u32 {
    const LAYOUT: Layout = Layout::new::<u8>();
    if len == 2 {
        // The guest deliberately exceeds the invocation's 512-byte budget.
        const TOO_LARGE: Layout = Layout::new::<[u8; 513]>();
        // SAFETY: The layout is nonzero. A successful checked write proves the
        // pointer names a live allocation before it is released.
        let ptr = unsafe { alloc(TOO_LARGE) };
        if rsm_heap_write_byte(ptr, 0, 0) {
            unsafe { dealloc(ptr, TOO_LARGE) };
        }
        return 0;
    }
    let value = (hook_id as u8) | 1;
    // SAFETY: The allocation has nonzero size. The accessors validate its base,
    // bounds and invocation. The successful write rules out a null allocation.
    let ptr = unsafe { alloc(LAYOUT) };
    if !rsm_heap_write_byte(ptr, 0, value) {
        return 0;
    }
    let observed = rsm_heap_read_byte(ptr, 0);
    // SAFETY: ptr belongs to this invocation and is released once with its layout.
    unsafe { dealloc(ptr, LAYOUT) };
    if observed == value as u32 {
        let handle = rsm_map_get_or_create(0, 1);
        if handle == 0 {
            return 0;
        }
        rsm_map_fetch_add(handle, 0, observed as u64);
        return print_kernel();
    }
    0
}
