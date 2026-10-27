// SPDX-License-Identifier: MPL-2.0

//! The host helper trampoline and its invocation state.

use core::{ffi::c_void, sync::atomic::Ordering};

use ostd::mm::KERNEL_VADDR_RANGE;

use crate::{
    abi::AbiScalar,
    log::{MAX_MESSAGE_BYTES, append},
};

/// Status returned for a successful host helper call.
pub const HOST_OK: u32 = 0;

/// Status returned for an unknown helper index.
const HOST_UNKNOWN: u32 = 1;

/// The invocation-local state the trampoline dispatches against.
pub struct HostInvocation {
    /// Points to the program's counter.
    pub counter: *const core::sync::atomic::AtomicU64,
}

/// Dispatches a helper call from compiled code.
///
/// Index 0 is the counter helper: it atomically increments the program's
/// counter and writes the new value to `output` as an unsigned 64-bit scalar.
/// Index 2 is `rsm_printk(ptr: *const u8, len: usize) -> ()`: it appends the
/// `len` bytes at `ptr` to the [`crate::log`] ring buffer.
///
/// # Safety
///
/// `host` must point to a live, exclusively borrowed [`HostInvocation`] whose
/// counter pointer remains valid for the call; `output` must point to writable,
/// aligned [`AbiScalar`] storage. For index 2, `args` must point to two
/// readable, initialized [`AbiScalar`] slots holding the byte pointer and the
/// length.
pub unsafe extern "C" fn host_trampoline(
    host: *mut c_void,
    index: u32,
    args: *const AbiScalar,
    output: *mut AbiScalar,
) -> u32 {
    if host.is_null() || output.is_null() {
        return HOST_UNKNOWN;
    }
    // SAFETY: The caller guarantees a live, exclusively borrowed invocation.
    let invocation = unsafe { &*(host as *const HostInvocation) };
    match index {
        0 => {
            // SAFETY: The invocation's counter pointer is valid for this call.
            let counter = unsafe { &*invocation.counter };
            let value = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            // SAFETY: `output` is writable per the helper contract.
            unsafe { (*output).bits = value };
            HOST_OK
        }
        2 => {
            if args.is_null() {
                return HOST_UNKNOWN;
            }

            // SAFETY: The caller supplies the two readable, initialized
            // argument slots for helper index 2.
            let len = unsafe { (*args.add(1)).bits } as usize;
            let len = len.min(MAX_MESSAGE_BYTES);
            if len == 0 {
                return HOST_OK;
            }

            // SAFETY: The caller supplies the two readable, initialized
            // argument slots for helper index 2.
            let ptr = unsafe { (*args).bits } as usize;
            let Some(end) = ptr.checked_add(len) else {
                return HOST_UNKNOWN;
            };

            // Confine the read to the kernel address space. This is a defensive
            // check, not the security boundary: the loader is the trust
            // boundary, and verified programs may only pass pointers to memory
            // the verifier proved they can read. Rejecting user and
            // non-canonical addresses here still bounds a buggy program's
            // reach and keeps `len` capped so a single call cannot scan memory.
            if !KERNEL_VADDR_RANGE.contains(&ptr) || !KERNEL_VADDR_RANGE.contains(&end) {
                return HOST_UNKNOWN;
            }

            // SAFETY:
            // 1. `ptr` is non-null because `len > 0` and the range lies within
            //    `KERNEL_VADDR_RANGE`, which excludes the null page.
            // 2. `ptr..end` is a `len`-byte range inside the kernel address
            //    space, so it addresses supervisor memory rather than user
            //    memory. The producing program is admitted only through the
            //    `require_rsm_capability`-gated loader, which is the trust
            //    boundary that vouches for the pointer's live backing memory.
            // 3. `len` is at most `MAX_MESSAGE_BYTES`, so the slice length
            //    cannot overflow `isize::MAX`.
            // 4. The trampoline only reads the bytes; it never writes through
            //    the slice, so no aliasing rule is violated.
            let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
            append(bytes);
            HOST_OK
        }
        _ => HOST_UNKNOWN,
    }
}
