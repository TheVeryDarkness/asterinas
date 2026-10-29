// SPDX-License-Identifier: MPL-2.0

//! The host helper dispatch and its invocation state.
//!
//! The generic callback-out trampoline lives in `ostd::mm::callback`; this
//! module supplies the RSM-specific dispatcher and the invocation state it
//! reads. Helper `index 0` atomically increments the program's counter, and
//! `index 2` (`rsm_printk`) appends a byte range to the [`crate::log`] ring.
//!
//! # Trust boundary
//!
//! The dispatcher below dereferences pointers that ultimately originate from
//! the compiled code (`host`, `args`, `output`). That is sound only if the code
//! is itself trusted/verified; see `ostd::mm::callback` for the shared contract.

use core::{ffi::c_void, sync::atomic::Ordering};

use ostd::mm::{
    KERNEL_VADDR_RANGE,
    callback::{HOST_OK, HOST_UNKNOWN, HostCallbackTable},
};

use crate::{
    abi::AbiScalar,
    log::{MAX_MESSAGE_BYTES, append},
};

/// The invocation-local state the trampoline dispatches against.
///
/// `table` is the first field so `ostd::mm::callback::host_trampoline` can
/// recover the dispatcher from the `host` pointer the compiled code passes
/// back.
#[repr(C)]
pub struct HostInvocation {
    table: HostCallbackTable,
    /// Points to the program's counter.
    counter: *const core::sync::atomic::AtomicU64,
}

impl HostInvocation {
    /// Builds the invocation state for the given counter.
    pub fn new(counter: &core::sync::atomic::AtomicU64) -> Self {
        Self {
            table: HostCallbackTable { dispatch },
            counter: counter as *const _,
        }
    }
}

/// RSM's helper dispatcher.
///
/// # Safety
///
/// `host` must point to a live, exclusively borrowed [`HostInvocation`];
/// `output` must point to writable, aligned [`AbiScalar`] storage. For index 2,
/// `args` must point to two readable, initialized [`AbiScalar`] slots holding
/// the byte pointer and the length.
unsafe extern "C" fn dispatch(
    host: *mut c_void,
    index: u32,
    args: *const c_void,
    output: *mut c_void,
) -> u32 {
    if output.is_null() {
        return HOST_UNKNOWN;
    }
    // SAFETY: `host` points to the `HostInvocation` set by `RsmProgram::observe`,
    // and `ostd::mm::callback::host_trampoline` has already rejected a null host.
    let invocation = unsafe { &*(host as *const HostInvocation) };
    match index {
        0 => {
            // SAFETY: `counter` is valid while the program lives.
            let counter = unsafe { &*invocation.counter };
            let value = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            // SAFETY: `output` is non-null and points to writable `AbiScalar`
            // storage per the helper contract.
            unsafe { (*(output as *mut AbiScalar)).bits = value };
            HOST_OK
        }
        2 => {
            let args = args as *const AbiScalar;
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
            // Terminate each message so /proc/rsm_log stays line-oriented, like
            // `bpf_trace_printk`'s trailing newline.
            append(b"\n");
            HOST_OK
        }
        _ => HOST_UNKNOWN,
    }
}
