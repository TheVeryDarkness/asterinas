// SPDX-License-Identifier: MPL-2.0

//! The host helper trampoline and its invocation state.

use core::{ffi::c_void, sync::atomic::Ordering};

use crate::abi::AbiScalar;

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
///
/// # Safety
///
/// `host` must point to a live, exclusively borrowed [`HostInvocation`] whose
/// counter pointer remains valid for the call; `output` must point to writable,
/// aligned [`AbiScalar`] storage.
pub unsafe extern "C" fn host_trampoline(
    host: *mut c_void,
    index: u32,
    _args: *const AbiScalar,
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
        _ => HOST_UNKNOWN,
    }
}
