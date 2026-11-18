// SPDX-License-Identifier: MPL-2.0

//! Host-callback trampoline for native programs.
//!
//! A native program placed via [`super::NativeProgram`] may call back into the
//! kernel through a single fixed helper trampoline. The kernel adapter installs
//! a [`HostCallbackTable`] and hands its address to the program as part of the
//! invocation context; the program passes that address back to
//! [`host_trampoline`] to dispatch a helper by index.
//!
//! This module owns the raw-pointer plumbing of the callback-out boundary:
//! validating and dereferencing the `host` pointer, and forwarding the
//! dispatcher. The dispatcher itself is provided by the adapter and implements
//! the helper-specific semantics.
//!
//! # Trust boundary
//!
//! `host`, `args`, and `output` ultimately originate from the compiled code.
//! They are only sound to dereference if that code is itself trusted/verified;
//! this module cannot re-establish that trust, it can only pass it through. See
//! the `# Safety` sections below.

pub mod rsm;

use core::ffi::c_void;

/// Status returned for a successful helper call.
pub const HOST_OK: u32 = 0;

/// Status returned for an unknown helper index (or a null `host` pointer).
pub const HOST_UNKNOWN: u32 = 1;

/// The table the trampoline dispatches through.
///
/// The adapter embeds this (as the first field of its own invocation state) so
/// [`host_trampoline`] can recover the dispatcher from the `host` pointer.
#[repr(C)]
pub struct HostCallbackTable {
    /// Dispatches helper `index`, receiving the same `host` pointer the program
    /// passed in, so the dispatcher can recover the adapter's invocation state.
    ///
    /// # Safety
    ///
    /// The dispatcher must dereference `host`, `args`, and `output` only in
    /// accordance with the contracts the adapter established when it placed the
    /// program and handed `host` to it.
    pub dispatch: unsafe extern "C" fn(
        host: *mut c_void,
        index: u32,
        args: *const c_void,
        output: *mut c_void,
    ) -> u32,
}

/// The fixed trampoline native code calls back into.
///
/// # Safety
///
/// `host` must point to a live, exclusively borrowed [`HostCallbackTable`];
/// `args` and `output` must satisfy the table's `dispatch` contract.
pub unsafe extern "C" fn host_trampoline(
    host: *mut c_void,
    index: u32,
    args: *const c_void,
    output: *mut c_void,
) -> u32 {
    if host.is_null() {
        return HOST_UNKNOWN;
    }
    // SAFETY: `host` is valid and points to a `HostCallbackTable` per the
    // `# Safety` contract above; this dereference is the callback-out trust
    // boundary.
    let table = unsafe { &*(host as *const HostCallbackTable) };
    // SAFETY: Forwarded from the `# Safety` contract above.
    unsafe { (table.dispatch)(host, index, args, output) }
}
