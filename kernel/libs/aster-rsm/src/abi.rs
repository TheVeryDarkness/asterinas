// SPDX-License-Identifier: MPL-2.0

//! The fixed ABI shared between RSM-compiled machine code and the kernel.
//!
//! Generated code bakes in `offset_of!` values for these structures, so the
//! field layout here must match the userspace `rsm-jit` definitions exactly.
//! The compile-time assertions at the bottom pin the critical offsets.

use core::ffi::c_void;

/// An exactly typed scalar argument or return slot, always eight bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbiScalar {
    pub bits: u64,
}

/// Records the kind and origin of a failed instruction.
#[repr(C)]
pub struct TrapRecord {
    pub kind: u32,
    pub function: u32,
    pub location: u32,
    pub detail: u32,
}

/// The invocation context passed as the first argument of every entry thunk.
///
/// The layout must match `rsm-jit`'s non-test `ExecContext` byte for byte: the
/// `trap` record is written at offset 0 and the `host` pointer read at offset 32.
#[repr(C)]
pub struct ExecContext {
    pub trap: TrapRecord,
    pub reserved: [u64; 2],
    pub host: usize,
}

/// The calling convention of a compiled entry thunk.
pub type NativeEntry =
    unsafe extern "C" fn(*mut ExecContext, *const AbiScalar, *mut AbiScalar) -> u32;

/// The calling convention of the host helper trampoline.
pub type HostTrampoline =
    unsafe extern "C" fn(*mut c_void, u32, *const AbiScalar, *mut AbiScalar) -> u32;

const _: () = {
    assert!(core::mem::offset_of!(ExecContext, trap) == 0);
    assert!(core::mem::offset_of!(ExecContext, host) == 32);
    assert!(size_of::<ExecContext>() == 40);
};
