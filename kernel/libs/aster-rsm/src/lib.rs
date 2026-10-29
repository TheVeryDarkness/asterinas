// SPDX-License-Identifier: MPL-2.0

//! RSM kernel runtime adapter.
//!
//! Decodes the relocatable machine-code artifact produced by the RSM toolchain
//! and applies its relocations, so the upper kernel can place verified code
//! into an OSTD [`NativeProgram`] and call it at the system-call entry.
//!
//! # Trust boundary
//!
//! The generic `unsafe` plumbing lives in OSTD: the call-in primitive is
//! `ostd::mm::ExecutableProgram::call`, and the callback-out trampoline is
//! `ostd::mm::callback::host_trampoline`. This crate retains only the
//! RSM-specific dereferences of the pointers a verified program passes back
//! (see `program::RsmProgram::observe` and the `trampoline` module), which are
//! sound only because the loaded artifact was verified offline. Enabling
//! `#![deny(unsafe_code)]` here is therefore deferred until the RSM verifier
//! runs in-kernel at load time.

#![no_std]

extern crate alloc;

pub mod abi;
pub mod artifact;
#[cfg(feature = "ostd")]
pub mod log;
#[cfg(feature = "ostd")]
pub mod program;
pub mod reloc;
#[cfg(feature = "ostd")]
pub mod trampoline;

pub use abi::{AbiScalar, ExecContext, NativeEntry, TrapRecord};
pub use artifact::{
    Artifact, DecodeError, Entry, INTERFACE_VERSION, RelocKind, RelocTarget, Relocation,
};
#[cfg(feature = "ostd")]
pub use program::{RsmError, RsmProgram};
pub use reloc::{RelocateError, apply_relocations};
#[cfg(feature = "ostd")]
pub use trampoline::HostInvocation;
