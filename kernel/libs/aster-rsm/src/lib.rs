// SPDX-License-Identifier: MPL-2.0

//! RSM kernel runtime adapter.
//!
//! Decodes the relocatable machine-code artifact produced by the RSM toolchain
//! and applies its relocations, so the upper kernel can place verified code
//! into an OSTD [`NativeProgram`] and call it at the system-call entry.
//!
//! # Trust boundary
//!
//! OSTD implements the native entry and the Rssembly helper trampoline in
//! `ostd::mm::callback::rsm`. OSTD decodes the native ABI slots and validates
//! buffer ranges. The adapter invokes the entry under the existing requirement
//! that a trusted producer verified the artifact offline.

#![no_std]

extern crate alloc;

pub mod abi;
pub mod artifact;
pub mod hooks;
#[cfg(feature = "ostd")]
pub mod log;
#[cfg(feature = "ostd")]
pub mod program;
pub mod reloc;
#[cfg(any(feature = "ostd", test))]
mod state;
#[cfg(feature = "ostd")]
pub mod trampoline;

pub use abi::{AbiScalar, ExecContext, NativeEntry, TrapRecord};
pub use artifact::{
    Artifact, DecodeError, Entry, INTERFACE_VERSION, RelocKind, RelocTarget, Relocation,
};
#[cfg(feature = "ostd")]
pub use program::{RsmError, RsmProgram};
pub use reloc::{RelocateError, apply_relocations};
#[cfg(any(feature = "ostd", test))]
pub use state::StateError;
#[cfg(feature = "ostd")]
pub use trampoline::HostInvocation;
