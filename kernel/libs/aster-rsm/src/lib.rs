// SPDX-License-Identifier: MPL-2.0

//! RSM kernel runtime adapter.
//!
//! Decodes the relocatable machine-code artifact produced by the RSM toolchain
//! and applies its relocations, so the upper kernel can place verified code
//! into an OSTD [`NativeProgram`] and call it at the system-call entry.

#![no_std]

extern crate alloc;

pub mod abi;
pub mod artifact;
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
pub use trampoline::{HostInvocation, host_trampoline};
