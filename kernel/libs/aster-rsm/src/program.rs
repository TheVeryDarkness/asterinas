// SPDX-License-Identifier: MPL-2.0

//! Loads and invokes a compiled RSM program.

use core::{ffi::c_void, sync::atomic::Ordering};

use ostd::mm::{ExecutableProgram, NativeProgram, Vaddr, host_trampoline};

use crate::{
    abi::{AbiScalar, ExecContext, TrapRecord},
    artifact::{Artifact, DecodeError},
    reloc::{RelocateError, apply_relocations},
    trampoline::HostInvocation,
};

/// The conventional name of the syscall-observer entry.
const OBSERVER_ENTRY: &str = "main";

/// Maximum native stack an entry may consume during one invocation.
///
/// This must remain well below the kernel task stack (64 pages by default), so
/// the syscall path and interrupt frames keep headroom below the plugin.
const MAX_ENTRY_STACK_BYTES: usize = 128 * 1024;

/// A loaded, relocated RSM program with its fixed counter.
pub struct RsmProgram {
    executable: ExecutableProgram,
    entry: Vaddr,
    counter: core::sync::atomic::AtomicU64,
}

impl RsmProgram {
    /// Decodes, places and finalizes a compiled program from artifact bytes.
    pub fn load(bytes: &[u8]) -> Result<Self, RsmError> {
        let artifact = Artifact::from_bytes(bytes)?;
        let entry = artifact
            .entry(OBSERVER_ENTRY)
            .ok_or(RsmError::MissingEntry)?;
        let code_offset = entry.code_offset;
        if entry.native_peak_bytes > MAX_ENTRY_STACK_BYTES {
            return Err(RsmError::StackBound);
        }

        let mut program = NativeProgram::new(artifact.code.len())?;
        let base = program.base();
        let slice = program.as_mut_slice();
        slice[..artifact.code.len()].copy_from_slice(&artifact.code);
        apply_relocations(
            &artifact,
            slice,
            base,
            host_trampoline as *const () as usize,
        )?;

        let executable = program.finalize()?;
        let entry = executable
            .entry(code_offset as usize)
            .ok_or(RsmError::MissingEntry)?;

        Ok(Self {
            executable,
            entry,
            counter: core::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Returns the current counter value.
    pub fn counter(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    /// Invokes the observer entry with the given system-call event.
    ///
    /// The event is packed into seven [`AbiScalar`] slots: the syscall number
    /// followed by its six arguments. Returns the entry's native status (0 for
    /// success, 1 for a trap recorded in the context).
    pub fn observe(&self, nr: u64, args: &[u64; 6]) -> u32 {
        let mut event = [AbiScalar { bits: 0 }; 7];
        event[0].bits = nr;
        for (slot, arg) in event[1..].iter_mut().zip(args) {
            slot.bits = *arg;
        }

        let invocation = HostInvocation::new(&self.counter);
        let mut context = ExecContext {
            trap: TrapRecord {
                kind: 0,
                function: 0,
                location: 0,
                detail: 0,
            },
            reserved: [0; 2],
            host: &invocation as *const HostInvocation as usize,
        };
        let mut output = AbiScalar { bits: 0 };

        // SAFETY: `entry` addresses verified code implementing the fixed ABI;
        // the context, event and output are live, disjoint storage for the call.
        unsafe {
            self.executable.call(
                self.entry,
                (&mut context as *mut ExecContext).cast::<c_void>(),
                event.as_ptr().cast::<c_void>(),
                (&mut output as *mut AbiScalar).cast::<c_void>(),
            )
        }
    }
}

/// Reports why loading a program failed.
#[derive(Debug)]
pub enum RsmError {
    Decode(DecodeError),
    MissingEntry,
    StackBound,
    Relocate(RelocateError),
    Ostd(ostd::Error),
}

impl From<DecodeError> for RsmError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<RelocateError> for RsmError {
    fn from(error: RelocateError) -> Self {
        Self::Relocate(error)
    }
}

impl From<ostd::Error> for RsmError {
    fn from(error: ostd::Error) -> Self {
        Self::Ostd(error)
    }
}
