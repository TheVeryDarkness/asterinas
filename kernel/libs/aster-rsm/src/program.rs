// SPDX-License-Identifier: MPL-2.0

//! Loads and invokes a compiled RSM program.

use core::{ffi::c_void, sync::atomic::Ordering};

use ostd::mm::{
    ExecutableProgram, NativeProgram, Vaddr, callback::rsm::trampoline, native_heap::NativeHeapPool,
};

use crate::{
    abi::{AbiScalar, ExecContext, TrapRecord},
    artifact::{Artifact, DecodeError},
    reloc::{RelocateError, apply_relocations},
    state::{ProgramState, StateError},
    trampoline::HostInvocation,
};

/// The conventional name of the syscall-observer entry.
const OBSERVER_ENTRY: &str = "main";

/// Maximum native stack an entry may consume during one invocation.
///
/// This must remain well below the kernel task stack (64 pages by default), so
/// the syscall path and interrupt frames keep headroom below the plugin.
const MAX_ENTRY_STACK_BYTES: usize = 128 * 1024;

/// A loaded RSM program. Attachments and in-flight callbacks hold an `Arc`
/// to this object and therefore retain its maps and reserved allocator pool.
pub struct RsmProgram {
    executable: ExecutableProgram,
    entry: Vaddr,
    memory: Option<ProgramMemory>,
    native_stack_bytes: usize,
    counter: core::sync::atomic::AtomicU64,
}

pub(crate) struct ProgramMemory {
    pub(crate) maps: ProgramState,
    pub(crate) native_heap: NativeHeapPool,
}

impl RsmProgram {
    /// Decodes, places and finalizes a compiled program from artifact bytes.
    pub fn load(bytes: &[u8]) -> Result<Self, RsmError> {
        let artifact = Artifact::from_bytes(bytes)?;
        let entry = artifact
            .entry(OBSERVER_ENTRY)
            .ok_or(RsmError::MissingEntry)?;
        let code_offset = entry.code_offset;
        let native_stack_bytes = entry.native_peak_bytes;
        if entry.native_peak_bytes > MAX_ENTRY_STACK_BYTES {
            return Err(RsmError::StackBound);
        }

        let mut program = NativeProgram::with_rodata(
            artifact.code.len(),
            artifact.data_offset..artifact.image_len(),
            artifact.alignment,
        )?;
        let base = program.base();
        let slice = program.as_mut_slice();
        artifact.write_image(slice)?;
        apply_relocations(&artifact, slice, base, trampoline as *const () as usize)?;

        let executable = program.finalize()?;
        let entry = executable
            .entry(code_offset as usize)
            .ok_or(RsmError::MissingEntry)?;

        let memory = if artifact.interface_version == 2 && artifact.requires_host {
            Some(ProgramMemory {
                maps: ProgramState::new().map_err(|_| ostd::Error::NoMemory)?,
                native_heap: NativeHeapPool::new()?,
            })
        } else {
            None
        };
        Ok(Self {
            executable,
            entry,
            memory,
            native_stack_bytes,
            counter: core::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Reads one word of a named array owned by this program.
    pub fn read_state_word(&self, key: u64, index: u64) -> Result<u64, StateError> {
        self.memory
            .as_ref()
            .ok_or(StateError::Missing)?
            .maps
            .read_named(key, index)
    }

    /// Returns the current counter value.
    pub fn counter(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    /// Returns the entry's native stack bound from the trusted artifact.
    pub fn native_stack_bytes(&self) -> usize {
        self.native_stack_bytes
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

        let invocation = HostInvocation::for_program(
            &self.counter,
            self.memory.as_ref(),
            Some(&self.executable),
        );
        let mut context = ExecContext {
            trap: TrapRecord {
                kind: 0,
                function: 0,
                location: 0,
                detail: 0,
            },
            reserved: [0; 2],
            host: invocation.address(),
        };
        let mut output = AbiScalar { bits: 0 };

        // SAFETY: `entry` addresses verified code implementing the fixed ABI;
        // the context, event and output are live, disjoint storage for the call.
        unsafe {
            self.executable.call_with_stack_bounds(
                self.entry,
                (&mut context as *mut ExecContext).cast::<c_void>(),
                event.as_ptr().cast::<c_void>(),
                (&mut output as *mut AbiScalar).cast::<c_void>(),
                invocation.stack_bounds(),
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
