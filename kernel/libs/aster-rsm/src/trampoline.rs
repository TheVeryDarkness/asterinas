// SPDX-License-Identifier: MPL-2.0

//! Helper dispatch and invocation-local context for compiled RSM programs.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use ostd::mm::{
    ExecutableProgram,
    callback::rsm::{HelperAbi, HelperCall, HostHelpers, NativeCallbacks, NativeStackBounds},
    native_heap::NativeHeapInvocation,
};

use crate::{
    log::{MAX_MESSAGE_BYTES, append},
    program::ProgramMemory,
    state::ProgramState,
};

/// The callback cookie and borrowed program resources for one native invocation.
#[repr(transparent)]
pub struct HostInvocation<'a>(NativeCallbacks<Invocation<'a>>);

impl<'a> HostInvocation<'a> {
    /// Builds the legacy helper context for the given counter.
    pub fn new(counter: &'a AtomicU64) -> Self {
        Self::for_program(counter, None, None)
    }

    pub(crate) fn for_program(
        counter: &'a AtomicU64,
        memory: Option<&'a ProgramMemory>,
        executable: Option<&'a ExecutableProgram>,
    ) -> Self {
        let abi = if memory.is_some() {
            HelperAbi::V2
        } else {
            HelperAbi::V1
        };
        Self(NativeCallbacks::new(
            abi,
            MAX_MESSAGE_BYTES,
            Invocation {
                counter,
                executable,
                maps: memory.map(|memory| &memory.maps),
                scratch: memory.map(|memory| memory.native_heap.invocation()),
            },
        ))
    }

    pub(crate) fn address(&self) -> usize {
        self.0.address()
    }

    pub(crate) fn stack_bounds(&self) -> &NativeStackBounds {
        self.0.stack_bounds()
    }
}

struct Invocation<'a> {
    counter: &'a AtomicU64,
    executable: Option<&'a ExecutableProgram>,
    maps: Option<&'a ProgramState>,
    scratch: Option<NativeHeapInvocation<'a>>,
}

impl HostHelpers for Invocation<'_> {
    fn copy_log_bytes(&self, address: usize, length: usize, prefix: &mut [u8]) -> bool {
        if let Some(rodata) = self
            .executable
            .and_then(|image| image.rodata_bytes(address, length))
            && let Some(source) = rodata.get(..prefix.len())
        {
            prefix.copy_from_slice(source);
            return true;
        }
        self.scratch
            .as_ref()
            .is_some_and(|scratch| scratch.copy_bytes(address, length, prefix))
    }

    fn invoke(&self, call: HelperCall<'_>) -> Option<u64> {
        match call {
            HelperCall::Counter => {
                Some(self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1))
            }
            HelperCall::TimeNs => Some(monotonic_nanoseconds()),
            HelperCall::Log(bytes) => {
                if !bytes.is_empty() {
                    append(bytes);
                    append(b"\n");
                }
                Some(0)
            }
            HelperCall::MapGetOrCreate { key, words } => {
                Some(self.maps?.get_or_create(key, words).unwrap_or(0))
            }
            HelperCall::MapLoad { handle, index } => {
                Some(self.maps?.load(handle, index).unwrap_or(0))
            }
            HelperCall::MapStore {
                handle,
                index,
                value,
            } => Some(u64::from(self.maps?.store(handle, index, value))),
            HelperCall::MapFetchAdd {
                handle,
                index,
                delta,
            } => Some(self.maps?.fetch_add(handle, index, delta).unwrap_or(0)),
            HelperCall::MapFree { handle } => Some(u64::from(self.maps?.free(handle))),
            HelperCall::MapSaveBytes { handle, address } => {
                let scratch = self.scratch.as_ref()?;
                Some(u64::from(self.maps?.save_bytes(handle, |bytes| {
                    scratch.read_allocation(address as usize, bytes)
                })))
            }
            HelperCall::MapRestoreBytes { handle, address } => {
                let scratch = self.scratch.as_ref()?;
                Some(u64::from(self.maps?.restore_bytes(handle, |bytes| {
                    scratch.write_allocation(address as usize, bytes)
                })))
            }
            HelperCall::HeapAlloc { size, alignment } => {
                let allocation = self.scratch.as_ref()?.allocate(
                    usize::try_from(size).ok()?,
                    usize::try_from(alignment).ok()?,
                )?;
                Some(allocation.as_ptr().expose_provenance() as u64)
            }
            HelperCall::HeapDealloc {
                address,
                size,
                alignment,
            } => self
                .scratch
                .as_ref()?
                .deallocate(
                    usize::try_from(address).ok()?,
                    usize::try_from(size).ok()?,
                    usize::try_from(alignment).ok()?,
                )
                .then_some(0),
            HelperCall::HeapWriteByte {
                address,
                offset,
                value,
            } => Some(u64::from(self.scratch.as_ref()?.write_byte(
                address as usize,
                offset as usize,
                value,
            ))),
            HelperCall::HeapReadByte { address, offset } => {
                // 0x100 distinguishes invalid access from all valid byte values.
                Some(
                    self.scratch
                        .as_ref()?
                        .read_byte(address as usize, offset as usize)
                        .map(u64::from)
                        .unwrap_or(0x100),
                )
            }
        }
    }
}

/// Returns the monotonic time since boot in nanoseconds.
///
/// Programs use this to time their own work without leaving the extension.
/// On x86-64 the TSC is scaled by a ratio cached on first use, so a call costs
/// a multiply and a shift instead of a 128-bit division. Other architectures
/// fall back to jiffies, whose resolution is far coarser: timing code that
/// needs sub-millisecond resolution is only meaningful on x86-64.
fn monotonic_nanoseconds() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        /// `(1e9 << 32) / tsc_frequency`, computed once.
        static TSC_TO_NANOSECONDS: AtomicU64 = AtomicU64::new(0);

        let cached = TSC_TO_NANOSECONDS.load(Ordering::Relaxed);
        let scale = if cached == 0 {
            let frequency = ostd::arch::tsc_freq();
            if frequency == 0 {
                return 0;
            }
            let computed = ((1_000_000_000u128 << 32) / u128::from(frequency)) as u64;
            TSC_TO_NANOSECONDS.store(computed, Ordering::Relaxed);
            computed
        } else {
            cached
        };

        // The product keeps 32 fractional bits of the TSC-to-nanosecond ratio,
        // so the shift is the conversion. It cannot overflow for any TSC value
        // a boot reaches within decades.
        let nanoseconds = (u128::from(ostd::arch::read_tsc()) * u128::from(scale)) >> 32;
        u64::try_from(nanoseconds).unwrap_or(u64::MAX)
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        ostd::timer::Jiffies::elapsed()
            .as_u64()
            .saturating_mul(1_000_000)
    }
}
