// SPDX-License-Identifier: MPL-2.0

//! Checked callback arguments for the fixed Rssembly native helper ABI.

use core::{cell::Cell, ffi::c_void, slice};

use super::{HOST_OK, HOST_UNKNOWN, HostCallbackTable};
use crate::mm::KERNEL_VADDR_RANGE;

/// The Rssembly helper ABI for the admitted native image.
#[derive(Clone, Copy)]
pub enum HelperAbi {
    /// Counter, time, and byte logging.
    V1,
    /// Adds text/byte logging, named maps, and native allocations.
    V2,
}

/// Typed inputs borrowed for one native call.
pub enum HelperCall<'a> {
    /// Increment the program counter.
    Counter,
    /// Read monotonic kernel time.
    TimeNs,
    /// Append a bounded message.
    Log(&'a [u8]),
    /// Open or create a named word array.
    MapGetOrCreate {
        /// Program-local array name.
        key: u64,
        /// Required array length in words.
        words: u64,
    },
    /// Read an array word.
    MapLoad {
        /// Handle returned when the array was opened.
        handle: u64,
        /// Zero-based word index.
        index: u64,
    },
    /// Store an array word.
    MapStore {
        /// Handle returned when the array was opened.
        handle: u64,
        /// Zero-based word index.
        index: u64,
        /// Word to store.
        value: u64,
    },
    /// Add to an array word and return its previous value.
    MapFetchAdd {
        /// Handle returned when the array was opened.
        handle: u64,
        /// Zero-based word index.
        index: u64,
        /// Unsigned wrapping increment.
        delta: u64,
    },
    /// Remove a named array.
    MapFree {
        /// Array to release.
        handle: u64,
    },
    /// Reserve storage for this invocation.
    HeapAlloc {
        /// Requested allocation size in bytes.
        size: u64,
        /// Required alignment in bytes.
        alignment: u64,
    },
    /// Release an exact allocation from this invocation.
    HeapDealloc {
        /// Original base address returned by allocation.
        address: u64,
        /// Original allocation size in bytes.
        size: u64,
        /// Original alignment in bytes.
        alignment: u64,
    },
    /// Write a byte within an owned live allocation.
    HeapWriteByte {
        /// Original base address returned by allocation.
        address: u64,
        /// Zero-based byte index.
        offset: u64,
        /// Value to write.
        value: u8,
    },
    /// Read a byte within an owned live allocation.
    HeapReadByte {
        /// Original base address returned by allocation.
        address: u64,
        /// Zero-based byte index.
        offset: u64,
    },
    /// Replace a named array's words with a complete native allocation.
    MapSaveBytes {
        /// Persistent array handle.
        handle: u64,
        /// Original base address of the source allocation.
        address: u64,
    },
    /// Restore a named array into a complete native allocation.
    MapRestoreBytes {
        /// Persistent array handle.
        handle: u64,
        /// Original base address of the destination allocation.
        address: u64,
    },
}

/// A native program's host helper implementation.
pub trait HostHelpers {
    /// Copies a prefix only if the whole range is in data owned by this invocation.
    fn copy_log_bytes(&self, address: usize, length: usize, prefix: &mut [u8]) -> bool;

    /// Returns the result word on success. `None` stops the native call.
    fn invoke(&self, call: HelperCall<'_>) -> Option<u64>;
}

/// Stack boundaries saved at native entry and before entering a helper.
#[derive(Default)]
pub struct NativeStackBounds {
    bottom: Cell<usize>,
    top: Cell<usize>,
}

impl NativeStackBounds {
    pub(crate) fn set_top(&self, address: usize) {
        self.top.set(address);
    }

    fn contains(&self, start: usize, end: usize) -> bool {
        self.bottom.get() != 0 && self.bottom.get() <= start && end <= self.top.get()
    }
}

#[repr(C)]
struct Header {
    table: HostCallbackTable,
    stack: NativeStackBounds,
}

/// Enters the native helper dispatcher with the current native stack boundary.
///
/// # Safety
///
/// `host` must be an active [`NativeCallbacks`] cookie and the other
/// arguments must match the fixed ABI of the linked helper.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub unsafe extern "C" fn trampoline(
    _host: *mut c_void,
    _index: u32,
    _args: *const c_void,
    _output: *mut c_void,
) -> u32 {
    // Capture the caller's SP before a host frame exists. The return address
    // pushed by call is below the caller's frame.
    core::arch::naked_asm!(
        "test rdi, rdi",
        "jz 2f",
        "lea rax, [rsp + 8]",
        "mov [rdi + {bottom}], rax",
        "jmp qword ptr [rdi]",
        "2: mov eax, {unknown}",
        "ret",
        bottom = const (core::mem::offset_of!(Header, stack) + core::mem::offset_of!(NativeStackBounds, bottom)),
        unknown = const HOST_UNKNOWN,
    )
}

#[cfg(not(target_arch = "x86_64"))]
pub use super::host_trampoline as trampoline;

/// An Rssembly callback table and its invocation state.
#[repr(C)]
pub struct NativeCallbacks<T> {
    header: Header,
    state: T,
    abi: HelperAbi,
    max_log_bytes: usize,
}

impl<T: HostHelpers> NativeCallbacks<T> {
    /// Builds the callback table for one native invocation.
    pub fn new(abi: HelperAbi, max_log_bytes: usize, state: T) -> Self {
        Self {
            header: Header {
                table: HostCallbackTable {
                    dispatch: Self::dispatch,
                },
                stack: NativeStackBounds::default(),
            },
            state,
            abi,
            max_log_bytes,
        }
    }

    /// Returns the opaque host cookie while this table is borrowed by a native call.
    pub fn address(&self) -> usize {
        core::ptr::from_ref(self).expose_provenance()
    }

    /// Returns the stack boundary storage for this invocation's native call.
    pub fn stack_bounds(&self) -> &NativeStackBounds {
        &self.header.stack
    }

    // SAFETY: The trusted caller provides this table's own cookie, the ABI
    // slots specified by its linked helper signature, and a writable output.
    unsafe extern "C" fn dispatch(
        host: *mut c_void,
        index: u32,
        args: *const c_void,
        output: *mut c_void,
    ) -> u32 {
        if output.is_null() {
            return HOST_UNKNOWN;
        }
        // SAFETY: The trampoline recovered this dispatcher from this table.
        let this = unsafe { &*host.cast::<Self>() };
        if matches!(this.abi, HelperAbi::V1) && index > 2 {
            return HOST_UNKNOWN;
        }
        // rsm-emit's fixed registration order defines these native signatures.
        let count = match index {
            0 | 1 => 0,
            8 => 1,
            2 | 3 | 4 | 5 | 9 | 12 | 13 | 14 => 2,
            6 | 7 | 10 | 11 => 3,
            _ => return HOST_UNKNOWN,
        };
        let words = if count == 0 {
            &[]
        } else {
            if args.is_null() {
                return HOST_UNKNOWN;
            }
            // SAFETY: The verified native producer supplied the readable,
            // initialized slots for the registered ABI and helper index.
            unsafe { slice::from_raw_parts(args.cast::<u64>(), count) }
        };
        let mut log_copy;
        let call = match (index, words) {
            (0, []) => HelperCall::Counter,
            (1, []) => HelperCall::TimeNs,
            (2 | 3, &[address, length]) => {
                let requested = length as usize;
                let len = requested.min(this.max_log_bytes);
                let address = address as usize;
                if len == 0 {
                    HelperCall::Log(&[])
                } else {
                    let Some(end) = address.checked_add(requested) else {
                        return HOST_UNKNOWN;
                    };
                    match this.abi {
                        HelperAbi::V1 => {
                            if len > isize::MAX as usize
                                || !KERNEL_VADDR_RANGE.contains(&address)
                                || !KERNEL_VADDR_RANGE.contains(&(end - 1))
                            {
                                return HOST_UNKNOWN;
                            }
                            // SAFETY: Legacy byte logging trusts the external
                            // verifier for readable backing and initialization.
                            HelperCall::Log(unsafe {
                                slice::from_raw_parts(address as *const u8, len)
                            })
                        }
                        HelperAbi::V2 if this.header.stack.contains(address, end) => {
                            // SAFETY: The range lies in the active native frames
                            // between assembly boundaries. The trusted producer
                            // guarantees the bytes form one initialized value.
                            HelperCall::Log(unsafe {
                                slice::from_raw_parts(address as *const u8, len)
                            })
                        }
                        HelperAbi::V2 => {
                            log_copy = [0; MAX_LOG_BYTES];
                            let Some(prefix) = log_copy.get_mut(..len) else {
                                return HOST_UNKNOWN;
                            };
                            if !this.state.copy_log_bytes(address, requested, prefix) {
                                return HOST_UNKNOWN;
                            }
                            HelperCall::Log(prefix)
                        }
                    }
                }
            }
            (4, &[key, words]) => HelperCall::MapGetOrCreate { key, words },
            (5, &[handle, index]) => HelperCall::MapLoad { handle, index },
            (6, &[handle, index, value]) => HelperCall::MapStore {
                handle,
                index,
                value,
            },
            (7, &[handle, index, delta]) => HelperCall::MapFetchAdd {
                handle,
                index,
                delta,
            },
            (8, &[handle]) => HelperCall::MapFree { handle },
            (9, &[size, alignment]) => HelperCall::HeapAlloc { size, alignment },
            (10, &[address, size, alignment]) => HelperCall::HeapDealloc {
                address,
                size,
                alignment,
            },
            (11, &[address, offset, value]) => HelperCall::HeapWriteByte {
                address,
                offset,
                value: value as u8,
            },
            (12, &[address, offset]) => HelperCall::HeapReadByte { address, offset },
            (13, &[handle, address]) => HelperCall::MapSaveBytes { handle, address },
            (14, &[handle, address]) => HelperCall::MapRestoreBytes { handle, address },
            _ => return HOST_UNKNOWN,
        };
        let Some(value) = this.state.invoke(call) else {
            return HOST_UNKNOWN;
        };
        // SAFETY: The caller supplies an aligned result slot. Input borrows
        // have ended, including when the ABI overlaps the argument slots.
        unsafe { output.cast::<u64>().write(value) };
        HOST_OK
    }
}

/// Maximum byte prefix copied by an Rssembly logging helper.
pub const MAX_LOG_BYTES: usize = 1024;
