// SPDX-License-Identifier: MPL-2.0

//! Supervisor memory for staging native code and read-only data.

use core::{ffi::c_void, ops::Range};

use crate::{
    Error,
    cpu::{AtomicCpuSet, CpuSet},
    mm::{
        CachePolicy, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, PrivilegedPageFlags,
        Vaddr,
        kspace::kvirt_area::KVirtArea,
        tlb::{TlbFlushOp, TlbFlusher},
    },
    task::disable_preempt,
};

/// Writable supervisor memory being staged into executable code.
///
/// The pages start read-write so a loader can copy machine code and patch
/// relocations. [`NativeProgram::finalize`] consumes the writable handle and
/// makes the code executable and any trailing data read-only.
pub struct NativeProgram {
    area: KVirtArea,
    image_offset: usize,
    image_len: usize,
    code_len: usize,
    rodata_start: usize,
}

impl NativeProgram {
    /// Allocates `size_bytes` of zeroed, writable, supervisor kernel memory.
    ///
    /// The size is rounded up to a page boundary.
    pub fn new(size_bytes: usize) -> Result<Self, Error> {
        let size = size_bytes
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Error::Overflow)?;
        Self::with_rodata(size, size..size, 1)
    }

    /// Allocates a writable image with code at offset zero and trailing read-only data.
    ///
    /// `rodata` specifies byte offsets from the image base. The image alignment
    /// must be a power of two up to [`PAGE_SIZE`]. Nonempty read-only data must
    /// start at an offset satisfying this alignment.
    pub fn with_rodata(
        code_len: usize,
        rodata: Range<usize>,
        alignment: usize,
    ) -> Result<Self, Error> {
        if code_len == 0
            || rodata.start < code_len
            || rodata.end < rodata.start
            || !alignment.is_power_of_two()
            || alignment > PAGE_SIZE
        {
            return Err(Error::InvalidArgs);
        }
        let image_offset = if rodata.is_empty() {
            if rodata.start != code_len {
                return Err(Error::InvalidArgs);
            }
            0
        } else {
            if !rodata.start.is_multiple_of(alignment) {
                return Err(Error::InvalidArgs);
            }
            // Put data on its own page without changing any image-relative offset.
            rodata.start.wrapping_neg() % PAGE_SIZE
        };
        let size = image_offset
            .checked_add(rodata.end)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(Error::Overflow)?;
        let segment = FrameAllocOptions::new().alloc_segment(size / PAGE_SIZE)?;
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            // Large or coalesced shootdowns flush only non-global mappings.
            priv_flags: PrivilegedPageFlags::empty(),
        };
        let area = KVirtArea::map_frames(size, 0, segment.into_iter(), prop);
        // KVirtArea leaves invalidation of a previous mapping to the next user
        // of its address. Complete it before granting access to these frames.
        flush_translations(&area);
        Ok(Self {
            area,
            image_offset,
            image_len: rodata.end,
            code_len,
            rodata_start: rodata.start,
        })
    }

    /// Returns the base virtual address of the staged code.
    pub fn base(&self) -> Vaddr {
        self.area.start() + self.image_offset
    }

    /// Returns the writable image buffer, valid until [`Self::finalize`].
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: The area is read-write supervisor memory that this handle
        // owns exclusively until it is finalized.
        unsafe { core::slice::from_raw_parts_mut(self.base() as *mut u8, self.image_len) }
    }

    /// Marks the code read-execute and trailing data read-only, then flushes
    /// cached translations before publishing the immutable program.
    pub fn finalize(mut self) -> Result<ExecutableProgram, Error> {
        let code_end = (self.base() + self.code_len).next_multiple_of(PAGE_SIZE);
        let area = self.area.range();
        // SAFETY: Both ranges belong to this area and we synchronously flush
        // every CPU before exposing the finalized image.
        unsafe {
            self.area.protect(area.start..code_end, PageFlags::RX);
            if code_end < area.end {
                self.area.protect(code_end..area.end, PageFlags::R);
            }
        }
        flush_translations(&self.area);
        Ok(ExecutableProgram { image: self })
    }
}

fn flush_translations(area: &KVirtArea) {
    let target_cpus = AtomicCpuSet::new(CpuSet::new_full());
    let mut flusher = TlbFlusher::new(&target_cpus, disable_preempt());
    flusher.issue_tlb_flush(TlbFlushOp::for_range(area.range()));
    flusher.dispatch_tlb_flush();
    flusher.sync_tlb_flush();
}

/// Immutable supervisor code and its read-only data.
pub struct ExecutableProgram {
    image: NativeProgram,
}

impl ExecutableProgram {
    /// Returns the base virtual address of the code.
    pub fn base(&self) -> Vaddr {
        self.image.base()
    }

    /// Returns the address of the entry thunk at `offset` bytes into the code.
    ///
    /// Returns [`None`] if `offset` is not within the code.
    pub fn entry(&self, offset: usize) -> Option<Vaddr> {
        (offset < self.image.code_len).then(|| self.base() + offset)
    }

    /// Borrows initialized bytes in this program's declared read-only data.
    pub fn rodata_bytes(&self, address: Vaddr, len: usize) -> Option<&[u8]> {
        let start = address.checked_sub(self.base())?;
        if start < self.image.rodata_start || start.checked_add(len)? > self.image.image_len {
            return None;
        }
        // SAFETY: The finalized mapping owns these initialized immutable
        // data bytes for the returned borrow. No writable handle survives.
        Some(unsafe { core::slice::from_raw_parts(address as *const u8, len) })
    }

    /// Calls an entry thunk with the fixed three-pointer native ABI.
    ///
    /// # Safety
    ///
    /// `entry` must address code produced by a trusted, verified toolchain that
    /// implements `extern "C" fn(*mut c_void, *const c_void, *mut c_void) -> u32`.
    /// `arg0` and `arg2` must point to valid writable storage, and `arg1` to
    /// valid readable storage, as required by that code; the caller must also
    /// ensure the code's stack bound fits the current kernel stack.
    pub unsafe fn call(
        &self,
        entry: Vaddr,
        arg0: *mut c_void,
        arg1: *const c_void,
        arg2: *mut c_void,
    ) -> u32 {
        // SAFETY: Forward the trusted entry and argument contracts.
        unsafe { Self::call_inner(entry, arg0, arg1, arg2, None) }
    }

    /// Calls a trusted entry with a recorded boundary between the native and host frames.
    ///
    /// # Safety
    ///
    /// The contracts of [`Self::call`] apply. The entry's callback context
    /// must use these same invocation bounds.
    pub unsafe fn call_with_stack_bounds(
        &self,
        entry: Vaddr,
        arg0: *mut c_void,
        arg1: *const c_void,
        arg2: *mut c_void,
        bounds: &super::callback::rsm::NativeStackBounds,
    ) -> u32 {
        // SAFETY: Forward the trusted entry and argument contracts.
        unsafe { Self::call_inner(entry, arg0, arg1, arg2, Some(bounds)) }
    }

    unsafe fn call_inner(
        entry: Vaddr,
        arg0: *mut c_void,
        arg1: *const c_void,
        arg2: *mut c_void,
        bounds: Option<&super::callback::rsm::NativeStackBounds>,
    ) -> u32 {
        // SAFETY: The caller upholds the entry-address contract documented
        // above.
        let entry_fn: unsafe extern "C" fn(*mut c_void, *const c_void, *mut c_void) -> u32 =
            unsafe { core::mem::transmute(entry) };
        #[cfg(target_arch = "x86_64")]
        if let Some(bounds) = bounds {
            let stack_pointer: usize;
            // SAFETY: Read the current stack pointer without touching memory.
            unsafe {
                core::arch::asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags))
            };
            bounds.set_top(stack_pointer);
        }
        // SAFETY: The caller upholds the documented pointer contracts.
        let status = unsafe { entry_fn(arg0, arg1, arg2) };
        if let Some(bounds) = bounds {
            bounds.set_top(0);
        }
        status
    }
}

#[cfg(ktest)]
mod tests {
    use super::{ExecutableProgram, NativeProgram};
    use crate::{
        mm::{PAGE_SIZE, PageFlags, PrivilegedPageFlags, kspace::MappedItemRef},
        prelude::*,
        task::disable_preempt,
    };

    #[ktest]
    fn finalizes_packed_data_on_a_nonexecutable_page() {
        let code_len = PAGE_SIZE + 5;
        let data_offset = code_len.next_multiple_of(16);
        let message = b"observer";
        let mut image =
            NativeProgram::with_rodata(code_len, data_offset..data_offset + message.len(), 16)
                .unwrap();
        assert!(image.base().is_multiple_of(16));
        assert!((image.base() + data_offset).is_multiple_of(PAGE_SIZE));
        image.as_mut_slice()[data_offset..].copy_from_slice(message);

        let executable = image.finalize().unwrap();
        assert_eq!(
            executable.rodata_bytes(executable.base() + data_offset, message.len()),
            Some(&message[..])
        );
        assert!(executable.rodata_bytes(executable.base(), 1).is_none());
        assert!(
            executable
                .rodata_bytes(executable.base() + data_offset, message.len() + 1)
                .is_none()
        );
        assert!(executable.entry(code_len - 1).is_some());
        assert!(executable.entry(code_len).is_none());
        assert!(executable.entry(data_offset).is_none());
        let guard = disable_preempt();
        for (offset, expected) in [(0, PageFlags::RX), (data_offset, PageFlags::R)] {
            let address = executable.base() + offset;
            let Some(MappedItemRef::Tracked(_, prop)) =
                executable.image.area.query(&guard, address)
            else {
                panic!("expected a tracked native image page");
            };
            assert_eq!(prop.flags & PageFlags::RWX, expected);
            assert!(!prop.priv_flags.contains(PrivilegedPageFlags::GLOBAL));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[ktest]
    fn native_logging_accepts_its_frame_and_excludes_the_host_frame() {
        use core::ffi::c_void;

        use crate::mm::callback::{
            HOST_OK, HOST_UNKNOWN,
            rsm::{HelperAbi, HelperCall, HostHelpers, NativeCallbacks, trampoline},
        };

        struct Logger;
        impl HostHelpers for Logger {
            fn copy_log_bytes(&self, _: usize, _: usize, _: &mut [u8]) -> bool {
                false
            }
            fn invoke(&self, call: HelperCall<'_>) -> Option<u64> {
                matches!(call, HelperCall::Log(b"test")).then_some(1)
            }
        }
        struct Context {
            cookie: usize,
            host_bytes: usize,
        }

        #[inline(never)]
        unsafe extern "C" fn native(context: *mut c_void, _: *const c_void, _: *mut c_void) -> u32 {
            // SAFETY: The test supplies a live context for this synchronous invocation.
            let context = unsafe { &*context.cast::<Context>() };
            let bytes = core::hint::black_box(*b"test");
            for (address, expected) in [
                (bytes.as_ptr().expose_provenance(), HOST_OK),
                (context.host_bytes, HOST_UNKNOWN),
            ] {
                let args = [address as u64, bytes.len() as u64];
                let mut result = 0u64;
                // SAFETY: The cookie, two input slots and output are live. Both
                // candidate byte ranges are initialized storage kept alive by the test.
                let status = unsafe {
                    trampoline(
                        context.cookie as *mut c_void,
                        3,
                        args.as_ptr().cast(),
                        (&raw mut result).cast(),
                    )
                };
                if status != expected {
                    return 1;
                }
            }
            0
        }

        let callbacks = NativeCallbacks::new(HelperAbi::V2, 16, Logger);
        let host_bytes = core::hint::black_box(*b"test");
        let mut context = Context {
            cookie: callbacks.address(),
            host_bytes: host_bytes.as_ptr().expose_provenance(),
        };
        // SAFETY: The trusted Rust test entry implements the exact native ABI.
        // It reads only context and its own frame, and ignores the null arguments.
        let status = unsafe {
            ExecutableProgram::call_inner(
                native as *const () as usize,
                (&raw mut context).cast(),
                core::ptr::null(),
                core::ptr::null_mut(),
                Some(callbacks.stack_bounds()),
            )
        };
        assert_eq!(status, 0);
    }

    /// Stages a `mov eax, 42; ret` thunk, finalizes it, and calls it.
    #[ktest]
    fn stages_and_calls_executable_memory() {
        let mut program = NativeProgram::new(16).expect("allocate program");
        // `mov eax, 42` (0xB8 2A 00 00 00) followed by `ret` (0xC3).
        let code = [
            0xb8, 42, 0, 0, 0,    // mov eax, 42
            0xc3, // ret
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // padding
        ];
        program.as_mut_slice()[..code.len()].copy_from_slice(&code);

        let executable: ExecutableProgram = program.finalize().expect("finalize program");
        let entry = executable.entry(0).expect("entry at offset 0");
        // SAFETY: `entry` addresses the verified `mov eax, 42; ret` thunk, and
        // the three pointer arguments are unused by that code.
        let result = unsafe {
            executable.call(
                entry,
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 42);
    }
}
