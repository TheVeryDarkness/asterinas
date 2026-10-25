// SPDX-License-Identifier: MPL-2.0

//! Writable, then read-execute, supervisor memory for staging native code.

use core::ffi::c_void;

use align_ext::AlignExt;

use crate::{
    Error,
    cpu::{AtomicCpuSet, CpuSet},
    mm::{
        CachePolicy, FrameAllocOptions, HasSize, PAGE_SIZE, PageFlags, PageProperty,
        PrivilegedPageFlags, Vaddr,
        kspace::kvirt_area::KVirtArea,
        tlb::{TlbFlushOp, TlbFlusher},
    },
    task::disable_preempt,
};

/// Writable supervisor memory being staged into executable code.
///
/// The pages start read-write so a loader can copy machine code and patch
/// relocations. [`NativeProgram::finalize`] flips them to read-execute and
/// consumes the handle, so executable code can never be written afterwards.
pub struct NativeProgram {
    area: KVirtArea,
}

impl NativeProgram {
    /// Allocates `size_bytes` of zeroed, writable, supervisor kernel memory.
    ///
    /// The size is rounded up to a page boundary.
    pub fn new(size_bytes: usize) -> Result<Self, Error> {
        let size = size_bytes.align_up(PAGE_SIZE);
        if size == 0 {
            return Err(Error::InvalidArgs);
        }
        let segment = FrameAllocOptions::new().alloc_segment(size / PAGE_SIZE)?;
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::GLOBAL,
        };
        let area = KVirtArea::map_frames(size, 0, segment.into_iter(), prop);
        Ok(Self { area })
    }

    /// Returns the base virtual address of the staged code.
    pub fn base(&self) -> Vaddr {
        self.area.start()
    }

    /// Returns the writable code buffer, valid until [`Self::finalize`].
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: The area is read-write supervisor memory that this handle
        // owns exclusively until it is finalized.
        unsafe { core::slice::from_raw_parts_mut(self.base() as *mut u8, self.area.size()) }
    }

    /// Marks the code read-execute, flushes the TLB, and returns the immutable
    /// program.
    pub fn finalize(mut self) -> Result<ExecutableProgram, Error> {
        // SAFETY: The TLB is flushed on all CPUs immediately below, before the
        // code is exposed for execution.
        unsafe { self.area.protect(PageFlags::RX) };

        let target_cpus = AtomicCpuSet::new(CpuSet::new_full());
        let mut flusher = TlbFlusher::new(&target_cpus, disable_preempt());
        flusher.issue_tlb_flush(TlbFlushOp::for_range(self.area.range()));
        flusher.dispatch_tlb_flush();
        flusher.sync_tlb_flush();

        Ok(ExecutableProgram { area: self.area })
    }
}

/// Read-execute supervisor code.
pub struct ExecutableProgram {
    area: KVirtArea,
}

impl ExecutableProgram {
    /// Returns the base virtual address of the code.
    pub fn base(&self) -> Vaddr {
        self.area.start()
    }

    /// Returns the address of the entry thunk at `offset` bytes into the code.
    ///
    /// Returns [`None`] if `offset` is not within the code.
    pub fn entry(&self, offset: usize) -> Option<Vaddr> {
        (offset < self.area.size()).then(|| self.base() + offset)
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
        // SAFETY: The caller upholds the entry-address contract documented
        // above.
        let entry_fn: unsafe extern "C" fn(*mut c_void, *const c_void, *mut c_void) -> u32 =
            unsafe { core::mem::transmute(entry) };
        // SAFETY: The caller upholds the pointer contracts documented above.
        unsafe { entry_fn(arg0, arg1, arg2) }
    }
}

#[cfg(ktest)]
mod tests {
    use super::{ExecutableProgram, NativeProgram};
    use crate::prelude::*;

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
