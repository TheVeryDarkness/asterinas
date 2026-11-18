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
