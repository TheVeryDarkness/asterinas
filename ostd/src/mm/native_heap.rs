// SPDX-License-Identifier: MPL-2.0

//! Bounded scratch allocations for trusted native programs.
//!
//! A loaded program reserves the pool. Each invocation claims a private lane
//! on its first allocation and releases the lane when the invocation ends.
//! The caller of native code must ensure that pointers do not escape the
//! invocation or survive deallocation.

use alloc::vec::Vec;
use core::{
    cell::{Cell, UnsafeCell},
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::Error;

const LANES: usize = 8;
const LANE_BYTES: usize = 512;
const MAX_LIVE_BLOCKS: usize = 16;

#[repr(C, align(16))]
struct LaneBytes([u8; LANE_BYTES]);

#[derive(Clone, Copy, Default)]
struct Block {
    offset: u16,
    size: u16,
    alignment: u16,
}

#[derive(Default)]
struct Allocations {
    end: usize,
    blocks: [Block; MAX_LIVE_BLOCKS],
}

struct Lane {
    claimed: AtomicBool,
    bytes: UnsafeCell<LaneBytes>,
    allocations: UnsafeCell<Allocations>,
}

// SAFETY: A successful acquire claims the lane exclusively until its matching
// release. Only that invocation can access the bytes and allocation records.
unsafe impl Sync for Lane {}

/// Storage reserved for one native program's per-invocation allocator.
pub struct NativeHeapPool {
    lanes: Vec<Lane>,
}

impl NativeHeapPool {
    /// Reserves all native heap storage in a sleepable load context.
    pub fn new() -> Result<Self, Error> {
        let mut lanes = Vec::new();
        lanes
            .try_reserve_exact(LANES)
            .map_err(|_| Error::NoMemory)?;
        lanes.resize_with(LANES, || Lane {
            claimed: AtomicBool::new(false),
            bytes: UnsafeCell::new(LaneBytes([0; LANE_BYTES])),
            allocations: UnsafeCell::new(Allocations::default()),
        });
        Ok(Self { lanes })
    }

    /// Creates an invocation lease. A lane is taken only if the program allocates.
    pub fn invocation(&self) -> NativeHeapInvocation<'_> {
        NativeHeapInvocation {
            pool: self,
            lane: Cell::new(None),
        }
    }
}

/// Exclusive access to a program's scratch storage for one native call.
///
/// A lease is not shareable across threads. Dropping it releases every
/// outstanding allocation, including when native execution exits with a trap.
pub struct NativeHeapInvocation<'a> {
    pool: &'a NativeHeapPool,
    lane: Cell<Option<&'a Lane>>,
}

impl NativeHeapInvocation<'_> {
    /// Allocates zeroed storage aligned as requested, or reports exhaustion or
    /// an invalid layout. A freed address is retired for this invocation.
    pub fn allocate(&self, size: usize, alignment: usize) -> Option<NonNull<u8>> {
        if size == 0
            || size > LANE_BYTES
            || !alignment.is_power_of_two()
            || alignment > align_of::<LaneBytes>()
        {
            return None;
        }
        let lane = match self.lane.get() {
            Some(lane) => lane,
            None => {
                let lane = self.pool.lanes.iter().find(|lane| {
                    lane.claimed
                        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                })?;
                self.lane.set(Some(lane));
                lane
            }
        };
        // SAFETY: This non-shared invocation holds the only claim on the lane.
        // The native program only receives pointers into bytes, never metadata.
        let allocations = unsafe { &mut *lane.allocations.get() };
        let offset = allocations.end.next_multiple_of(alignment);
        let end = offset + size;
        if end > LANE_BYTES {
            return None;
        }
        let block = allocations
            .blocks
            .iter_mut()
            .find(|block| block.size == 0)?;
        *block = Block {
            offset: offset as u16,
            size: size as u16,
            alignment: alignment as u16,
        };
        allocations.end = end;
        // SAFETY: The checked range fits the aligned lane. The bump cursor
        // never reuses an address during this invocation, and previous
        // invocations have completed before the lane can be claimed again.
        unsafe {
            let ptr = (&raw mut (*lane.bytes.get()).0).cast::<u8>().add(offset);
            ptr.write_bytes(0, size);
            Some(NonNull::new_unchecked(ptr))
        }
    }

    /// Retires an exact, live allocation belonging to this invocation.
    pub fn deallocate(&self, address: usize, size: usize, alignment: usize) -> bool {
        let Some(lane) = self.lane.get() else {
            return false;
        };
        let Some(offset) = address.checked_sub(lane.bytes.get().addr()) else {
            return false;
        };
        // SAFETY: The lane is exclusively claimed by this invocation.
        let allocations = unsafe { &mut *lane.allocations.get() };
        if let Some(block) = allocations.blocks.iter_mut().find(|block| {
            block.size != 0
                && usize::from(block.offset) == offset
                && usize::from(block.size) == size
                && usize::from(block.alignment) == alignment
        }) {
            block.size = 0;
            true
        } else {
            false
        }
    }

    /// Reads a byte if `address` is a live base and `index` fits its allocation.
    pub fn read_byte(&self, address: usize, index: usize) -> Option<u8> {
        let ptr = self.byte_pointer(address, index)?;
        // SAFETY: This invocation holds the checked, initialized byte.
        Some(unsafe { ptr.read() })
    }

    /// Writes a byte if `address` is a live base and `index` fits its allocation.
    pub fn write_byte(&self, address: usize, index: usize, value: u8) -> bool {
        let Some(ptr) = self.byte_pointer(address, index) else {
            return false;
        };
        // SAFETY: This invocation holds exclusive access to the checked byte.
        unsafe { ptr.write(value) };
        true
    }

    fn byte_pointer(&self, address: usize, index: usize) -> Option<*mut u8> {
        let lane = self.lane.get()?;
        let offset = address.checked_sub(lane.bytes.get().addr())?;
        // SAFETY: This invocation exclusively owns the allocation records.
        let allocations = unsafe { &*lane.allocations.get() };
        let block = allocations
            .blocks
            .iter()
            .find(|block| usize::from(block.offset) == offset && index < usize::from(block.size))?;
        // Derive the pointer from the backing allocation; the native address
        // is only a lookup key.
        Some(
            lane.bytes
                .get()
                .cast::<u8>()
                .wrapping_add(usize::from(block.offset) + index),
        )
    }

    /// Copies a prefix of a readable range inside one live allocation. The
    /// entire requested range must belong to this invocation, even when the
    /// caller truncates the copy. Interior starting addresses are accepted.
    pub fn copy_bytes(&self, address: usize, length: usize, prefix: &mut [u8]) -> bool {
        let Some(lane) = self.lane.get() else {
            return false;
        };
        let Some(start) = address.checked_sub(lane.bytes.get().addr()) else {
            return false;
        };
        let Some(end) = start.checked_add(length) else {
            return false;
        };
        // SAFETY: The active invocation exclusively owns the metadata.
        let allocations = unsafe { &*lane.allocations.get() };
        if prefix.len() > length
            || !allocations.blocks.iter().any(|block| {
                let base = usize::from(block.offset);
                block.size != 0 && base <= start && end <= base + usize::from(block.size)
            })
        {
            return false;
        }
        // SAFETY: This lane is exclusive; live block bytes are initialized
        // on allocation. The checked prefix lies within that block. Copy
        // permits overlapping storage and no borrow of native bytes escapes.
        unsafe {
            lane.bytes
                .get()
                .cast::<u8>()
                .add(start)
                .copy_to(prefix.as_mut_ptr(), prefix.len())
        };
        true
    }

    fn exact_block(&self, address: usize, size: usize) -> Option<*mut u8> {
        let lane = self.lane.get()?;
        let offset = address.checked_sub(lane.bytes.get().addr())?;
        // SAFETY: This invocation exclusively owns the allocation records.
        let allocations = unsafe { &*lane.allocations.get() };
        let block = allocations.blocks.iter().find(|block| {
            block.size != 0
                && usize::from(block.offset) == offset
                && usize::from(block.size) == size
        })?;
        Some(
            lane.bytes
                .get()
                .cast::<u8>()
                .wrapping_add(usize::from(block.offset)),
        )
    }

    /// Copies an entire live allocation of exactly the destination's size.
    pub fn read_allocation(&self, address: usize, destination: &mut [u8]) -> bool {
        let Some(ptr) = self.exact_block(address, destination.len()) else {
            return false;
        };
        // SAFETY: The invocation owns the full initialized block. The
        // destination borrow spans the same number of bytes.
        unsafe { ptr.copy_to(destination.as_mut_ptr(), destination.len()) };
        true
    }

    /// Replaces an entire live allocation only if the address and size match.
    pub fn write_allocation(&self, address: usize, source: &[u8]) -> bool {
        let Some(ptr) = self.exact_block(address, source.len()) else {
            return false;
        };
        // SAFETY: The invocation owns the exact checked destination. The
        // source is readable for the same number of bytes.
        unsafe { source.as_ptr().copy_to(ptr, source.len()) };
        true
    }
}

impl Drop for NativeHeapInvocation<'_> {
    fn drop(&mut self) {
        if let Some(lane) = self.lane.get() {
            // SAFETY: Native execution has returned and this lease still owns
            // the lane. All pointer lifetimes end before the next invocation.
            unsafe { *lane.allocations.get() = Allocations::default() };
            lane.claimed.store(false, Ordering::Release);
        }
    }
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[ktest]
    fn native_heap_enforces_layout_ownership_and_bounds() {
        let pool = NativeHeapPool::new().unwrap();
        let invocation = pool.invocation();
        assert!(invocation.allocate(0, 1).is_none());
        assert!(invocation.allocate(1, 3).is_none());
        assert!(invocation.allocate(1, 32).is_none());
        let block = invocation.allocate(7, 16).unwrap();
        let address = block.as_ptr().addr();
        assert!(address.is_multiple_of(16));
        let other = pool.invocation();
        let second = other.allocate(7, 16).unwrap();
        assert_ne!(address, second.as_ptr().addr());
        assert!(invocation.write_byte(address, 6, 0x82));
        assert_eq!(invocation.read_byte(address, 6), Some(0x82));
        let mut prefix = [0; 1];
        assert!(invocation.copy_bytes(address + 6, 1, &mut prefix));
        assert_eq!(prefix, [0x82]);
        assert!(!invocation.copy_bytes(address + 6, 2, &mut prefix));
        assert!(!other.copy_bytes(address, 1, &mut prefix));
        let saved = [0x12; 7];
        assert!(invocation.write_allocation(address, &saved));
        assert!(!invocation.write_allocation(address, &[0x34; 6]));
        assert!(!other.write_allocation(address, &[0xa5; 7]));
        let mut copy = [0; 7];
        assert!(!invocation.read_allocation(address + 1, &mut copy));
        assert_eq!(copy, [0; 7]);
        assert!(invocation.read_allocation(address, &mut copy));
        assert_eq!(copy, saved);
        assert_eq!(other.read_byte(address, 6), None);
        assert!(!other.write_byte(address, 0, 1));
        assert_eq!(invocation.read_byte(address + 1, 0), None);
        assert_eq!(invocation.read_byte(address, 7), None);
        assert!(!invocation.write_byte(address, usize::MAX, 2));
        assert!(!other.deallocate(address, 7, 16));
        assert!(!invocation.deallocate(address + 1, 7, 16));
        assert!(!invocation.deallocate(address, 6, 16));
        assert!(!invocation.deallocate(address, 7, 8));
        assert!(invocation.deallocate(address, 7, 16));
        assert!(!invocation.copy_bytes(address, 1, &mut prefix));
        assert!(!invocation.read_allocation(address, &mut copy));
        assert!(!invocation.write_allocation(address, &saved));
        assert_eq!(invocation.read_byte(address, 0), None);
        assert!(!invocation.write_byte(address, 0, 2));
        assert!(!invocation.deallocate(address, 7, 16));
        assert_ne!(invocation.allocate(7, 16).unwrap().as_ptr().addr(), address);
        assert!(invocation.allocate(LANE_BYTES, 1).is_none());
    }

    #[ktest]
    fn native_heap_reclaims_outstanding_blocks_at_invocation_exit() {
        let pool = NativeHeapPool::new().unwrap();
        let leases: Vec<_> = (0..LANES).map(|_| pool.invocation()).collect();
        for lease in &leases {
            let block = lease.allocate(LANE_BYTES, 1).unwrap();
            // SAFETY: The invocation owns all these bytes for this test's write.
            unsafe { block.as_ptr().write_bytes(0xa5, LANE_BYTES) };
        }
        assert!(pool.invocation().allocate(1, 1).is_none());
        drop(leases);
        let lease = pool.invocation();
        for _ in 0..MAX_LIVE_BLOCKS {
            let block = lease.allocate(1, 1).unwrap();
            // SAFETY: The invocation owns this newly zeroed byte.
            assert_eq!(unsafe { block.as_ptr().read() }, 0);
        }
        assert!(lease.allocate(1, 1).is_none());
    }
}
