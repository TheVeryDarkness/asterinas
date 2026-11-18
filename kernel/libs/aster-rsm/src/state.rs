// SPDX-License-Identifier: MPL-2.0

//! Fixed-capacity, named arrays owned by a loaded RSM program.

#![forbid(unsafe_code)]

use alloc::{collections::TryReserveError, vec::Vec};
use core::{
    ops::DerefMut,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(feature = "ostd")]
use ostd::sync::SpinLock as Lock;
#[cfg(not(feature = "ostd"))]
extern crate std;
#[cfg(not(feature = "ostd"))]
use std::sync::Mutex as Lock;

const MAX_MAPS: usize = 16;
const MAX_WORDS: usize = 64;

/// Handles are unique across all programs and are never recycled across frees.
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Errors from inspecting a program's named state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    /// The program has no live array with this name.
    Missing,
    /// The index is outside the named array.
    OutOfBounds,
}

struct WordMap {
    key: u64,
    handle: u64,
    len: usize,
    words: [u64; MAX_WORDS],
}

pub(crate) struct ProgramState {
    maps: Lock<Vec<WordMap>>,
}

impl ProgramState {
    /// Reserves all storage during load, before a hook can run.
    pub(crate) fn new() -> Result<Self, TryReserveError> {
        let mut maps = Vec::new();
        maps.try_reserve_exact(MAX_MAPS)?;
        Ok(Self {
            maps: Lock::new(maps),
        })
    }

    fn lock(&self) -> impl DerefMut<Target = Vec<WordMap>> + '_ {
        // The same program may run in an IRQ-disabled hook while userspace is
        // reading its state. Disable local IRQs on both sides of the lock.
        #[cfg(feature = "ostd")]
        {
            self.maps.disable_irq().lock()
        }
        #[cfg(not(feature = "ostd"))]
        {
            self.maps.lock().unwrap()
        }
    }

    pub(crate) fn get_or_create(&self, key: u64, words: u64) -> Option<u64> {
        let len = usize::try_from(words).ok()?;
        if !(1..=MAX_WORDS).contains(&len) {
            return None;
        }
        let mut maps = self.lock();
        if let Some(map) = maps.iter().find(|map| map.key == key) {
            return (map.len == len).then_some(map.handle);
        }
        if maps.len() == MAX_MAPS {
            return None;
        }
        let handle = NEXT_HANDLE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .ok()?;
        maps.push(WordMap {
            key,
            handle,
            len,
            words: [0; MAX_WORDS],
        });
        Some(handle)
    }

    pub(crate) fn read_named(&self, key: u64, index: u64) -> Result<u64, StateError> {
        let maps = self.lock();
        let map = maps
            .iter()
            .find(|map| map.key == key)
            .ok_or(StateError::Missing)?;
        let index = usize::try_from(index).map_err(|_| StateError::OutOfBounds)?;
        map.words[..map.len]
            .get(index)
            .copied()
            .ok_or(StateError::OutOfBounds)
    }

    fn with_word<T>(&self, handle: u64, index: u64, f: impl FnOnce(&mut u64) -> T) -> Option<T> {
        let index = usize::try_from(index).ok()?;
        let mut maps = self.lock();
        let map = maps.iter_mut().find(|map| map.handle == handle)?;
        map.words[..map.len].get_mut(index).map(f)
    }

    pub(crate) fn load(&self, handle: u64, index: u64) -> Option<u64> {
        self.with_word(handle, index, |word| *word)
    }

    pub(crate) fn store(&self, handle: u64, index: u64, value: u64) -> bool {
        self.with_word(handle, index, |word| *word = value)
            .is_some()
    }

    pub(crate) fn fetch_add(&self, handle: u64, index: u64, value: u64) -> Option<u64> {
        self.with_word(handle, index, |word| {
            let old = *word;
            *word = old.wrapping_add(value);
            old
        })
    }

    /// Replaces every word together, after the native source has validated.
    pub(crate) fn save_bytes(&self, handle: u64, read: impl FnOnce(&mut [u8]) -> bool) -> bool {
        let mut maps = self.lock();
        let Some(map) = maps.iter_mut().find(|map| map.handle == handle) else {
            return false;
        };
        let mut bytes = [0; MAX_WORDS * size_of::<u64>()];
        let destination = &mut bytes[..map.len * size_of::<u64>()];
        if !read(destination) {
            return false;
        }
        for (word, bytes) in map.words[..map.len]
            .iter_mut()
            .zip(destination.as_chunks::<8>().0)
        {
            *word = u64::from_le_bytes(*bytes);
        }
        true
    }

    /// Takes one snapshot of all words before copying into a native allocation.
    pub(crate) fn restore_bytes(&self, handle: u64, write: impl FnOnce(&[u8]) -> bool) -> bool {
        let mut bytes = [0; MAX_WORDS * size_of::<u64>()];
        let length = {
            let maps = self.lock();
            let Some(map) = maps.iter().find(|map| map.handle == handle) else {
                return false;
            };
            for (word, bytes) in map.words[..map.len]
                .iter()
                .zip(bytes.as_chunks_mut::<8>().0)
            {
                *bytes = word.to_le_bytes();
            }
            map.len * size_of::<u64>()
        };
        write(&bytes[..length])
    }

    pub(crate) fn free(&self, handle: u64) -> bool {
        let mut maps = self.lock();
        let Some(index) = maps.iter().position(|map| map.handle == handle) else {
            return false;
        };
        maps.swap_remove(index);
        true
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn create_reopen_inspect_and_reclaim_named_arrays() {
        let state = ProgramState::new().unwrap();
        assert_eq!(state.get_or_create(0, 0), None);
        assert_eq!(state.get_or_create(0, (MAX_WORDS + 1) as u64), None);
        let handle = state.get_or_create(0, MAX_WORDS as u64).unwrap();
        assert_eq!(state.get_or_create(0, MAX_WORDS as u64), Some(handle));
        assert_eq!(state.get_or_create(0, 1), None);
        assert!(state.store(handle, 63, u64::MAX));
        assert_eq!(state.fetch_add(handle, 63, 2), Some(u64::MAX));
        assert_eq!(state.read_named(0, 63), Ok(1));
        assert_eq!(state.read_named(0, 64), Err(StateError::OutOfBounds));
        assert!(!state.store(handle, u64::MAX, 1));
        for key in 1..MAX_MAPS {
            assert!(state.get_or_create(key as u64, 1).is_some());
        }
        assert_eq!(state.get_or_create(MAX_MAPS as u64, 1), None);
        assert!(state.free(handle));
        assert_eq!(state.read_named(0, 0), Err(StateError::Missing));
        let replacement = state.get_or_create(0, MAX_WORDS as u64).unwrap();
        assert_ne!(handle, replacement);
        assert_eq!(state.load(handle, 0), None);
        assert!(!state.free(handle));
        assert_eq!(state.load(replacement, 63), Some(0));
    }

    #[test]
    fn handles_are_private_to_the_program_and_expire_on_drop() {
        let first = Arc::new(ProgramState::new().unwrap());
        let second = ProgramState::new().unwrap();
        let handle = first.get_or_create(7, 1).unwrap();
        let other = second.get_or_create(7, 1).unwrap();
        assert_ne!(handle, other);
        assert!(!second.store(handle, 0, 3));
        let callback = first.clone();
        let weak = Arc::downgrade(&first);
        drop(first);
        assert!(callback.store(handle, 0, 9));
        drop(callback);
        assert!(weak.upgrade().is_none());
        let reloaded = ProgramState::new().unwrap();
        assert_eq!(reloaded.read_named(7, 0), Err(StateError::Missing));
        assert_ne!(reloaded.get_or_create(7, 1), Some(handle));
        assert_eq!(reloaded.load(handle, 0), None);
    }

    #[test]
    fn concurrent_creation_and_additions_share_a_single_array() {
        let state = Arc::new(ProgramState::new().unwrap());
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let state = &state;
                scope.spawn(move || {
                    let handle = state.get_or_create(1, 2).unwrap();
                    for _ in 0..500 {
                        assert!(state.fetch_add(handle, 1, 1).is_some());
                    }
                });
            }
        });
        assert_eq!(state.read_named(1, 1), Ok(4000));
    }

    #[test]
    fn whole_arrays_round_trip_little_endian_without_partial_updates() {
        let state = ProgramState::new().unwrap();
        let handle = state.get_or_create(5, 2).unwrap();
        let mut saved = [0x77; 16];
        saved[..8].copy_from_slice(&17u64.to_le_bytes());
        assert!(state.save_bytes(handle, |dst| {
            dst.copy_from_slice(&saved);
            true
        }));
        assert_eq!(state.read_named(5, 0), Ok(17));
        assert_eq!(state.read_named(5, 1), Ok(0x7777_7777_7777_7777));
        assert!(!state.save_bytes(handle, |dst| {
            dst[0] = 0xff;
            false
        }));
        assert!(state.restore_bytes(handle, |src| src == saved));
        assert!(!state.restore_bytes(handle, |_| false));
        assert!(state.free(handle));
        assert!(!state.restore_bytes(handle, |_| panic!("stale handle read")));
        assert!(!state.save_bytes(handle, |_| panic!("stale handle write")));
    }

    #[test]
    fn concurrent_snapshots_never_mix_two_saved_buffers() {
        let state = ProgramState::new().unwrap();
        let handle = state.get_or_create(0, MAX_WORDS as u64).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for value in 1..=200 {
                    assert!(state.save_bytes(handle, |dst| {
                        dst.fill(value);
                        true
                    }));
                }
            });
            for _ in 0..200 {
                assert!(state.restore_bytes(handle, |src| src.iter().all(|byte| *byte == src[0])));
            }
        });
    }
}
