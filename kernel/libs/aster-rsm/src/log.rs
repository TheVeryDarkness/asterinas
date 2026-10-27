// SPDX-License-Identifier: MPL-2.0

//! A fixed-capacity byte ring that records messages from verified RSM programs.
//!
//! The ring backs `/proc/rsm_log` and is written by [`super::trampoline::host_trampoline`]
//! when it dispatches helper index 2 (`rsm_printk`). It lives in `aster-rsm` rather
//! than `aster-core` because the trampoline is its sole writer: keeping the buffer
//! next to its writer avoids a callback across the crate boundary and keeps the
//! write path on the system-call entry allocation-free and panic-free. `aster-core`
//! reads the buffer through [`snapshot`] only.

use ostd::sync::SpinLock;

/// Maximum number of bytes a single `rsm_printk` call may append.
///
/// Longer messages are truncated by the trampoline before reaching [`append`].
pub const MAX_MESSAGE_BYTES: usize = 1024;

/// Capacity of the ring buffer in bytes.
pub const LOG_CAPACITY_BYTES: usize = 4096;

/// The ring buffer exposed at `/proc/rsm_log`.
///
/// It is a fixed-capacity byte ring guarded by a [`SpinLock`], so appending
/// never allocates and cannot panic on the system-call path. New bytes are
/// appended after the newest existing byte; when the ring is full, the oldest
/// bytes are overwritten.
struct LogRing {
    bytes: [u8; LOG_CAPACITY_BYTES],
    /// Index of the oldest byte.
    head: usize,
    /// Number of valid bytes.
    len: usize,
}

impl LogRing {
    /// Creates an empty ring.
    const fn new() -> Self {
        Self {
            bytes: [0; LOG_CAPACITY_BYTES],
            head: 0,
            len: 0,
        }
    }

    /// Appends `bytes`, dropping the oldest bytes when the ring is full.
    fn append(&mut self, bytes: &[u8]) {
        let capacity = self.bytes.len();
        if bytes.len() >= capacity {
            // The message alone overflows the ring; keep only its newest tail.
            let newest = &bytes[bytes.len() - capacity..];
            self.bytes.copy_from_slice(newest);
            self.head = 0;
            self.len = capacity;
            return;
        }

        // Drop the oldest bytes to make room when the free space is insufficient.
        let free = capacity - self.len;
        if bytes.len() > free {
            let dropped = bytes.len() - free;
            self.head = (self.head + dropped) % capacity;
            self.len -= dropped;
        }

        let tail = (self.head + self.len) % capacity;
        let first_len = (capacity - tail).min(bytes.len());
        self.bytes[tail..tail + first_len].copy_from_slice(&bytes[..first_len]);
        let second_len = bytes.len() - first_len;
        if second_len > 0 {
            self.bytes[..second_len].copy_from_slice(&bytes[first_len..]);
        }
        self.len += bytes.len();
    }

    /// Copies the buffered bytes, oldest first, into `dest`.
    ///
    /// Returns the number of bytes copied.
    fn copy_out(&self, dest: &mut [u8]) -> usize {
        let count = self.len.min(dest.len());
        let first_len = (self.bytes.len() - self.head).min(count);
        dest[..first_len].copy_from_slice(&self.bytes[self.head..self.head + first_len]);
        let second_len = count - first_len;
        if second_len > 0 {
            dest[first_len..count].copy_from_slice(&self.bytes[..second_len]);
        }
        count
    }

    /// Resets the ring to empty.
    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }
}

/// The sole ring buffer, shared by the trampoline and `/proc/rsm_log`.
static LOG: SpinLock<LogRing> = SpinLock::new(LogRing::new());

/// Appends `bytes` to the ring buffer, dropping the oldest bytes when full.
pub fn append(bytes: &[u8]) {
    LOG.lock().append(bytes);
}

/// Copies the buffered bytes, oldest first, into `dest`.
///
/// Returns the number of bytes copied.
pub fn snapshot(dest: &mut [u8]) -> usize {
    LOG.lock().copy_out(dest)
}

/// Resets the ring buffer to empty.
pub fn clear() {
    LOG.lock().clear();
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::ktest;

    use super::{LOG_CAPACITY_BYTES, LogRing};

    /// Verifies that append and snapshot round-trip when no wraparound occurs.
    #[ktest]
    fn log_round_trip() {
        let mut ring = LogRing::new();
        let message = b"rsm_printk test";

        ring.append(message);

        let mut out = [0u8; LOG_CAPACITY_BYTES];
        let count = ring.copy_out(&mut out);
        assert_eq!(count, message.len());
        assert_eq!(&out[..count], message);
    }

    /// Verifies that a full ring overwrites the oldest bytes with the newest.
    #[ktest]
    fn log_overwrites_oldest() {
        let mut ring = LogRing::new();
        ring.append(&[b'a'; LOG_CAPACITY_BYTES]);
        ring.append(b"tail");

        let mut out = [0u8; LOG_CAPACITY_BYTES];
        let count = ring.copy_out(&mut out);
        assert_eq!(count, LOG_CAPACITY_BYTES);
        assert_eq!(
            &out[..LOG_CAPACITY_BYTES - 4],
            &[b'a'; LOG_CAPACITY_BYTES - 4]
        );
        assert_eq!(&out[LOG_CAPACITY_BYTES - 4..], b"tail");
    }
}
