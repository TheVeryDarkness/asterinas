// SPDX-License-Identifier: MPL-2.0

//! Counts completed opens by access intent and outcome on both phases of sys_openat.

use rsm_apis::{rsm_map_fetch_add, rsm_map_get_or_create, rsm_map_load, rsm_map_store};

const O_CREAT: u64 = 1 << 6;
const O_PATH: u64 = 1 << 21;
const O_TMPFILE_BIT: u64 = 1 << 22;
const SLOT_MASK: u64 = 63;

#[rsm::export]
pub fn main(_hook: u64, phase: u64, id: u64, is_error: u64, _: u64, flags: u64, _: u64) -> u32 {
    let totals = rsm_map_get_or_create(0, 9);
    let entries = rsm_map_get_or_create(1, 64);
    if totals == 0 || entries == 0 {
        return 0;
    }

    // The index holds the low six ID bits. In the same word as the remaining
    // ID bits, save the class (1–4). A single load can then identify a collision.
    let slot = id & SLOT_MASK;
    let tag = id & !SLOT_MASK;
    if phase == 0 {
        let access = flags & 3;
        let class = if flags & O_PATH != 0 {
            4 // Path-only descriptors ignore ordinary access modes.
        } else if flags & (O_CREAT | O_TMPFILE_BIT) != 0 {
            3 // Create requested, whether or not the file already exists.
        } else if access == 0 {
            1 // Read-only.
        } else if access == 1 || access == 2 {
            2 // Write-only or read-write.
        } else {
            4 // Reserved access mode.
        };
        rsm_map_store(entries, slot, tag | class);
    } else if phase == 1 {
        let saved = rsm_map_load(entries, slot);
        let class = saved & SLOT_MASK;
        if saved & !SLOT_MASK == tag && class >= 1 && class <= 4 && is_error <= 1 {
            let bucket = (class.wrapping_sub(1) << 1) | is_error;
            rsm_map_fetch_add(totals, bucket, 1);
        } else {
            rsm_map_fetch_add(totals, 8, 1);
        }
    }
    0
}
