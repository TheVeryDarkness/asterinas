// SPDX-License-Identifier: MPL-2.0

//! Histograms elapsed kernel time for successful plain FUTEX_WAIT operations.
//! Key zero holds four latency buckets, the error count, and unmatched successes.

use rsm_apis::{
    get_kernel_time_ns, rsm_map_fetch_add, rsm_map_get_or_create, rsm_map_load, rsm_map_store,
};

#[rsm::export]
pub fn main(_hook: u64, phase: u64, id: u64, is_error: u64, _: u64, _: u64, _: u64) -> u32 {
    let totals = rsm_map_get_or_create(0, 6);
    if totals == 0 || id == 0 {
        return 0;
    }
    if phase == 1 && is_error != 0 {
        rsm_map_fetch_add(totals, 4, 1);
        return 0;
    }

    let now = get_kernel_time_ns();
    // Each of 16 slots holds an access count, a full invocation ID, and a timestamp.
    // A later entry can replace a skipped return's record without exhausting the map.
    let records = rsm_map_get_or_create(1, 48);
    let slot = (id & 15) * 3;
    if records == 0 {
        if phase == 1 {
            rsm_map_fetch_add(totals, 5, 1);
        }
        return 0;
    }
    // Only the caller that increments zero accesses the ID/time pair. All callers
    // release their increment; none waits for an overlapping callback.
    let previous = rsm_map_fetch_add(records, slot, 1);
    if previous == 0 {
        if phase == 0 {
            rsm_map_store(records, slot + 1, id);
            rsm_map_store(records, slot + 2, now);
        } else {
            let owner = rsm_map_load(records, slot + 1);
            let start = rsm_map_load(records, slot + 2);
            let bucket = if owner != id || now < start {
                5
            } else {
                let ns = now.wrapping_sub(start);
                if ns < 100_000 {
                    0
                } else if ns < 1_000_000 {
                    1
                } else if ns < 10_000_000 {
                    2
                } else {
                    3
                }
            };
            rsm_map_fetch_add(totals, bucket, 1);
        }
    } else if phase == 1 {
        rsm_map_fetch_add(totals, 5, 1);
    }
    rsm_map_fetch_add(records, slot, u64::MAX);
    0
}
