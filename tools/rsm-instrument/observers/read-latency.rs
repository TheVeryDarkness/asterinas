// SPDX-License-Identifier: MPL-2.0

//! Correlates entry and return by invocation ID and sums completed read durations.

use rsm_apis::{
    get_kernel_time_ns, rsm_map_fetch_add, rsm_map_free, rsm_map_get_or_create, rsm_map_load,
    rsm_map_store,
};

#[rsm::export]
pub fn main(_hook: u64, phase: u64, id: u64, _: u64, _: u64, _: u64, _: u64) -> u32 {
    // Hook invocation IDs start at one. Key zero holds counts for the whole instance.
    let totals = rsm_map_get_or_create(0, 3);
    if totals == 0 || id == 0 {
        return 0;
    }
    let record = rsm_map_get_or_create(id, 1);
    if record == 0 {
        rsm_map_fetch_add(totals, 2, 1);
        return 0;
    }
    if phase == 0 {
        rsm_map_store(record, 0, get_kernel_time_ns());
    } else {
        let start = rsm_map_load(record, 0);
        rsm_map_free(record);
        let end = get_kernel_time_ns();
        if start != 0 && end >= start {
            rsm_map_fetch_add(totals, 0, 1);
            rsm_map_fetch_add(totals, 1, end.wrapping_sub(start));
        } else {
            rsm_map_fetch_add(totals, 2, 1);
        }
    }
    0
}
