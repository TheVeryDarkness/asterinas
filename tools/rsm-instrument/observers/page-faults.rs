// SPDX-License-Identifier: MPL-2.0

//! Counts resolved and rejected page faults at the process address-space handler.

use rsm_apis::{rsm_map_fetch_add, rsm_map_get_or_create};

#[rsm::export]
pub fn main(_hook: u64, phase: u64, _id: u64, is_error: u64, _: u64, _: u64, _: u64) -> u32 {
    if phase == 1 && is_error <= 1 {
        let totals = rsm_map_get_or_create(0, 2);
        if totals != 0 {
            rsm_map_fetch_add(totals, is_error, 1);
        }
    }
    0
}
