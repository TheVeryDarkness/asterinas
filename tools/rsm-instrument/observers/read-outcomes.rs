// SPDX-License-Identifier: MPL-2.0

//! Counts successful and failed reads. Emits one alert on the third failure.

use rsm_apis::{rsm_map_fetch_add, rsm_map_get_or_create, rsm_printk};

#[rsm::export]
pub fn main(_hook: u64, phase: u64, _id: u64, is_error: u64, _: u64, _: u64, _: u64) -> u32 {
    if phase == 1 && is_error <= 1 {
        let counts = rsm_map_get_or_create(0, 2);
        if counts != 0 {
            let previous = rsm_map_fetch_add(counts, is_error, 1);
            if is_error == 1 && previous == 2 {
                rsm_printk("three failed reads");
            }
        }
    }
    0
}
