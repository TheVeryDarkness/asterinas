// SPDX-License-Identifier: MPL-2.0

//! Counts successful and failed binds independently for each attached transport.
//! Attach to the return of the TCP and UDP socket implementations of `bind`.

use rsm_apis::{rsm_map_fetch_add, rsm_map_get_or_create};

#[rsm::export]
pub fn main(hook: u64, phase: u64, _id: u64, is_error: u64, _: u64, _: u64, _: u64) -> u32 {
    if phase == 1 && is_error <= 1 {
        let counts = rsm_map_get_or_create(hook, 2);
        if counts != 0 {
            rsm_map_fetch_add(counts, is_error, 1);
        }
    }
    0
}
