// SPDX-License-Identifier: MPL-2.0

//! Counts read requests by size: empty, 1–64 bytes, 65–4096 bytes, and larger.

use rsm_apis::{rsm_map_fetch_add, rsm_map_get_or_create};

#[rsm::export]
pub fn main(_hook: u64, phase: u64, _id: u64, _fd: u64, _buf: u64, len: u64, _: u64) -> u32 {
    if phase == 0 {
        let counts = rsm_map_get_or_create(0, 4);
        if counts != 0 {
            let bucket = if len == 0 {
                0
            } else if len <= 64 {
                1
            } else if len <= 4096 {
                2
            } else {
                3
            };
            rsm_map_fetch_add(counts, bucket, 1);
        }
    }
    0
}
