// SPDX-License-Identifier: MPL-2.0

//! Reports the entry and error return of the guest's controlled one-byte read.

use rsm_apis::{print_kernel, rsm_printk};

#[rsm::export]
pub fn main(
    hook_id: u64,
    phase: u64,
    invocation_id: u64,
    first: u64,
    second: u64,
    third: u64,
    fourth: u64,
) -> u32 {
    if hook_id == 0 || invocation_id == 0 || fourth != 0 {
        return 0;
    }

    // Entry carries the signed file descriptor, user buffer address and length.
    if phase == 0 && first == u64::MAX && second != 0 && third == 1 {
        rsm_printk("rsm-v2-entry");
    }

    // The error return sets is_error and leaves the rest of the payload empty.
    if phase == 1 && first == 1 && second == 0 && third == 0 {
        rsm_printk("rsm-v2-return");
        return print_kernel();
    }

    0
}
