// SPDX-License-Identifier: MPL-2.0

//! The RSM subsystem directory at `/proc/rsm`.

use self::{hooks::RsmHooksFileOps, log::RsmLogFileOps, stats::RsmStatsFileOps};
use super::{
    StaticEntry,
    template::{
        ProcDir, ProcDirOps, ReaddirEntry, listed_entries_from_table, lookup_child_from_table,
        visit_listed_entries,
    },
};
use crate::{
    fs::{
        file::{InodeType, mkmod},
        vfs::inode::Inode,
    },
    prelude::*,
};

mod hooks;
mod log;
mod stats;

/// Represents the inode at `/proc/rsm`.
pub(super) struct RsmDirOps;

impl RsmDirOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcDir::new(Self, parent, mkmod!(a+rx))
    }

    const STATIC_ENTRIES: &'static [StaticEntry] = &[
        ("hooks", InodeType::File, RsmHooksFileOps::new_inode),
        ("log", InodeType::File, RsmLogFileOps::new_inode),
        ("stats", InodeType::File, RsmStatsFileOps::new_inode),
    ];
}

impl ProcDirOps for RsmDirOps {
    fn lookup_child(&self, this_dir: &ProcDir<Self>, name: &str) -> Result<Arc<dyn Inode>> {
        if let Some(child) = lookup_child_from_table(name, Self::STATIC_ENTRIES, |f| {
            (f)(this_dir.this_weak().clone())
        }) {
            return Ok(child);
        }

        return_errno_with_message!(Errno::ENOENT, "the file does not exist");
    }

    fn visit_entries_from_offset<'a, F>(&'a self, offset: usize, visit_fn: F) -> Result<()>
    where
        F: FnMut(ReaddirEntry<'a>) -> Result<()>,
    {
        visit_listed_entries(
            offset,
            listed_entries_from_table(Self::STATIC_ENTRIES),
            visit_fn,
        )
    }
}
