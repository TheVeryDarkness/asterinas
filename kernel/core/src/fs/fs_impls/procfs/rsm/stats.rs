// SPDX-License-Identifier: MPL-2.0

//! Exposes RSM subsystem statistics at `/proc/rsm/stats`.

use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
    syscall::rsm::read_stats,
};

/// Represents the inode at `/proc/rsm/stats`.
pub(super) struct RsmStatsFileOps;

impl RsmStatsFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for RsmStatsFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut printer = VmPrinter::new_skip(writer, offset);
        let stats = read_stats();
        writeln!(printer, "counter={}", stats.counter)?;
        writeln!(printer, "invocations={}", stats.invocations)?;
        Ok(printer.bytes_written())
    }
}
