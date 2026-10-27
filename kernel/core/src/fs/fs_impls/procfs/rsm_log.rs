// SPDX-License-Identifier: MPL-2.0

//! Exposes the RSM message log at `/proc/rsm_log`.

use aster_rsm::log::{LOG_CAPACITY_BYTES, snapshot};

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

/// Represents the inode at `/proc/rsm_log`.
pub(super) struct RsmLogFileOps;

impl RsmLogFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for RsmLogFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        let mut buffer = [0u8; LOG_CAPACITY_BYTES];
        let len = snapshot(&mut buffer);
        if offset >= len {
            return Ok(0);
        }

        let mut reader = VmReader::from(&buffer[offset..len]);
        let written = writer.write_fallible(&mut reader)?;
        Ok(written)
    }
}
