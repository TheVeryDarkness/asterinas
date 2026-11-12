// SPDX-License-Identifier: MPL-2.0

//! Lists the generated hooks and copied scalar fields compiled into this kernel.

use aster_rsm::hooks::{self, Phase};
use aster_util::printer::VmPrinter;

use crate::{
    fs::{
        file::mkmod,
        procfs::template::{ProcFile, ProcFileOps},
        vfs::inode::Inode,
    },
    prelude::*,
};

/// The immutable function-hook catalog at `/proc/rsm/hooks`.
pub(super) struct RsmHooksFileOps;

impl RsmHooksFileOps {
    pub(super) fn new_inode(parent: Weak<dyn Inode>) -> Arc<dyn Inode> {
        ProcFile::new(Self, parent, mkmod!(a+r))
    }
}

impl ProcFileOps for RsmHooksFileOps {
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        // Registration and schemas never change after boot. Repeated partial
        // reads therefore see one catalog even during concurrent attach/detach.
        let mut printer = VmPrinter::new_skip(writer, offset);
        writeln!(printer, "# id\tfunction\tentry_fields\treturn_fields")?;
        for hook in hooks::catalog() {
            write!(printer, "{:016x}\t{}", hook.id(), hook.name())?;
            for phase in [Phase::Entry, Phase::Return] {
                write!(printer, "\t")?;
                let fields = hook.fields(phase);
                if fields.is_empty() {
                    write!(printer, "-")?;
                }
                for (index, field) in fields.iter().enumerate() {
                    if index != 0 {
                        write!(printer, ",")?;
                    }
                    write!(printer, "{}:{}", field.name(), field.type_name())?;
                }
            }
            writeln!(printer)?;
        }
        Ok(printer.bytes_written())
    }
}
