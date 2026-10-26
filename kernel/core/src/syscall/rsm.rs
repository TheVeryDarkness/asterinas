// SPDX-License-Identifier: MPL-2.0

//! RSM kernel extension subsystem.
//!
//! Loads verified, compiled RSM programs into executable kernel memory, attaches
//! one to the system-call entry, and reports counters. All state is statically
//! initialized, so the subsystem needs no runtime setup.

use core::sync::atomic::{AtomicU64, Ordering};

use aster_rsm::RsmProgram;

use super::SyscallReturn;
use crate::prelude::*;

/// Maximum accepted artifact size, guarding against oversized user buffers.
const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;

/// The loaded program, replaced by each successful `LOAD`.
static PROGRAM: RwLock<Option<Arc<RsmProgram>>> = RwLock::new(None);
/// The program attached to the system-call entry, if any.
static ATTACHED: RwLock<Option<Arc<RsmProgram>>> = RwLock::new(None);
/// Total number of invocations of the attached program.
static INVOCATIONS: AtomicU64 = AtomicU64::new(0);

/// Invokes the attached program with the given system-call event.
///
/// Reading the attachment takes a brief lock and clones the program, so the
/// plugin runs without holding any lock and survives a concurrent detach.
pub(crate) fn observe(nr: u64, args: &[u64; 6]) {
    let program = ATTACHED.read().as_ref().cloned();
    if let Some(program) = program {
        INVOCATIONS.fetch_add(1, Ordering::Relaxed);
        program.observe(nr, args);
    }
}

/// Loads an artifact from a user buffer and stores it as the loaded program.
pub(super) fn sys_rsm_load(
    user_buf_ptr: Vaddr,
    user_buf_len: usize,
    ctx: &Context,
) -> Result<SyscallReturn> {
    if user_buf_len > MAX_ARTIFACT_BYTES {
        return_errno_with_message!(Errno::EINVAL, "artifact is too large");
    }
    let mut bytes = vec![0u8; user_buf_len];
    let user_space = ctx.user_space();
    let mut reader = user_space.reader(user_buf_ptr, user_buf_len)?;
    reader.read_fallible(&mut VmWriter::from(bytes.as_mut_slice()))?;

    let program = RsmProgram::load(&bytes).map_err(|error| {
        warn!("failed to load RSM program: {error:?}");
        Error::new(Errno::EINVAL)
    })?;

    *PROGRAM.write() = Some(Arc::new(program));
    Ok(SyscallReturn::Return(0))
}

/// Attaches the loaded program to the system-call entry.
pub(super) fn sys_rsm_attach(_ctx: &Context) -> Result<SyscallReturn> {
    let Some(program) = PROGRAM.read().as_ref().cloned() else {
        return_errno_with_message!(Errno::ENOENT, "no loaded program");
    };
    let mut attached = ATTACHED.write();
    if attached.is_some() {
        return_errno_with_message!(Errno::EBUSY, "a program is already attached");
    }
    *attached = Some(program);
    Ok(SyscallReturn::Return(0))
}

/// Detaches the currently attached program without waiting for in-flight calls.
pub(super) fn sys_rsm_detach(_ctx: &Context) -> Result<SyscallReturn> {
    *ATTACHED.write() = None;
    // Reclaim the per-attachment invocation count now that the plugin's
    // lifecycle has ended, so the next attachment starts from zero.
    INVOCATIONS.store(0, Ordering::Relaxed);
    Ok(SyscallReturn::Return(0))
}

/// Copies the counter and invocation statistics to the user buffer.
pub(super) fn sys_rsm_read_stats(user_buf_ptr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    let stats = read_stats();
    let user_space = ctx.user_space();
    let mut writer = user_space.writer(user_buf_ptr, size_of::<RsmStats>())?;
    writer.write_val(&stats)?;
    Ok(SyscallReturn::Return(0))
}

/// Returns the current statistics.
pub(crate) fn read_stats() -> RsmStats {
    let counter = ATTACHED
        .read()
        .as_ref()
        .map_or(0, |program| program.counter());
    RsmStats {
        counter,
        invocations: INVOCATIONS.load(Ordering::Relaxed),
    }
}

/// Statistics reported by `READ_STATS` and `/proc/rsm_stats`.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub(crate) struct RsmStats {
    pub(crate) counter: u64,
    pub(crate) invocations: u64,
}
