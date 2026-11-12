// SPDX-License-Identifier: MPL-2.0

//! RSM kernel extension subsystem.
//!
//! Loads verified, compiled RSM programs into executable kernel memory, attaches
//! one to the system-call entry, and reports counters. All state is statically
//! initialized, so the subsystem needs no runtime setup.

use core::sync::atomic::{AtomicU64, Ordering};

use aster_rsm::{
    RsmProgram,
    hooks::{self, HookError, Phase},
};

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{UserNamespace, credentials::capabilities::CapSet},
    security::lsm::hooks as lsm_hooks,
};

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

/// Gates the RSM loader behind `CAP_SYS_MODULE`.
///
/// This is a stopgap, not the real trust boundary: a caller that holds the
/// capability can still load arbitrary machine code. It only blocks
/// unprivileged abuse until the RSM verifier runs in-kernel at load time.
fn require_rsm_capability(ctx: &Context) -> Result<()> {
    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        UserNamespace::get_init_singleton().as_ref(),
        ctx.posix_thread,
        CapSet::SYS_MODULE,
    ))
}

/// Commands multiplexed through the single `SYS_RSM` syscall.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum RsmCmd {
    /// Loads a compiled program from a user buffer.
    Load = 0,
    /// Attaches the loaded program to the system-call entry.
    Attach = 1,
    /// Detaches the currently attached program.
    Detach = 2,
    /// Copies counter and invocation statistics to a user buffer.
    ReadStats = 3,
    /// Attaches the loaded program to a generated function and phase.
    AttachHook = 4,
    /// Detaches a generated function's phase from future invocations.
    DetachHook = 5,
    /// Reads a generated function phase's cumulative statistics.
    ReadHookStats = 6,
}

/// Dispatches the multiplexed `SYS_RSM` command.
///
/// `arg1` and `arg2` are interpreted per command: `Load` reads an artifact of
/// `arg2` bytes from the user buffer `arg1`, `ReadStats` writes to the user
/// buffer `arg1`, and `Attach`/`Detach` ignore both.
pub(super) fn sys_rsm(cmd: u32, arg1: Vaddr, arg2: usize, ctx: &Context) -> Result<SyscallReturn> {
    match RsmCmd::try_from(cmd)? {
        RsmCmd::Load => rsm_load(arg1, arg2, ctx),
        RsmCmd::Attach => rsm_attach(ctx),
        RsmCmd::Detach => rsm_detach(ctx),
        RsmCmd::ReadStats => rsm_read_stats(arg1, ctx),
        RsmCmd::AttachHook => rsm_attach_hook(arg1 as u64, arg2 as u64, ctx),
        RsmCmd::DetachHook => rsm_detach_hook(arg1 as u64, arg2 as u64, ctx),
        RsmCmd::ReadHookStats => rsm_read_hook_stats(arg1, ctx),
    }
}

/// Attaches the loaded program to one generated hook phase.
fn rsm_attach_hook(id: u64, phase: u64, ctx: &Context) -> Result<SyscallReturn> {
    require_rsm_capability(ctx)?;
    let phase = hook_phase(phase)?;
    hooks::find(id).map_err(hook_error)?;
    let program = PROGRAM
        .read()
        .as_ref()
        .cloned()
        .ok_or_else(|| Error::new(Errno::ENOENT))?;
    hooks::attach(id, phase, program).map_err(hook_error)?;
    Ok(SyscallReturn::Return(0))
}

/// Stops admitting new function invocations to one hook phase.
fn rsm_detach_hook(id: u64, phase: u64, ctx: &Context) -> Result<SyscallReturn> {
    require_rsm_capability(ctx)?;
    let phase = hook_phase(phase)?;
    hooks::detach(id, phase).map_err(hook_error)?;
    Ok(SyscallReturn::Return(0))
}

/// Copies cumulative hook counters without exposing kernel addresses.
fn rsm_read_hook_stats(address: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    let user_space = ctx.user_space();
    let mut request = user_space
        .reader(address, size_of::<RsmHookStats>())?
        .read_val::<RsmHookStats>()?;
    if request.reserved != 0 {
        return_errno_with_message!(Errno::EINVAL, "reserved hook statistics field is nonzero");
    }
    let phase = hook_phase(u64::from(request.phase))?;
    let stats = hooks::find(request.hook_id)
        .map_err(hook_error)?
        .stats(phase);
    request.invocations = stats.invocations;
    request.skipped = stats.skipped;
    request.traps = stats.traps;
    user_space
        .writer(address, size_of::<RsmHookStats>())?
        .write_val(&request)?;
    Ok(SyscallReturn::Return(0))
}

fn hook_phase(value: u64) -> Result<Phase> {
    Phase::from_raw(value).ok_or_else(|| Error::new(Errno::EINVAL))
}

fn hook_error(error: HookError) -> Error {
    Error::new(match error {
        HookError::NotFound | HookError::NotAttached => Errno::ENOENT,
        HookError::AlreadyAttached => Errno::EBUSY,
        HookError::Ambiguous => Errno::EINVAL,
        HookError::GenerationExhausted => Errno::EOVERFLOW,
    })
}

/// The input identity and output counters for `READ_HOOK_STATS`.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
struct RsmHookStats {
    hook_id: u64,
    phase: u32,
    reserved: u32,
    invocations: u64,
    skipped: u64,
    traps: u64,
}

/// Loads an artifact from a user buffer and stores it as the loaded program.
fn rsm_load(user_buf_ptr: Vaddr, user_buf_len: usize, ctx: &Context) -> Result<SyscallReturn> {
    require_rsm_capability(ctx)?;

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
fn rsm_attach(ctx: &Context) -> Result<SyscallReturn> {
    require_rsm_capability(ctx)?;

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
fn rsm_detach(ctx: &Context) -> Result<SyscallReturn> {
    require_rsm_capability(ctx)?;

    *ATTACHED.write() = None;
    // Reclaim the per-attachment invocation count now that the plugin's
    // lifecycle has ended, so the next attachment starts from zero.
    INVOCATIONS.store(0, Ordering::Relaxed);
    Ok(SyscallReturn::Return(0))
}

/// Copies the counter and invocation statistics to the user buffer.
fn rsm_read_stats(user_buf_ptr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    let stats = read_stats();
    let user_space = ctx.user_space();
    let mut writer = user_space.writer(user_buf_ptr, size_of::<RsmStats>())?;
    writer.write_val(&stats)?;
    Ok(SyscallReturn::Return(0))
}

/// Returns the current statistics.
///
/// The counter belongs to the loaded program, not to one attachment, so it
/// stays readable after a detach — that is when a run's totals are usually
/// inspected. The attached program is consulted first so the common case does
/// not touch the second lock; both handles are cloned out before the lock guard
/// is dropped.
pub(crate) fn read_stats() -> RsmStats {
    let attached = ATTACHED.read().as_ref().cloned();
    let counter = match attached {
        Some(program) => program.counter(),
        None => PROGRAM
            .read()
            .as_ref()
            .map_or(0, |program| program.counter()),
    };
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
