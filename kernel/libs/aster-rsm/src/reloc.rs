// SPDX-License-Identifier: MPL-2.0

//! Applies the artifact's relocations at a placement base.
//!
//! The formulas mirror `rsm_jit`'s relocator exactly:
//! `pcrel = (target + addend) - site` for PC-relative forms and
//! `value = target + addend` for absolute forms. The addend is `-4` for x86-64
//! `call` displacements, as emitted by the Cranelift backend.

use crate::artifact::{Artifact, RelocKind, RelocTarget};

/// Reports why relocation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocateError {
    BufferTooShort,
    Overflow,
    OutOfRange,
    UnknownFunction { index: u32 },
}

/// Patches `buffer` in place, treating `buffer.as_ptr()` as the base address.
///
/// The caller must already have copied [`Artifact::code`] into the front of
/// `buffer`. `host_trampoline` supplies the external helper address; it is only
/// consulted for [`RelocTarget::HostTrampoline`] targets.
pub fn apply_relocations(
    artifact: &Artifact,
    buffer: &mut [u8],
    base: usize,
    host_trampoline: usize,
) -> Result<(), RelocateError> {
    if buffer.len() < artifact.code.len() {
        return Err(RelocateError::BufferTooShort);
    }
    for relocation in &artifact.relocations {
        let offset = usize::try_from(relocation.offset).map_err(|_| RelocateError::Overflow)?;
        let site = base.checked_add(offset).ok_or(RelocateError::Overflow)?;
        let target = target_address(artifact, relocation.target, base, host_trampoline)?;
        let resolved = (target as i128)
            .checked_add(i128::from(relocation.addend))
            .ok_or(RelocateError::Overflow)?;
        match relocation.kind {
            RelocKind::Abs4 => {
                let value = u32::try_from(resolved).map_err(|_| RelocateError::OutOfRange)?;
                patch(buffer, offset, &value.to_le_bytes()[..4])?;
            }
            RelocKind::Abs8 => {
                let value = u64::try_from(resolved).map_err(|_| RelocateError::OutOfRange)?;
                patch(buffer, offset, &value.to_le_bytes())?;
            }
            RelocKind::PcRel4 | RelocKind::CallPcRel4 | RelocKind::CallPltRel4 => {
                let displacement = resolved - (site as i128);
                let value = i32::try_from(displacement).map_err(|_| RelocateError::OutOfRange)?;
                patch(buffer, offset, &value.to_le_bytes())?;
            }
        }
    }
    Ok(())
}

/// Resolves the absolute address a relocation target denotes.
fn target_address(
    artifact: &Artifact,
    target: RelocTarget,
    base: usize,
    host_trampoline: usize,
) -> Result<usize, RelocateError> {
    let relative = match target {
        RelocTarget::Function { index } => function_offset(artifact, index)?,
        RelocTarget::FunctionOffset { index, offset } => {
            let function = function_offset(artifact, index)?;
            let offset = usize::try_from(offset).map_err(|_| RelocateError::Overflow)?;
            function
                .checked_add(offset)
                .ok_or(RelocateError::Overflow)?
        }
        RelocTarget::HostTrampoline => return Ok(host_trampoline),
    };
    base.checked_add(relative).ok_or(RelocateError::Overflow)
}

/// Returns the byte offset of a function within the code blob.
fn function_offset(artifact: &Artifact, index: u32) -> Result<usize, RelocateError> {
    let offset = artifact
        .function_offsets
        .get(&index)
        .copied()
        .ok_or(RelocateError::UnknownFunction { index })?;
    usize::try_from(offset).map_err(|_| RelocateError::Overflow)
}

/// Copies `bytes` into `buffer` at `offset`, checking bounds.
fn patch(buffer: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), RelocateError> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(RelocateError::Overflow)?;
    let destination = buffer
        .get_mut(offset..end)
        .ok_or(RelocateError::BufferTooShort)?;
    destination.copy_from_slice(bytes);
    Ok(())
}
