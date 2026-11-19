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
    UnknownData { index: u32 },
}

/// Patches the code in `buffer` for an image that will reside at `base`.
///
/// The caller must already have staged the image with [`Artifact::write_image`].
/// `host_trampoline` supplies the external helper address and is only
/// consulted for [`RelocTarget::HostTrampoline`] targets.
pub fn apply_relocations(
    artifact: &Artifact,
    buffer: &mut [u8],
    base: usize,
    host_trampoline: usize,
) -> Result<(), RelocateError> {
    if buffer.len() < artifact.image_len() {
        return Err(RelocateError::BufferTooShort);
    }
    if !base.is_multiple_of(artifact.alignment) {
        return Err(RelocateError::OutOfRange);
    }
    // Relocations patch instruction bytes, even when their target is data.
    let code = buffer
        .get_mut(..artifact.code.len())
        .ok_or(RelocateError::BufferTooShort)?;
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
                patch(code, offset, &value.to_le_bytes())?;
            }
            RelocKind::Abs8 => {
                let value = u64::try_from(resolved).map_err(|_| RelocateError::OutOfRange)?;
                patch(code, offset, &value.to_le_bytes())?;
            }
            RelocKind::PcRel4 | RelocKind::CallPcRel4 | RelocKind::CallPltRel4 => {
                let displacement = resolved - (site as i128);
                let value = i32::try_from(displacement).map_err(|_| RelocateError::OutOfRange)?;
                patch(code, offset, &value.to_le_bytes())?;
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
        RelocTarget::Function { index } => function_offset(artifact, index, 0)?,
        RelocTarget::FunctionOffset { index, offset } => function_offset(artifact, index, offset)?,
        RelocTarget::Data { index } => {
            let offset = artifact
                .data_offsets
                .get(&index)
                .ok_or(RelocateError::UnknownData { index })?;
            artifact
                .data_offset
                .checked_add(*offset as usize)
                .ok_or(RelocateError::Overflow)?
        }
        RelocTarget::HostTrampoline => return Ok(host_trampoline),
    };
    base.checked_add(relative).ok_or(RelocateError::Overflow)
}

/// Returns the byte offset of a function within the code blob.
fn function_offset(
    artifact: &Artifact,
    index: u32,
    inner_offset: u32,
) -> Result<usize, RelocateError> {
    let offset = artifact
        .function_offsets
        .get(&index)
        .copied()
        .ok_or(RelocateError::UnknownFunction { index })?;
    let target = offset
        .checked_add(inner_offset)
        .ok_or(RelocateError::Overflow)? as usize;
    if target >= artifact.code.len() {
        return Err(RelocateError::OutOfRange);
    }
    Ok(target)
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
