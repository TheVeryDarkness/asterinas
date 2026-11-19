// SPDX-License-Identifier: MPL-2.0

//! Decodes the serialized machine-code artifact produced by `rsm-jit`.
//!
//! The byte layout is little-endian throughout and mirrors
//! `rsm_jit::artifact::MachineArtifact::to_bytes`:
//!
//! ```text
//! magic "RSMPIC\0\0" (8) | version u32 | requires_host u32
//! v1: code_len u32 | function_count u32
//! v2: alignment u32 | code_len u32 | data_len u32 | data_offset u32 |
//!     function_count u32 | data_object_count u32
//! relocation_count u32 | entry_count u32
//! code [u8; code_len] | data [u8; data_len] (v2 only)
//! functions: (index u32, offset u32) * function_count
//! data objects (v2 only): (index u32, offset u32) * data_object_count
//! relocations: (offset u32, kind u8, pad[3], addend i64,
//!               target_kind u8, pad[3], index u32, target_offset u32) * N
//! entries: (name_len u32, name bytes, code_offset u32,
//!           native_peak u64, body_frame u64, thunk_frame u64) * entry_count
//! ```

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::ops::RangeBounds;

use crate::reloc::RelocateError;

/// The current Rssembly artifact ABI and layout revision.
pub const INTERFACE_VERSION: u32 = 2;

const MAGIC: &[u8; 8] = b"RSMPIC\0\0";

/// The x86-64 relocation encodings an artifact can contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocKind {
    Abs4,
    Abs8,
    PcRel4,
    CallPcRel4,
    CallPltRel4,
}

impl RelocKind {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Abs4,
            1 => Self::Abs8,
            2 => Self::PcRel4,
            3 => Self::CallPcRel4,
            4 => Self::CallPltRel4,
            _ => return None,
        })
    }
}

/// What a relocation resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocTarget {
    Function { index: u32 },
    FunctionOffset { index: u32, offset: u32 },
    Data { index: u32 },
    HostTrampoline,
}

impl RelocTarget {
    fn from_bytes(version: u32, kind: u8, index: u32, offset: u32) -> Option<Self> {
        Some(match (version, kind) {
            (_, 0) => Self::Function { index },
            (_, 1) => Self::FunctionOffset { index, offset },
            (2, 2) => Self::Data { index },
            (1, 2) | (2, 3) => Self::HostTrampoline,
            _ => return None,
        })
    }
}

/// A single relocation the loader must apply at its placement base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    pub offset: u32,
    pub kind: RelocKind,
    pub addend: i64,
    pub target: RelocTarget,
}

/// A callable entry and its native resource requirements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub code_offset: u32,
    pub native_peak_bytes: usize,
    pub body_frame_bytes: usize,
    pub thunk_frame_bytes: usize,
}

/// A decoded, relocatable machine-code artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub interface_version: u32,
    /// Required alignment of the image base.
    pub alignment: usize,
    pub code: Vec<u8>,
    data: Vec<u8>,
    pub(crate) data_offset: usize,
    pub function_offsets: BTreeMap<u32, u32>,
    pub(crate) data_offsets: BTreeMap<u32, u32>,
    pub relocations: Vec<Relocation>,
    pub entries: Vec<Entry>,
    pub requires_host: bool,
}

impl Artifact {
    /// Decodes an artifact produced by `MachineArtifact::to_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);

        if reader.bytes(8)? != MAGIC {
            return Err(DecodeError::Malformed);
        }
        let interface_version = reader.u32()?;
        if !matches!(interface_version, 1 | 2) {
            return Err(DecodeError::Malformed);
        }
        let requires_host = reader.u32()? != 0;
        let alignment = if interface_version == 2 {
            reader.u32()? as usize
        } else {
            1
        };
        if !alignment.is_power_of_two() {
            return Err(DecodeError::Malformed);
        }
        let code_len = reader.u32()? as usize;
        let (data_len, data_offset) = if interface_version == 2 {
            (reader.u32()? as usize, reader.u32()? as usize)
        } else {
            (0, code_len)
        };
        // The emitter aligns the data section only when it contains bytes.
        // Reject arbitrary gaps before the loader reserves memory for the image.
        let expected_offset = if data_len == 0 {
            code_len
        } else {
            code_len
                .checked_next_multiple_of(alignment)
                .ok_or(DecodeError::Malformed)?
        };
        if data_offset != expected_offset || data_offset.checked_add(data_len).is_none() {
            return Err(DecodeError::Malformed);
        }
        let function_count = reader.u32()? as usize;
        let data_object_count = if interface_version == 2 {
            reader.u32()? as usize
        } else {
            0
        };
        let relocation_count = reader.u32()? as usize;
        let entry_count = reader.u32()? as usize;

        let code = reader.bytes(code_len)?.to_vec();
        let data = reader.bytes(data_len)?.to_vec();
        let function_offsets = reader.offsets(function_count, ..code_len)?;
        // A zero-sized data object can start at the very end of the section.
        let data_offsets = reader.offsets(data_object_count, ..=data_len)?;

        // Grow both tables as records are consumed. Counts in a truncated
        // header must not translate directly into kernel allocations.
        let mut relocations = Vec::new();
        for _ in 0..relocation_count {
            let offset = reader.u32()?;
            let kind = RelocKind::from_byte(reader.bytes(1)?[0]).ok_or(DecodeError::Malformed)?;
            reader.skip(3)?;
            let addend = reader.i64()?;
            let target_kind = reader.bytes(1)?[0];
            reader.skip(3)?;
            let index = reader.u32()?;
            let target_offset = reader.u32()?;
            let target =
                RelocTarget::from_bytes(interface_version, target_kind, index, target_offset)
                    .ok_or(DecodeError::Malformed)?;
            relocations.push(Relocation {
                offset,
                kind,
                addend,
                target,
            });
        }

        let mut entries = Vec::new();
        for _ in 0..entry_count {
            let name_len = reader.u32()? as usize;
            let name = core::str::from_utf8(reader.bytes(name_len)?)
                .map_err(|_| DecodeError::Malformed)?
                .into();
            let code_offset = reader.u32()?;
            if code_offset as usize >= code_len {
                return Err(DecodeError::Malformed);
            }
            let native_peak_bytes = reader.u64()? as usize;
            let body_frame_bytes = reader.u64()? as usize;
            let thunk_frame_bytes = reader.u64()? as usize;
            entries.push(Entry {
                name,
                code_offset,
                native_peak_bytes,
                body_frame_bytes,
                thunk_frame_bytes,
            });
        }

        if !reader.is_consumed() {
            return Err(DecodeError::Malformed);
        }

        Ok(Self {
            interface_version,
            alignment,
            code,
            data,
            data_offset,
            function_offsets,
            data_offsets,
            relocations,
            entries,
            requires_host,
        })
    }

    /// Returns the number of bytes occupied by code, alignment padding, and data.
    pub fn image_len(&self) -> usize {
        self.data_offset + self.data.len()
    }

    /// Copies the code and read-only data to their positions in the staged image.
    pub fn write_image(&self, buffer: &mut [u8]) -> Result<(), RelocateError> {
        let image = buffer
            .get_mut(..self.image_len())
            .ok_or(RelocateError::BufferTooShort)?;
        let (code_and_padding, data) = image.split_at_mut(self.data_offset);
        let (code, padding) = code_and_padding
            .split_at_mut_checked(self.code.len())
            .ok_or(RelocateError::BufferTooShort)?;
        code.copy_from_slice(&self.code);
        padding.fill(0);
        data.copy_from_slice(&self.data);
        Ok(())
    }

    /// Returns the entry with the given name.
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.name == name)
    }
}

/// Reports why decoding failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytes are truncated, have a bad magic, or an unsupported version.
    Malformed,
}

/// Reads little-endian fields from a byte slice.
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(DecodeError::Malformed)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(DecodeError::Malformed)?;
        self.position = end;
        Ok(slice)
    }

    fn skip(&mut self, len: usize) -> Result<(), DecodeError> {
        self.bytes(len).map(|_| ())
    }

    fn offsets(
        &mut self,
        count: usize,
        valid_offsets: impl RangeBounds<usize>,
    ) -> Result<BTreeMap<u32, u32>, DecodeError> {
        let mut offsets = BTreeMap::new();
        for _ in 0..count {
            let index = self.u32()?;
            let offset = self.u32()?;
            if !valid_offsets.contains(&(offset as usize))
                || offsets.insert(index, offset).is_some()
            {
                return Err(DecodeError::Malformed);
            }
        }
        Ok(offsets)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(
            self.bytes(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(
            self.bytes(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(
            self.bytes(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn is_consumed(&self) -> bool {
        self.position == self.bytes.len()
    }
}
