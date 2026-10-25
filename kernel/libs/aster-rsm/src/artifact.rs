// SPDX-License-Identifier: MPL-2.0

//! Decodes the serialized machine-code artifact produced by `rsm-jit`.
//!
//! The byte layout is little-endian throughout and mirrors
//! `rsm_jit::artifact::MachineArtifact::to_bytes`:
//!
//! ```text
//! magic "RSMPIC\0\0" (8) | version u32 | requires_host u32
//! code_len u32 | function_count u32 | relocation_count u32 | entry_count u32
//! code [u8; code_len]
//! functions: (index u32, offset u32) * function_count
//! relocations: (offset u32, kind u8, pad[3], addend i64,
//!               target_kind u8, pad[3], index u32, target_offset u32) * N
//! entries: (name_len u32, name bytes, code_offset u32,
//!           native_peak u64, body_frame u64, thunk_frame u64) * entry_count
//! ```

use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// The ABI and layout revision this decoder understands.
pub const INTERFACE_VERSION: u32 = 1;

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
    HostTrampoline,
}

impl RelocTarget {
    fn from_bytes(kind: u8, index: u32, offset: u32) -> Option<Self> {
        Some(match kind {
            0 => Self::Function { index },
            1 => Self::FunctionOffset { index, offset },
            2 => Self::HostTrampoline,
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
    pub code: Vec<u8>,
    pub function_offsets: BTreeMap<u32, u32>,
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
        if reader.u32()? != INTERFACE_VERSION {
            return Err(DecodeError::Malformed);
        }
        let requires_host = reader.u32()? != 0;
        let code_len = reader.u32()? as usize;
        let function_count = reader.u32()? as usize;
        let relocation_count = reader.u32()? as usize;
        let entry_count = reader.u32()? as usize;

        let code = reader.bytes(code_len)?.to_vec();

        let mut function_offsets = BTreeMap::new();
        for _ in 0..function_count {
            let index = reader.u32()?;
            let offset = reader.u32()?;
            function_offsets.insert(index, offset);
        }

        let mut relocations = Vec::with_capacity(relocation_count);
        for _ in 0..relocation_count {
            let offset = reader.u32()?;
            let kind = RelocKind::from_byte(reader.bytes(1)?[0]).ok_or(DecodeError::Malformed)?;
            reader.skip(3)?;
            let addend = reader.i64()?;
            let target_kind = reader.bytes(1)?[0];
            reader.skip(3)?;
            let index = reader.u32()?;
            let target_offset = reader.u32()?;
            let target = RelocTarget::from_bytes(target_kind, index, target_offset)
                .ok_or(DecodeError::Malformed)?;
            relocations.push(Relocation {
                offset,
                kind,
                addend,
                target,
            });
        }

        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let name_len = reader.u32()? as usize;
            let name = core::str::from_utf8(reader.bytes(name_len)?)
                .map_err(|_| DecodeError::Malformed)?
                .into();
            let code_offset = reader.u32()?;
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
            code,
            function_offsets,
            relocations,
            entries,
            requires_host,
        })
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
