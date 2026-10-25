// SPDX-License-Identifier: MPL-2.0

//! Host-runnable tests for the artifact decoder and relocation application.

use std::collections::BTreeMap;

use aster_rsm::{Artifact, DecodeError, RelocKind, RelocTarget, Relocation, apply_relocations};

/// Builds a minimal, valid artifact byte stream with two functions, one
/// `CallPcRel4` relocation, and one `main` entry.
fn fixture_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"RSMPIC\0\0");
    out.extend_from_slice(&1u32.to_le_bytes()); // version
    out.extend_from_slice(&0u32.to_le_bytes()); // requires_host
    out.extend_from_slice(&8u32.to_le_bytes()); // code_len
    out.extend_from_slice(&2u32.to_le_bytes()); // function_count
    out.extend_from_slice(&1u32.to_le_bytes()); // relocation_count
    out.extend_from_slice(&1u32.to_le_bytes()); // entry_count
    out.extend_from_slice(&[0x90; 8]); // code (nops)
    out.extend_from_slice(&0u32.to_le_bytes()); // fn[0].index
    out.extend_from_slice(&0u32.to_le_bytes()); // fn[0].offset
    out.extend_from_slice(&1u32.to_le_bytes()); // fn[1].index
    out.extend_from_slice(&8u32.to_le_bytes()); // fn[1].offset
    // Relocation: offset 0, CallPcRel4, addend -4, target Function{1}.
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(3); // CallPcRel4
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&(-4i64).to_le_bytes());
    out.push(0); // Function
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    // Entry "main".
    let name = b"main";
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&0u32.to_le_bytes()); // code_offset
    out.extend_from_slice(&16u64.to_le_bytes()); // native_peak_bytes
    out.extend_from_slice(&8u64.to_le_bytes()); // body_frame_bytes
    out.extend_from_slice(&12u64.to_le_bytes()); // thunk_frame_bytes
    out
}

#[test]
fn decodes_an_artifact() {
    let artifact = Artifact::from_bytes(&fixture_bytes()).expect("decode");
    assert_eq!(artifact.code.len(), 8);
    assert_eq!(artifact.function_offsets, BTreeMap::from([(0, 0), (1, 8)]));
    assert_eq!(artifact.relocations.len(), 1);
    assert!(!artifact.requires_host);

    let entry = artifact.entry("main").expect("main entry");
    assert_eq!(entry.code_offset, 0);
    assert_eq!(entry.native_peak_bytes, 16);
    assert_eq!(entry.body_frame_bytes, 8);
    assert_eq!(entry.thunk_frame_bytes, 12);
}

#[test]
fn rejects_bad_magic() {
    let mut bytes = fixture_bytes();
    bytes[0] = b'X';
    assert_eq!(Artifact::from_bytes(&bytes), Err(DecodeError::Malformed));
}

#[test]
fn applies_call_relocation() {
    let artifact = Artifact::from_bytes(&fixture_bytes()).expect("decode");
    let mut buffer = artifact.code.clone();
    // Function{1} at +8, addend -4, base 0x1000:
    // pcrel = (0x1000 + 8 - 4) - 0x1000 = 4.
    apply_relocations(&artifact, &mut buffer, 0x1000, 0).expect("relocate");
    assert_eq!(&buffer[0..4], &4i32.to_le_bytes());
}

#[test]
fn applies_function_offset_and_trampoline_relocations() {
    let artifact = Artifact {
        code: vec![0; 16],
        function_offsets: BTreeMap::from([(0, 0), (1, 16)]),
        relocations: vec![
            Relocation {
                offset: 0,
                kind: RelocKind::CallPcRel4,
                addend: -4,
                target: RelocTarget::FunctionOffset {
                    index: 1,
                    offset: 8,
                },
            },
            Relocation {
                offset: 4,
                kind: RelocKind::Abs8,
                addend: 0,
                target: RelocTarget::HostTrampoline,
            },
        ],
        entries: vec![],
        requires_host: true,
    };
    let mut buffer = vec![0u8; 16];
    apply_relocations(&artifact, &mut buffer, 0x2000, 0x7000).expect("relocate");
    // FunctionOffset{1,8}: target 0x2000+16+8 = 0x2028, resolved 0x2024, site 0x2000.
    assert_eq!(&buffer[0..4], &20i32.to_le_bytes());
    // HostTrampoline: value 0x7000 + 0.
    assert_eq!(&buffer[4..12], &0x7000u64.to_le_bytes());
}
