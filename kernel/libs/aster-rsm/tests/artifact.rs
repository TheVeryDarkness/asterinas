// SPDX-License-Identifier: MPL-2.0

//! Host-runnable tests for the artifact decoder and relocation application.

use std::collections::BTreeMap;

use aster_rsm::{Artifact, DecodeError, RelocTarget, RelocateError, apply_relocations};

fn relocation(bytes: &mut Vec<u8>, site: u32, kind: u8, addend: i64, target: (u8, u32, u32)) {
    let (tag, index, offset) = target;
    bytes.extend_from_slice(&site.to_le_bytes());
    bytes.extend_from_slice(&[kind, 0, 0, 0]);
    bytes.extend_from_slice(&addend.to_le_bytes());
    bytes.extend_from_slice(&[tag, 0, 0, 0]);
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.extend_from_slice(&offset.to_le_bytes());
}

/// Builds a v1 code-only artifact with a host call and two functions.
fn fixture_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"RSMPIC\0\0");
    out.extend_from_slice(&1u32.to_le_bytes()); // version
    out.extend_from_slice(&1u32.to_le_bytes()); // requires_host
    out.extend_from_slice(&32u32.to_le_bytes()); // code_len
    out.extend_from_slice(&2u32.to_le_bytes()); // function_count
    out.extend_from_slice(&3u32.to_le_bytes()); // relocation_count
    out.extend_from_slice(&1u32.to_le_bytes()); // entry_count
    out.extend_from_slice(&[0x90; 32]); // code (nops)
    out.extend_from_slice(&0u32.to_le_bytes()); // fn[0].index
    out.extend_from_slice(&0u32.to_le_bytes()); // fn[0].offset
    out.extend_from_slice(&1u32.to_le_bytes()); // fn[1].index
    out.extend_from_slice(&8u32.to_le_bytes()); // fn[1].offset
    relocation(&mut out, 0, 3, -4, (0, 1, 0)); // CallPcRel4, Function{1}
    relocation(&mut out, 4, 3, -4, (1, 1, 16)); // CallPcRel4, FunctionOffset{1, 16}
    relocation(&mut out, 8, 1, 0, (2, 0, 0)); // Abs8, v1 HostTrampoline
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
    assert_eq!(artifact.code.len(), 32);
    assert_eq!(artifact.function_offsets, BTreeMap::from([(0, 0), (1, 8)]));
    assert_eq!(artifact.relocations.len(), 3);
    assert!(artifact.requires_host);
    assert_eq!(artifact.interface_version, 1);
    assert_eq!(artifact.image_len(), artifact.code.len());

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
    let artifact = Artifact::from_bytes(&fixture_bytes()).unwrap();
    let mut buffer = artifact.code.clone();
    apply_relocations(&artifact, &mut buffer, 0x2000, 0x7000).expect("relocate");
    // (function 1 at 8 + inner offset 16 - addend bias 4) - site 4.
    assert_eq!(&buffer[4..8], &16i32.to_le_bytes());
    assert_eq!(&buffer[8..16], &0x7000u64.to_le_bytes());
}

/// Builds the v2 wire layout emitted by Rssembly with an aligned data section.
fn v2_fixture() -> Vec<u8> {
    let mut bytes = b"RSMPIC\0\0".to_vec();
    for field in [
        2u32, 1, // version, requires_host
        16, 12, 5, 16, // alignment, code_len, data_len, data_offset
        0, 1, 2, 0, // counts for functions, data objects, relocations, entries
    ] {
        bytes.extend_from_slice(&field.to_le_bytes());
    }
    bytes.extend_from_slice(&[0x90; 12]);
    bytes.extend_from_slice(b"hello");
    bytes.extend_from_slice(&7u32.to_le_bytes()); // data object index
    bytes.extend_from_slice(&2u32.to_le_bytes()); // offset in data
    relocation(&mut bytes, 0, 2, -4, (2, 7, 0)); // PcRel4, Data{7}
    relocation(&mut bytes, 4, 1, 0, (3, 0, 0)); // Abs8, v2 HostTrampoline
    bytes
}

#[test]
fn places_and_relocates_v2_code_and_data() {
    let artifact = Artifact::from_bytes(&v2_fixture()).unwrap();
    assert_eq!(artifact.interface_version, 2);
    assert_eq!(artifact.alignment, 16);
    assert_eq!(artifact.image_len(), 21);
    let mut image = [0xff; 32];
    artifact.write_image(&mut image).unwrap();
    apply_relocations(&artifact, &mut image, 0x2000, 0x7000).unwrap();
    assert_eq!(&image[..4], &14i32.to_le_bytes()); // (16 + 2 - 4) - 0
    assert_eq!(&image[4..12], &0x7000u64.to_le_bytes());
    assert_eq!(&image[12..16], &[0; 4]);
    assert_eq!(&image[16..21], b"hello");
    assert_eq!(&image[21..], &[0xff; 11]);
}

#[test]
fn rejects_invalid_v2_layout_and_truncated_tables() {
    for (field, invalid_value) in [
        (8, 3u32), // unknown version
        (16, 0),
        (16, 3), // invalid alignment
        (28, 8),
        (28, 32),       // overlap or excessive padding
        (40, u32::MAX), // more relocation records than bytes
        (44, u32::MAX), // more entry records than bytes
        (69, 6),        // data object outside the five-byte data blob
    ] {
        let mut bytes = v2_fixture();
        bytes[field..field + 4].copy_from_slice(&invalid_value.to_le_bytes());
        assert_eq!(Artifact::from_bytes(&bytes), Err(DecodeError::Malformed));
    }
    let mut bytes = fixture_bytes();
    let entry_offset = bytes.len() - 28;
    bytes[entry_offset..entry_offset + 4].copy_from_slice(&32u32.to_le_bytes());
    assert_eq!(Artifact::from_bytes(&bytes), Err(DecodeError::Malformed));
}

#[test]
fn rejects_v2_patch_outside_code_and_missing_data_object() {
    let mut artifact = Artifact::from_bytes(&v2_fixture()).unwrap();
    let mut image = [0xff; 32];
    artifact.write_image(&mut image).unwrap();
    assert_eq!(
        apply_relocations(&artifact, &mut image, 1, 0),
        Err(RelocateError::OutOfRange),
    );
    artifact.relocations[0].offset = 10; // Four-byte patch straddles the code boundary.
    assert_eq!(
        apply_relocations(&artifact, &mut image, 16, 0),
        Err(RelocateError::BufferTooShort),
    );
    artifact.relocations[0].offset = 0;
    artifact.relocations[0].target = RelocTarget::Data { index: 2 };
    assert_eq!(
        apply_relocations(&artifact, &mut image, 16, 0),
        Err(RelocateError::UnknownData { index: 2 }),
    );
    assert_eq!(&image[16..21], b"hello");
}
