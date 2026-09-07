// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors
//! Golden byte-for-byte test: verifies `write_evtx_from_xml` output is
//! identical to the reference fixture generated from the baseline code.

use std::path::Path;

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn golden_output_is_byte_identical() {
    let xml =
        std::fs::read_to_string(Path::new(CARGO_MANIFEST_DIR).join("tests/fixtures/sample.xml"))
            .unwrap();
    let golden =
        std::fs::read(Path::new(CARGO_MANIFEST_DIR).join("tests/fixtures/sample.evtx")).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.evtx");
    sigmacatch_evtx_writer::write_evtx_from_xml(&xml, 1, &path).unwrap();

    let written = std::fs::read(&path).unwrap();
    assert_eq!(
        written.len(),
        golden.len(),
        "size mismatch: written {} vs golden {}",
        written.len(),
        golden.len()
    );
    if written != golden {
        for (i, (a, b)) in written.iter().zip(golden.iter()).enumerate() {
            if a != b {
                panic!(
                    "byte mismatch at offset {i} (0x{i:04x}): written=0x{a:02x} golden=0x{b:02x}"
                );
            }
        }
    }
}
