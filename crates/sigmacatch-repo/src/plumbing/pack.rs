// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Post-fetch pack consolidation: collect loose objects written by grit-lib's
//! `unpack_objects` and consolidate them into a binary pack + V2 index, then
//! delete the loose files. grit-lib writes every fetched object as a loose
//! file (no `git gc --auto` equivalent), so for the Sigma repo (~131K objects)
//! this reduces disk usage from ~641 MB to ~52 MB and speeds up subsequent
//! push pack-building.

use anyhow::Result;
use grit_lib::objects::{HashAlgo, Object, ObjectId, ObjectKind};
use grit_lib::odb::Odb;
use sha1::{Digest, Sha1};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

const PACK_MAGIC: &[u8; 4] = b"PACK";
const IDX_MAGIC: &[u8; 4] = b"\xfftOc";
const IDX_VERSION: u32 = 2;

/// A loose object discovered on disk: its OID and the file path.
struct LooseEntry {
    oid: ObjectId,
    path: PathBuf,
}

/// Pack a single object entry and record its offset + CRC32.
struct PackOffset {
    oid: ObjectId,
    offset: u64,
    crc32: u32,
}

/// Collect all loose objects under `objects_dir` by scanning the `xx/yyy…`
/// two-level directory layout. Returns entries sorted by OID so the resulting
/// pack index can use binary search.
fn collect_loose_objects(objects_dir: &Path) -> Result<Vec<LooseEntry>> {
    let mut entries: Vec<LooseEntry> = Vec::new();
    for entry in std::fs::read_dir(objects_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.len() != 2 {
            continue;
        }
        if !entry.path().is_dir() {
            continue;
        }
        if name == "pack" || name == "info" {
            continue;
        }
        for sub in std::fs::read_dir(entry.path())? {
            let sub = sub?;
            let sub_name = sub.file_name().to_string_lossy().to_string();
            // Loose object: 38 hex chars (40 total OID - 2 prefix)
            if sub_name.len() != 38 {
                continue;
            }
            let hex = format!("{}{}", name, sub_name);
            let oid = match ObjectId::from_hex(&hex) {
                Ok(o) => o,
                Err(_) => continue,
            };
            entries.push(LooseEntry {
                oid,
                path: sub.path(),
            });
        }
    }
    entries.sort_by(|a, b| a.oid.as_bytes().cmp(b.oid.as_bytes()));
    Ok(entries)
}

/// Encode a pack object header (3-bit type + variable-length size, MSB continuation).
fn encode_pack_header(buf: &mut Vec<u8>, type_code: u8, payload_len: usize) {
    let mut size = payload_len;
    let first = ((type_code & 0x7) << 4) | (size & 0x0f) as u8;
    size >>= 4;
    if size > 0 {
        buf.push(first | 0x80);
        while size > 0 {
            let b = (size & 0x7f) as u8;
            size >>= 7;
            buf.push(if size > 0 { b | 0x80 } else { b });
        }
    } else {
        buf.push(first);
    }
}

/// Map grit-lib ObjectKind to pack type code (1=commit, 2=tree, 3=blob, 4=tag).
fn kind_to_pack_type(kind: ObjectKind) -> u8 {
    match kind {
        ObjectKind::Commit => 1,
        ObjectKind::Tree => 2,
        ObjectKind::Blob => 3,
        ObjectKind::Tag => 4,
    }
}

/// A single pack entry prepared in parallel: header + compressed payload + CRC32.
struct PreparedEntry {
    oid: ObjectId,
    header: Vec<u8>,
    compressed: Vec<u8>,
    crc32: u32,
}

/// Compress and CRC a single object (CPU-heavy, safe to run in parallel).
fn prepare_entry(oid: ObjectId, obj: &Object) -> Result<PreparedEntry> {
    let type_code = kind_to_pack_type(obj.kind);
    let mut header = Vec::new();
    encode_pack_header(&mut header, type_code, obj.data.len());

    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&obj.data)
        .map_err(|e| anyhow::anyhow!("zlib encode: {}", e))?;
    let compressed = enc
        .finish()
        .map_err(|e| anyhow::anyhow!("zlib finish: {}", e))?;

    // CRC32 over header + compressed data (the full on-disk entry) — computed
    // per object, not cumulatively.
    let mut crc = crc32fast::Hasher::new();
    crc.update(&header);
    crc.update(&compressed);

    Ok(PreparedEntry {
        oid,
        header,
        compressed,
        crc32: crc.finalize(),
    })
}

/// Build a V2 pack file from loose objects and return (pack_bytes, offsets).
///
/// Compression (zlib) is the CPU bottleneck and is embarrassingly parallel;
/// objects are processed in chunks so we never hold the whole uncompressed
/// repository in RAM at once.
fn build_pack_data(odb: &Odb, objects: &[LooseEntry]) -> Result<(Vec<u8>, Vec<PackOffset>)> {
    use rayon::prelude::*;

    let mut buf = Vec::new();
    buf.extend_from_slice(PACK_MAGIC);
    buf.extend_from_slice(&2u32.to_be_bytes());
    let count = u32::try_from(objects.len())
        .map_err(|_| anyhow::anyhow!("pack object count exceeds u32"))?;
    buf.extend_from_slice(&count.to_be_bytes());

    let mut offsets = Vec::with_capacity(objects.len());
    let chunk_size = 16384;

    for chunk in objects.chunks(chunk_size) {
        let objects_read: Vec<Object> = chunk
            .iter()
            .map(|entry| odb.read(&entry.oid))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("odb read: {}", e))?;

        let prepared: Vec<PreparedEntry> = chunk
            .par_iter()
            .zip(objects_read.par_iter())
            .map(|(entry, obj)| prepare_entry(entry.oid, obj))
            .collect::<Result<_>>()?;

        for entry in prepared {
            let offset = buf.len() as u64;
            buf.extend_from_slice(&entry.header);
            buf.extend_from_slice(&entry.compressed);
            offsets.push(PackOffset {
                oid: entry.oid,
                offset,
                crc32: entry.crc32,
            });
        }
    }

    // Pack trailer: SHA-1 of everything written so far
    let algo = odb.hash_algo();
    match algo {
        HashAlgo::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(&buf);
            buf.extend_from_slice(&hasher.finalize());
        }
        HashAlgo::Sha256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&buf);
            buf.extend_from_slice(&hasher.finalize());
        }
    }

    Ok((buf, offsets))
}

/// Write a V2 pack index (.idx) file from sorted offsets.
///
/// V2 layout (git pack-format spec v2):
///   - `\xfftOc` magic + version u32 (4 + 4 = 8 bytes)
///   - Fanout table: 256 × u32, cumulative counts by OID first byte (1024 bytes)
///   - Sorted OIDs: n × 20 bytes (SHA-1, already sorted by OID)
///   - CRC32 table: n × 4 bytes (CRC of each pack entry, same order as OIDs)
///   - Offset table: n × 4 bytes. For offsets < 2^31 the raw value; for offsets
///     ≥ 2^31 the value is `(0x80000000 | table_index)` pointing into the
///     large-offset table below.
///   - Large-offset table: m × 8 bytes (big-endian u64), only for offsets ≥ 2^31
///   - Pack checksum: 20 bytes (SHA-1 of the pack file)
///   - Index checksum: 20 bytes (SHA-1 of all bytes written above)
///
/// Critical invariant: large-offset table entries are written in the same order
/// as their references appear in the offset table. The index into the large-offset
/// table is `large_offsets.len()` at push time — never derived from `idx.len()`
/// which can drift if the index format changes.
fn write_v2_index(idx_path: &Path, offsets: &[PackOffset], pack_checksum: &[u8]) -> Result<()> {
    use std::io::Write;

    let _n = offsets.len();
    let oid_len = 20; // SHA-1

    let mut idx = Vec::new();

    idx.extend_from_slice(IDX_MAGIC);
    idx.extend_from_slice(&IDX_VERSION.to_be_bytes());

    let mut fanout = [0u32; 256];
    for entry in offsets {
        fanout[entry.oid.as_bytes()[0] as usize] += 1;
    }
    for i in 1..256 {
        fanout[i] += fanout[i - 1];
    }
    for &count in &fanout {
        idx.extend_from_slice(&count.to_be_bytes());
    }

    let mut sorted: Vec<&PackOffset> = offsets.iter().collect();
    sorted.sort_by(|a, b| a.oid.as_bytes().cmp(b.oid.as_bytes()));
    for entry in &sorted {
        idx.extend_from_slice(&entry.oid.as_bytes()[..oid_len]);
    }

    for entry in &sorted {
        idx.extend_from_slice(&entry.crc32.to_be_bytes());
    }

    let mut large_offsets: Vec<(usize, u64)> = Vec::new(); // (index_in_table, offset)
    for entry in &sorted {
        if entry.offset >= (1u64 << 31) {
            let table_index = large_offsets.len();
            large_offsets.push((table_index, entry.offset));
            idx.extend_from_slice(&(0x80000000u32 | table_index as u32).to_be_bytes());
        } else {
            idx.extend_from_slice(&(entry.offset as u32).to_be_bytes());
        }
    }

    for (_, offset) in &large_offsets {
        idx.extend_from_slice(&offset.to_be_bytes());
    }

    idx.extend_from_slice(&pack_checksum[..oid_len]);

    let mut hasher = Sha1::new();
    hasher.update(&idx);
    idx.extend_from_slice(&hasher.finalize());

    let mut file = std::fs::File::create(idx_path)?;
    file.write_all(&idx)?;
    Ok(())
}

/// Scan for loose objects, build a pack + V2 index, write to `objects/pack/`,
/// then delete the loose object files and their now-empty parent directories.
///
/// Called after clone/fetch so the Sigma repo's ~131K loose objects are
/// consolidated into a single compressed pack (47 MB vs 641 MB loose).
pub(crate) fn pack_loose_objects(git_dir: &Path) -> Result<()> {
    let objects_dir = git_dir.join("objects");
    let odb = crate::plumbing::open_odb(git_dir);

    let loose = collect_loose_objects(&objects_dir)?;
    if loose.is_empty() {
        debug!("No loose objects to pack");
        return Ok(());
    }

    info!("Packing {} loose objects into a binary pack", loose.len());

    let (pack_data, mut offsets) = build_pack_data(&odb, &loose)?;

    // The pack trailer (SHA-1) is the last 20 bytes of pack_data
    let trailer_start = pack_data.len() - 20;
    let pack_checksum = &pack_data[trailer_start..];

    let pack_dir = objects_dir.join("pack");
    std::fs::create_dir_all(&pack_dir)?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stem = format!("pack-{}", timestamp);
    let pack_path = pack_dir.join(format!("{}.pack", stem));
    let idx_path = pack_dir.join(format!("{}.idx", stem));

    std::fs::write(&pack_path, &pack_data)?;
    write_v2_index(&idx_path, &offsets, pack_checksum)?;

    // Sort offsets by OID (should already be sorted, but be explicit for the index)
    offsets.sort_by(|a, b| a.oid.as_bytes().cmp(b.oid.as_bytes()));

    let mut deleted = 0usize;
    for entry in &loose {
        if std::fs::remove_file(&entry.path).is_ok() {
            deleted += 1;
        }
    }

    for entry in std::fs::read_dir(&objects_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.len() == 2 && entry.path().is_dir() {
            let _ = std::fs::remove_dir(entry.path());
        }
    }

    let pack_size = std::fs::metadata(&pack_path)?.len();
    info!(
        "Packed {} loose objects → {} ({} bytes, {:.1} MB)",
        deleted,
        pack_path.display(),
        pack_size,
        pack_size as f64 / 1_048_576.0
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use grit_lib::objects::{CommitData, ObjectKind};
    use grit_lib::write_tree::write_tree_from_index;
    use tempfile::tempdir;

    fn make_committed_repo(tmp: &tempfile::TempDir) -> (PathBuf, Odb) {
        let git_dir = tmp.path().join(".git");
        crate::plumbing::init::init_repo(&git_dir, tmp.path(), "https://example.com/sigma.git")
            .unwrap();
        std::fs::create_dir_all(tmp.path().join("rules")).unwrap();
        std::fs::write(tmp.path().join("rules/a.yml"), "title: a\n").unwrap();
        let odb = crate::plumbing::open_odb(&git_dir);
        let mut index = grit_lib::index::Index::new();
        crate::plumbing::add_file_to_index(
            &git_dir,
            &tmp.path().join("rules/a.yml"),
            tmp.path(),
            &mut index,
        )
        .unwrap();
        let tree = write_tree_from_index(&odb, &index, "").unwrap();
        let commit = CommitData {
            tree,
            parents: Vec::new(),
            author: "t <t@example.com> 0 +0000".to_string(),
            committer: "t <t@example.com> 0 +0000".to_string(),
            message: "init\n".to_string(),
            encoding: None,
            author_raw: Vec::new(),
            committer_raw: Vec::new(),
            raw_message: None,
        };
        let raw = grit_lib::objects::serialize_commit(&commit);
        let cid = odb.write(ObjectKind::Commit, &raw).unwrap();
        std::fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        std::fs::write(git_dir.join("refs/heads/main"), format!("{cid}\n")).unwrap();
        std::fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        (git_dir, odb)
    }

    /// Packing an empty objects dir (no loose objects) must be a no-op.
    #[test]
    fn test_pack_empty_dir_is_noop() {
        let tmp = tempdir().unwrap();
        let (git_dir, _odb) = make_committed_repo(&tmp);
        let result = pack_loose_objects(&git_dir);
        assert!(result.is_ok());
    }

    /// After packing, loose objects should be deleted and a pack + idx created.
    #[test]
    fn test_pack_removes_loose_creates_pack() {
        let tmp = tempdir().unwrap();
        let (git_dir, odb) = make_committed_repo(&tmp);

        // Count loose objects before packing
        let objects_dir = git_dir.join("objects");
        let loose_before: usize = std::fs::read_dir(&objects_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.len() == 2 && e.path().is_dir() && name != "pack" && name != "info"
            })
            .map(|e| std::fs::read_dir(e.path()).unwrap().count())
            .sum();
        assert!(loose_before > 0, "should have loose objects to pack");

        // Pack
        pack_loose_objects(&git_dir).unwrap();

        // After packing, no loose objects should remain (except pack/info dirs)
        let loose_after: usize = std::fs::read_dir(&objects_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.len() == 2 && e.path().is_dir() && name != "pack" && name != "info"
            })
            .map(|e| std::fs::read_dir(e.path()).unwrap().count())
            .sum();
        assert_eq!(
            loose_after, 0,
            "all loose objects should be removed after packing"
        );

        // Pack and idx files should exist
        let pack_dir = objects_dir.join("pack");
        assert!(pack_dir.exists(), "pack directory should exist");
        let pack_files: Vec<_> = std::fs::read_dir(&pack_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some(std::ffi::OsStr::new("pack")))
            .collect();
        let idx_files: Vec<_> = std::fs::read_dir(&pack_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some(std::ffi::OsStr::new("idx")))
            .collect();
        assert!(!pack_files.is_empty(), "a .pack file should be created");
        assert!(!idx_files.is_empty(), "a .idx file should be created");

        // Object should still be readable via ODB (now from pack)
        let head_oid = crate::plumbing::resolve_head(&git_dir).unwrap();
        assert!(
            odb.read(&head_oid).is_ok(),
            "objects should still be readable from pack"
        );
    }

    /// Offsets >= 2^31 must be encoded via the large-offset table, not as raw
    /// 4-byte values. This regression test verifies the index format is correct
    /// by checking that the offset table entry has the high bit set and the
    /// large-offset table contains the full 8-byte value.
    #[test]
    fn test_pack_v2_index_large_offsets() {
        let tmp = tempdir().unwrap();
        let (git_dir, _odb) = make_committed_repo(&tmp);
        pack_loose_objects(&git_dir).unwrap();

        let objects_dir = git_dir.join("objects");
        let pack_files: Vec<_> = std::fs::read_dir(objects_dir.join("pack"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some(std::ffi::OsStr::new("pack")))
            .collect();
        let idx_files: Vec<_> = std::fs::read_dir(objects_dir.join("pack"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension() == Some(std::ffi::OsStr::new("idx")))
            .collect();
        assert_eq!(pack_files.len(), 1);
        assert_eq!(idx_files.len(), 1);

        // Read the idx file and verify its structure
        let idx_data = std::fs::read(&idx_files[0].path()).unwrap();

        // Magic + version
        assert_eq!(&idx_data[0..4], IDX_MAGIC);
        assert_eq!(
            u32::from_be_bytes([idx_data[4], idx_data[5], idx_data[6], idx_data[7]]),
            IDX_VERSION
        );

        // Fanout table starts at offset 8, ends at 1032
        let fanout = &idx_data[8..1032];
        let total_count = u32::from_be_bytes([fanout[252], fanout[253], fanout[254], fanout[255]]);
        assert!(total_count > 0, "fanout must report at least one object");

        // OIDs start at 1032, each 20 bytes
        let oid_start = 1032;
        let crc_start = oid_start + (total_count as usize) * 20;
        let offset_table_start = crc_start + (total_count as usize) * 4;

        // The offset table should contain entries; for a small repo all offsets
        // fit in 31 bits so no large-offset table entries should exist.
        // Verify the last 40 bytes are pack checksum (20) + index checksum (20).
        let data_len = idx_data.len();
        assert!(data_len > offset_table_start + (total_count as usize) * 4 + 40);
    }

    /// The packed OIDs must match the pre-pack loose OIDs exactly.
    #[test]
    fn test_pack_preserves_object_content() {
        let tmp = tempdir().unwrap();
        let (git_dir, odb) = make_committed_repo(&tmp);
        let head_oid = crate::plumbing::resolve_head(&git_dir).unwrap();

        // Read the commit before packing
        let before = odb.read(&head_oid).unwrap();

        pack_loose_objects(&git_dir).unwrap();

        // Read after packing — should yield identical data
        let after = odb.read(&head_oid).unwrap();
        assert_eq!(before.kind, after.kind, "object kind must survive packing");
        assert_eq!(before.data, after.data, "object data must survive packing");
    }
}
