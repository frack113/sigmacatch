use std::fs;

fn main() {
    let path = "sigma/regression_data/rules/windows/process_creation/proc_creation_win_renamed_curl/7530cd3d-7671-43e3-b209-976966f6ea48.evtx";
    let data = fs::read(path).unwrap();
    println!("File size: {} bytes", data.len());

    // Check file header
    println!("File header magic: {:?}", &data[0..8]);
    println!(
        "First chunk at: {}",
        u32::from_le_bytes(data[0x20..0x24].try_into().unwrap())
    );

    // Chunk header at 0x1000
    let chunk = &data[0x1000..];
    println!("Chunk magic: {:?}", &chunk[0..8]);
    let first_rec_no = u64::from_le_bytes(chunk[0x08..0x10].try_into().unwrap());
    let last_rec_no = u64::from_le_bytes(chunk[0x10..0x18].try_into().unwrap());
    println!("First rec: {}, Last rec: {}", first_rec_no, last_rec_no);

    // Try to find record at offset 0x1200 (from our hex analysis)
    let rec_offset: usize = 0x1200;
    let rec = &data[rec_offset..];
    println!("\nRecord at 0x{:x}:", rec_offset);
    let magic = u32::from_le_bytes(rec[0..4].try_into().unwrap());
    let size = u32::from_le_bytes(rec[4..8].try_into().unwrap());
    let rec_id = u64::from_le_bytes(rec[8..16].try_into().unwrap());
    let ts = u64::from_le_bytes(rec[16..24].try_into().unwrap());
    println!(
        "  magic: 0x{:08x}, size: {}, rec_id: {}, ts: {}",
        magic, size, rec_id, ts
    );

    // BinXML starts at offset 24
    let binxml = &rec[24..size as usize - 4]; // -4 for trailing size
    println!("\nBinXML payload: {} bytes", binxml.len());

    // Dump first 64 bytes as hex
    let dump_len = binxml.len().min(256);
    println!("First {} bytes:", dump_len);
    for (i, chunk) in binxml[..dump_len].chunks(16).enumerate() {
        print!("  {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        println!();
    }

    // Check trailing size
    let trailing_size =
        u32::from_le_bytes(rec[size as usize - 4..size as usize].try_into().unwrap());
    println!("\nTrailing size: {} (expected: {})", trailing_size, size);

    // Dump strings in the BinXML payload
    println!("\nUTF-16LE strings in BinXML:");
    let mut i = 0;
    while i < binxml.len() - 2 {
        // Look for UTF-16LE strings (alternating non-zero/null bytes)
        if binxml[i] == 0 && binxml[i + 1] != 0 && i + 2 < binxml.len() {
            let start = i + 1;
            let mut end = start;
            while end + 1 < binxml.len() {
                if binxml[end] != 0 && binxml[end + 1] == 0 {
                    end += 2;
                } else if binxml[end] == 0 && binxml[end + 1] == 0 {
                    break;
                } else {
                    break;
                }
            }
            if end - start >= 4 {
                let s: Vec<u16> = binxml[start..end]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                if let Ok(s) = String::from_utf16(&s) {
                    if s.len() >= 2
                        && s.chars().all(|c| {
                            c.is_ascii()
                                || c == '/'
                                || c == ':'
                                || c == '.'
                                || c == '_'
                                || c == '\\'
                        })
                    {
                        println!("  0x{:04x}: \"{}\"", i, s);
                    }
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
}
