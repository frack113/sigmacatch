// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Smoke test for the sigmacatch kernel sensor (feature `driver`, Windows).
//!
//! Opens `\\.\sigmacatch`, reports the protocol version, then drains the ring
//! once a second for eight seconds, printing each record and the Sysmon-schema
//! event it maps to. Run it on a machine with the driver loaded:
//!
//! ```text
//! cargo xwin build --release --examples --features driver -p sigmacatch
//! etw_driver_probe.exe
//! ```

#[cfg(not(windows))]
fn main() {
    eprintln!("etw_driver_probe is Windows-only");
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use std::time::Duration;

    use sigmacatch::inputs::etw_driver::{Device, Mapper};

    let Some(device) = Device::open() else {
        anyhow::bail!("\\\\.\\sigmacatch not available (is the driver loaded?)");
    };
    println!("driver version: {:?}", device.version());

    let mut mapper = Mapper::new();
    for second in 1..=8 {
        let mut events = Vec::new();
        let count = device.read_events(&mut events)?;
        if count == 0 {
            println!("t={second}s: no events");
        }
        for event in &events {
            let image = String::from_utf16_lossy(
                &event.primary[..(event.primary_length as usize).min(event.primary.len())],
            );
            let command_line = String::from_utf16_lossy(
                &event.secondary[..(event.secondary_length as usize).min(event.secondary.len())],
            );
            println!(
                "t={second}s kind={} pid={} parent={} image={image} command={command_line}",
                event.kind, event.pid, event.parent_pid
            );
            if let Some(mapped) = mapper.map(event) {
                println!("  -> {}", serde_json::to_string(&*mapped.event_json_raw)?);
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}
