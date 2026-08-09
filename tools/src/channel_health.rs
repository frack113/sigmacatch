// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! channel_health: Windows-only diagnostic tool to check event channel health.
//!
//! On Windows (cfg(windows)): queries each resolved channel via Winevt API,
//! reports event counts, last event time, and channel status.
//!
//! On non-Windows: prints a stub message and exits 0.
//!
//! Usage:
//!   cargo run --release --bin channel_health [--json] [--channel <name>]

#[cfg(windows)]
use windows::Win32::System::EventLog::{EvtClose, EvtNext, EvtOpenChannelEnum, EvtQuery};

use sigmacatch_config::Config;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_rule::SigmahqRules;
use std::path::PathBuf;
use std::process;

#[derive(serde::Serialize)]
struct ChannelHealth {
    name: String,
    enabled: bool,
    event_count: u64,
    last_event_time: Option<String>,
    path: String,
    status: String,
}

#[derive(serde::Serialize)]
struct ChannelHealthReport {
    channels: Vec<ChannelHealth>,
    total_channels: usize,
    enabled_channels: usize,
    total_events: u64,
}

fn main() {
    let mut _json_output = false;
    let mut _channel_filter: Option<String> = None;
    for arg in std::env::args().skip(1) {
        if arg == "--json" {
            _json_output = true;
        } else if arg.starts_with("--channel") {
            _channel_filter = arg.strip_prefix("--channel=").map(|s| s.to_string());
        }
    }

    let config = match Config::load(&PathBuf::from("config.yaml")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config.yaml: {}", e);
            process::exit(1);
        }
    };

    let rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules from ./sigma: {}", e);
            process::exit(1);
        }
    };
    let rules = rules.filter(config.filter.clone());

    if rules.is_empty() {
        eprintln!("0 rules loaded — adjust filter.* in config.yaml");
        process::exit(1);
    }

    let engine = match DetectionEngine::new(&rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {}", e);
            process::exit(1);
        }
    };

    let custom_map = sigmacatch_config::load_custom_channel_mapping(
        PathBuf::from("custom_channels.yaml").as_path(),
    );
    let cycle_channels = engine.resolve_channels(&custom_map);

    if cycle_channels.is_empty() {
        eprintln!("0 channels resolved — nothing to check");
        process::exit(1);
    }

    #[cfg(windows)]
    {
        let report = check_channels_windows(&cycle_channels, _channel_filter.as_deref());
        if _json_output || !cfg!(not(windows)) {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        } else {
            print_report_text(&report);
        }
    }

    #[cfg(not(windows))]
    {
        let report = ChannelHealthReport {
            channels: cycle_channels
                .iter()
                .map(|name| ChannelHealth {
                    name: name.clone(),
                    enabled: false,
                    event_count: 0,
                    last_event_time: None,
                    path: name.clone(),
                    status: "stub (non-Windows)".to_string(),
                })
                .collect(),
            total_channels: cycle_channels.len(),
            enabled_channels: 0,
            total_events: 0,
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
}

#[cfg(windows)]
fn check_channels_windows(channels: &[String], filter: Option<&str>) -> ChannelHealthReport {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::System::EventLog::{EvtClose, EvtNext, EvtOpenChannelEnum, EvtQuery};

    let mut results: Vec<ChannelHealth> = Vec::new();
    let mut total_events: u64 = 0;

    // Query each channel directly for health info
    for channel_name in channels {
        let mut health = ChannelHealth {
            name: channel_name.clone(),
            enabled: false,
            event_count: 0,
            last_event_time: None,
            path: channel_name.clone(),
            status: "unknown".to_string(),
        };

        // Try to open the channel to check if it exists and is enabled
        let wname: Vec<u16> = OsStr::new(channel_name)
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let query = format!(r#"*[System/Channel='{}']"#, channel_name);
        let wquery: Vec<u16> = OsStr::new(&query).encode_utf16().chain(Some(0)).collect();

        unsafe {
            // Try to open the channel
            match windows::Win32::System::EventLog::EvtOpenChannelEnum(Some(wname.as_ptr()), 0) {
                Ok(ch_handle) => {
                    health.enabled = true;
                    health.status = "ok".to_string();

                    // Query events to count them (sample first 1000)
                    match windows::Win32::System::EventLog::EvtQuery(
                        None,
                        wquery.as_ptr(),
                        wquery.as_ptr(),
                        0,
                    ) {
                        Ok(query_handle) => {
                            let mut event_count: u32 = 0;
                            let mut events = [0isize; 1];
                            let mut returned = 0u32;
                            loop {
                                events.fill(0);
                                returned = 0;
                                let rc = windows::Win32::System::EventLog::EvtNext(
                                    query_handle,
                                    &mut events,
                                    1000,
                                    0,
                                    &mut returned,
                                );
                                if rc.is_err() || returned == 0 {
                                    break;
                                }
                                event_count += 1;
                                if event_count >= 1000 {
                                    break;
                                }
                                if events[0] != 0 {
                                    unsafe {
                                        windows::Win32::System::EventLog::EvtClose(events[0])
                                    };
                                }
                            }
                            health.event_count = event_count as u64;
                            total_events += event_count as u64;
                            health.status = format!("ok ({} events sampled)", event_count);
                        }
                        Err(_) => {
                            health.status = "query_failed".to_string();
                        }
                    }
                    EvtClose(ch_handle);
                }
                Err(_) => {
                    health.status = "not_found".to_string();
                }
            }
        }

        results.push(health);
    }

    let enabled_count = results.iter().filter(|c| c.enabled).count();

    ChannelHealthReport {
        channels: results,
        total_channels: channels.len(),
        enabled_channels: enabled_count,
        total_events,
    }
}

#[cfg(windows)]
fn print_report_text(report: &ChannelHealthReport) {
    println!("\n{}", "=".repeat(70));
    println!("  CHANNEL HEALTH REPORT");
    println!("{}", "=".repeat(70));
    println!("  Total channels:    {}", report.total_channels);
    println!("  Enabled channels:  {}", report.enabled_channels);
    println!("  Total events:      {}", report.total_events);
    println!("{}", "=".repeat(70));

    for ch in &report.channels {
        let icon = if ch.enabled { "✓" } else { "✗" };
        println!(
            "  {} {:<40} events={} status={}",
            icon, ch.name, ch.event_count, ch.status
        );
    }
    println!("{}", "=".repeat(70));
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_coverage_structures_compile() {
        // Ensure the types compile
        let _ = super::ChannelHealth {
            name: "test".to_string(),
            enabled: true,
            event_count: 0,
            last_event_time: None,
            path: "test".to_string(),
            status: "ok".to_string(),
        };
    }
}
