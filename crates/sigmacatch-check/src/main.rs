// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Cross-platform regression validation tool.
//!
//! Loads Sigma rules and regression data, replays each stored event through
//! the detection engine, and reports whether the expected rule still matches.
//! Works on both Linux and Windows — no platform-specific collectors required.

use std::collections::HashSet;

use serde::Serialize;
use serde_json::{Map, Value as JsonValue};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_rule::{SigmaFilterConfig, SigmahqRules};
use sigmacatch_types::Event;
use uuid::Uuid;

#[derive(Serialize)]
struct CheckFail {
    rule_name: String,
    error: String,
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut product = String::from("windows");
    let mut json_output = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--product" => {
                i += 1;
                product = args[i].clone();
            }
            "--json" => json_output = true,
            "--help" | "-h" => {
                println!(
                    "sigmacatch-check — validate regression data against loaded rules\n\n\
                    Usage: sigmacatch-check [OPTIONS]\n\n\
                    Options:\n\
                      --product <product>  Filter rules by product (default: windows)\n\
                      --json               Output results as JSON\n\
                      --help, -h           Print this help and exit"
                );
                return Ok(());
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return Ok(());
            }
        }
        i += 1;
    }

    let rules = SigmahqRules::new()?;
    let rules = rules.filter(SigmaFilterConfig {
        product,
        ..Default::default()
    });

    let regression = SigmahqRegression::new()?;
    if regression.is_empty() {
        eprintln!("No regression entries found — nothing to validate");
        std::process::exit(1);
    }

    let mut engine = DetectionEngine::new(&rules)?;

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut failed: Vec<CheckFail> = Vec::new();

    for idx in 0..regression.len() {
        let entry = match regression.get_entry(idx) {
            Some(e) => e,
            None => {
                total += 1;
                if !json_output {
                    println!("[FAIL] No entry");
                }
                continue;
            }
        };

        let raw = match regression.get_raw_data(idx) {
            Some(r) => r,
            None => {
                total += 1;
                failed.push(CheckFail {
                    rule_name: entry.rule_name.clone(),
                    error: "No raw data".to_string(),
                });
                if !json_output {
                    println!("[FAIL] No raw data");
                }
                continue;
            }
        };

        let events: Vec<Event> = match entry.logtype {
            sigmacatch_regression::logtype::LogType::Evtx => {
                match input_windows_evtx::parse_evtx_bytes(&raw) {
                    Ok(evts) => evts,
                    Err(e) => {
                        total += 1;
                        failed.push(CheckFail {
                            rule_name: entry.rule_name.clone(),
                            error: format!("EVTX parse error: {e}"),
                        });
                        if !json_output {
                            println!("[FAIL] EVTX parse error: {e}");
                        }
                        continue;
                    }
                }
            }
            sigmacatch_regression::logtype::LogType::Log => parse_auditd_lines(&raw),
            sigmacatch_regression::logtype::LogType::Json => parse_json_lines(&raw),
            sigmacatch_regression::logtype::LogType::Raw => {
                total += 1;
                failed.push(CheckFail {
                    rule_name: entry.rule_name.clone(),
                    error: "Raw logtype not supported".to_string(),
                });
                if !json_output {
                    println!("[FAIL] Raw logtype not supported");
                }
                continue;
            }
        };

        if events.is_empty() {
            total += 1;
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: "EMPTY — no events produced from raw data".to_string(),
            });
            if !json_output {
                println!("[FAIL] EMPTY — no events produced from raw data");
            }
            continue;
        }

        engine.put_events(events);
        engine.process_events();
        let alerts = engine.get_alerts();
        let matched_ids: HashSet<Uuid> = alerts.iter().map(|a| a.rule_id).collect();

        if !matched_ids.contains(&entry.rule_id) {
            let matched: Vec<String> = matched_ids.iter().map(|s| s.to_string()).collect();
            total += 1;
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: format!(
                    "RULE NOT MATCHED — expected '{}' ({} alert(s), matched: {})",
                    entry.rule_id,
                    alerts.len(),
                    matched.join(", ")
                ),
            });
            if !json_output {
                println!(
                    "[FAIL] RULE NOT MATCHED — expected '{}' ({} alert(s), matched: {})",
                    entry.rule_id,
                    alerts.len(),
                    matched.join(", ")
                );
            }
            continue;
        }

        let rule_alert_count = alerts.iter().filter(|a| a.rule_id == entry.rule_id).count();
        if rule_alert_count < 1 {
            total += 1;
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: "MATCH COUNT MISMATCH — expected >= 1 (got 0)".to_string(),
            });
            if !json_output {
                println!("[FAIL] MATCH COUNT MISMATCH — expected >= 1 (got 0)");
            }
            continue;
        }

        total += 1;
        passed += 1;
        if !json_output {
            println!("[PASS] {} alert(s), rule matched", rule_alert_count);
        }
    }

    let pass_rate = if total > 0 {
        (passed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    if json_output {
        let output = serde_json::json!({
            "total": total,
            "passed": passed,
            "skipped": 0,
            "failed_count": failed.len(),
            "pass_rate": pass_rate,
            "failed": failed,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .expect("serde_json Value serialization is infallible")
        );
    } else {
        println!("\n{}", "=".repeat(60));
        println!("  VALIDATION SUMMARY");
        println!("{}", "=".repeat(60));
        println!("  Total entries:   {}", total);
        println!("  Passed:          {}", passed);
        println!("  Failed:          {}", failed.len());
        println!("  Pass rate:       {:.1}%", pass_rate);
        println!("{}", "=".repeat(60));
        if !failed.is_empty() {
            println!("\nFailed rules:");
            for f in &failed {
                println!("  FAIL {} — {}", f.rule_name, f.error);
            }
        }
    }

    if !failed.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

fn parse_auditd_lines(raw: &[u8]) -> Vec<Event> {
    use linux_audit_parser::Parser;

    let parser = Parser {
        enriched: true,
        split_msg: false,
    };

    raw.split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let message = parser.parse(line).ok()?;
            let mut fields = Map::new();
            for (key, value) in &message.body {
                if let Some(json) = value_to_json(value) {
                    fields.insert(key.to_string(), json);
                }
            }
            let json_raw = serde_json::json!({
                "stamp": { "timestamp": message.id.timestamp, "sequence": message.id.sequence },
                "type": message.ty.to_string(),
                "fields": fields,
            });
            let mut flat = Map::new();
            for (key, value) in &fields {
                flat.insert(key.clone(), value.clone());
            }
            flat.insert("type".into(), JsonValue::String(message.ty.to_string()));
            flat.insert("provider".into(), JsonValue::String("auditd".into()));
            flat.insert("product".into(), JsonValue::String("linux".into()));
            flat.insert("service".into(), JsonValue::String("auditd".into()));
            let mut event = Event::new(json_raw, JsonValue::Object(flat), line.to_vec());
            event.inject_logsource_fields_for("linux", Some("auditd"));
            Some(event)
        })
        .collect()
}

fn value_to_json(value: &linux_audit_parser::Value<'_>) -> Option<JsonValue> {
    use linux_audit_parser::Value as AuditValue;
    match value {
        AuditValue::Empty => Some(JsonValue::String(String::new())),
        AuditValue::Str(bytes, _) => Some(JsonValue::String(
            String::from_utf8_lossy(bytes).into_owned(),
        )),
        AuditValue::Owned(bytes) => Some(JsonValue::String(
            String::from_utf8_lossy(bytes.as_slice()).into_owned(),
        )),
        AuditValue::Number(n) => Some(JsonValue::String(n.to_string())),
        AuditValue::List(items) | AuditValue::StringifiedList(items) => {
            let arr: Vec<JsonValue> = items.iter().filter_map(value_to_json).collect();
            if arr.is_empty() {
                None
            } else {
                Some(JsonValue::Array(arr))
            }
        }
        AuditValue::Map(pairs) => {
            let mut map = Map::new();
            for (k, v) in pairs {
                if let Some(json) = value_to_json(v) {
                    map.insert(k.to_string(), json);
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(JsonValue::Object(map))
            }
        }
        AuditValue::Literal(s) => Some(JsonValue::String((*s).to_string())),
        AuditValue::Segments(_) | AuditValue::Skipped(_) => None,
    }
}

fn parse_json_lines(raw: &[u8]) -> Vec<Event> {
    raw.split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let value: JsonValue = serde_json::from_slice(line).ok()?;
            let mut event = Event::new(value.clone(), value, line.to_vec());
            event.inject_logsource_fields();
            Some(event)
        })
        .collect()
}
