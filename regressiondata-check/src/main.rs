// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Cross-platform regression validation tool.
//!
//! Loads Sigma rules and regression data, replays each stored event through
//! the detection engine, and reports whether the expected rule still matches.
//! Works on both Linux and Windows — no platform-specific collectors required.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value as JsonValue};
use sigmacatch_detection::DetectionEngine;
use sigmacatch_regression::SigmahqRegression;
use sigmacatch_rule::SigmahqRules;
use sigmacatch_types::Event;
use uuid::Uuid;

#[derive(Serialize)]
struct CheckFail {
    rule_name: String,
    error: String,
}

const HELP: &str = "regressiondata-check — validate regression data against loaded rules\n\
    \n\
    Usage: regressiondata-check [OPTIONS]\n\
    \n\
    Options:\n\
      --json        Output results as JSON\n\
      --ignore      Skip invalid entries without counting them\n\
      --fix         Normalize JSON trailing newlines and info.yml indentation\n\
      --path <DIR>  Root of the sigma repository (default: ./sigma)\n\
      --help, -h    Print this help and exit";

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    let mut json_output = false;
    let mut ignore_invalid = false;
    let mut fix = false;
    let mut sigma_path = PathBuf::from("./sigma");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_output = true,
            "--ignore" => ignore_invalid = true,
            "--fix" => fix = true,
            "--path" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing value for --path\n\n{HELP}");
                    std::process::exit(1);
                }
                i += 1;
                let value = args[i].as_str();
                if value.is_empty() || value.starts_with('-') {
                    eprintln!("Invalid value for --path: expected a directory path\n\n{HELP}");
                    std::process::exit(1);
                }
                sigma_path = PathBuf::from(value);
            }
            "--help" | "-h" => {
                println!("{HELP}");
                return Ok(());
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return Ok(());
            }
        }
        i += 1;
    }

    if fix {
        let regression = SigmahqRegression::new_from_path(&sigma_path.join("regression_data"))?;
        fix_json_newlines(&regression)?;
        return Ok(());
    }

    let rules = SigmahqRules::new_from_path(&sigma_path)?;

    let regression = SigmahqRegression::new_from_path(&sigma_path.join("regression_data"))?;
    if regression.is_empty() {
        eprintln!("No regression entries found — nothing to validate");
        std::process::exit(1);
    }

    // Bidirectional regression_tests_path validation.
    // Direction 1: each entry → rule must exist and declare a matching path.
    // Direction 2: each rule with regression_tests_path → entry must exist.
    let path_validation = validate_regression_paths(&rules, &regression, json_output);
    let missing_path = path_validation.missing_path;
    let mismatched_path = path_validation.mismatched_path;

    if missing_path > 0 && !json_output {
        eprintln!("[FAIL] {} missing regression_tests_path(s)", missing_path);
    }
    if mismatched_path > 0 && !json_output {
        eprintln!(
            "[FAIL] {} mismatched regression_tests_path(s)",
            mismatched_path
        );
    }

    // Upstream SigmaHQ ships rules with non-v4 ids; we generate v4, so this
    // only warns and never fails.
    let mut warnings: Vec<String> = Vec::new();
    for entry in regression.entries() {
        if entry.rule_id.get_version_num() != 4 {
            let msg = format!(
                "{} rule id {} is not a UUID v4 (version {})",
                entry.rule_name,
                entry.rule_id,
                entry.rule_id.get_version_num()
            );
            if !json_output {
                eprintln!("[WARN] {msg}");
            }
            warnings.push(msg);
        }
    }

    let mut engine = DetectionEngine::new_lenient(&rules)?;

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut skipped = 0usize;
    let mut failed: Vec<CheckFail> = Vec::new();
    let mut dropped_audit_lines = 0usize;
    let mut ignored = 0usize;

    for idx in 0..regression.len() {
        let entry = match regression.get_entry(idx) {
            Some(e) => e,
            None => {
                if ignore_invalid {
                    ignored += 1;
                    if !json_output {
                        println!("[IGNORE] No entry");
                    }
                } else {
                    total += 1;
                    if !json_output {
                        println!("[FAIL] No entry");
                    }
                }
                continue;
            }
        };

        // Validate auxiliary JSON files for every declared rule: must exist
        // (if any), be valid JSON, and end with exactly one \n.
        let mut json_err = None;
        match regression.get_info(idx) {
            Some(info) if info.rule_metadata.is_empty() => {
                json_err = Some("rule_metadata is empty".to_string());
            }
            Some(info) => {
                for m in &info.rule_metadata {
                    if let Some(err) = validate_json_auxiliary(idx, &m.id, &regression) {
                        json_err = Some(err);
                        break;
                    }
                }
            }
            None => {}
        }
        if let Some(json_err) = json_err {
            total += 1;
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: json_err,
            });
            if !json_output {
                println!("[FAIL] JSON — {}", entry.rule_name);
            }
            continue;
        }

        // Validate info.yml indentation matches SigmaHQ 4-space style.
        if let Some(indent_err) = validate_yaml_indentation(idx, &regression) {
            total += 1;
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: indent_err,
            });
            if !json_output {
                println!("[FAIL] YAML indentation — {}", entry.rule_name);
            }
            continue;
        }

        // Detect info.yml with empty/commented regression_tests_info section.
        if regression.get_info(idx).is_some_and(|i| i.regression_tests_info.is_empty()) {
            let msg = "invalid info.yml — no regression_tests_info";
            if ignore_invalid {
                ignored += 1;
                if !json_output {
                    println!("[IGNORE] {msg} — {}", entry.rule_name);
                }
            } else {
                total += 1;
                failed.push(CheckFail {
                    rule_name: entry.rule_name.clone(),
                    error: msg.to_string(),
                });
                if !json_output {
                    println!("[FAIL] {msg} — {}", entry.rule_name);
                }
            }
            continue;
        }

        let raw = match regression.get_raw_data(idx) {
            Some(r) => r,
            None => {
                if ignore_invalid {
                    ignored += 1;
                    if !json_output {
                        println!("[IGNORE] No raw data");
                    }
                } else {
                    total += 1;
                    failed.push(CheckFail {
                        rule_name: entry.rule_name.clone(),
                        error: "No raw data".to_string(),
                    });
                    if !json_output {
                        println!("[FAIL] No raw data");
                    }
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
            sigmacatch_regression::logtype::LogType::Log => {
                let (events, dropped) = parse_auditd_lines(&raw);
                dropped_audit_lines += dropped;
                events
            }
            sigmacatch_regression::logtype::LogType::Json => parse_json_lines(&raw),
            sigmacatch_regression::logtype::LogType::Raw => {
                skipped += 1;
                if !json_output {
                    println!("[SKIP] Raw logtype — skipped");
                }
                total += 1;
                continue;
            }
        };

        if events.is_empty() {
            if ignore_invalid {
                ignored += 1;
                if !json_output {
                    println!("[IGNORE] No events produced from raw data");
                }
            } else {
                total += 1;
                failed.push(CheckFail {
                    rule_name: entry.rule_name.clone(),
                    error: "EMPTY — no events produced from raw data".to_string(),
                });
                if !json_output {
                    println!("[FAIL] EMPTY — no events produced from raw data");
                }
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

        // Validate the declared match_count against the actual hit count when a
        // JSON auxiliary file is present alongside the data. The JSON mirrors
        // the raw event, so its hit count must equal info.yml's match_count.
        let expected = regression
            .get_info(idx)
            .and_then(|info| info.regression_tests_info.first())
            .map(|t| t.match_count)
            .unwrap_or(0);
        let json_present = regression.get_json_data(idx).is_some();
        if json_present && expected > 0 && rule_alert_count != expected {
            total += 1;
            let msg = format!(
                "MATCH COUNT MISMATCH — expected {} hit(s), got {}",
                expected, rule_alert_count
            );
            failed.push(CheckFail {
                rule_name: entry.rule_name.clone(),
                error: msg,
            });
            if !json_output {
                println!(
                    "[FAIL] {}",
                    failed.last().expect("failed entry just pushed").error
                );
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
        (passed as f64 / (total + skipped) as f64) * 100.0
    } else {
        0.0
    };

    let path_failures = missing_path + mismatched_path;
    if json_output {
        let output = serde_json::json!({
            "total": total,
            "passed": passed,
            "skipped": skipped,
            "ignored": ignored,
            "missing_path": missing_path,
            "mismatched_path": mismatched_path,
            "failed_count": failed.len(),
            "pass_rate": pass_rate,
            "failed": failed,
            "warning_count": warnings.len(),
            "warnings": warnings,
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
        if missing_path > 0 {
            println!("  Missing paths:   {}", missing_path);
        }
        if mismatched_path > 0 {
            println!("  Mismatched:      {}", mismatched_path);
        }
        if ignored > 0 {
            println!("  Ignored:         {}", ignored);
        }
        if skipped > 0 {
            println!("  Skipped:         {}", skipped);
        }
        if dropped_audit_lines > 0 {
            println!("  Dropped lines:   {}", dropped_audit_lines);
        }
        if !warnings.is_empty() {
            println!("  Warnings:        {}", warnings.len());
        }
        println!("  Pass rate:       {:.1}%", pass_rate);
        println!("{}", "=".repeat(60));
        if missing_path > 0 || mismatched_path > 0 {
            println!("\nRegression path issues:");
            println!("  Missing paths:   {}", missing_path);
            println!("  Mismatched:      {}", mismatched_path);
        }
        if !failed.is_empty() {
            println!("\nFailed rules:");
            for f in &failed {
                println!("  FAIL {} — {}", f.rule_name, f.error);
            }
        }
    }

    if path_failures > 0 || !failed.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

struct PathValidation {
    missing_path: usize,
    mismatched_path: usize,
}

/// Bidirectional validation of `regression_tests_path` between rules and
/// regression entries. Returns counts of missing and mismatched paths.
fn validate_regression_paths(
    rules: &SigmahqRules,
    regression: &SigmahqRegression,
    json_output: bool,
) -> PathValidation {
    let sigma_root = regression.path().parent().unwrap_or(Path::new("./sigma"));
    let mut missing_path = 0usize;
    let mut mismatched_path = 0usize;

    for (info_path, _info, entry) in regression.iter_entries() {
        let Some(rule) = rules.get(&entry.rule_id) else {
            missing_path += 1;
            if !json_output {
                eprintln!("[FAIL] Rule {} not found in loaded rules", entry.rule_id);
            }
            continue;
        };
        let Some(rtp) = rule
            .custom_attributes
            .get("regression_tests_path")
            .and_then(|v| v.as_str())
        else {
            missing_path += 1;
            if !json_output {
                eprintln!(
                    "[FAIL] Rule {} missing or non-string regression_tests_path",
                    entry.rule_id
                );
            }
            continue;
        };
        let expected = sigma_root.join(rtp);
        if *info_path != expected {
            mismatched_path += 1;
            if !json_output {
                eprintln!(
                    "[FAIL] Rule {} regression_tests_path mismatch: '{}' ≠ '{}'",
                    entry.rule_id,
                    rtp,
                    info_path.display()
                );
            }
        }
    }

    let entry_paths: HashSet<&Path> = regression
        .iter_entries()
        .map(|(p, _, _)| p.as_path())
        .collect();
    for rule in rules.iter() {
        let Some(v) = rule.custom_attributes.get("regression_tests_path") else {
            continue;
        };
        let Some(rtp) = v.as_str() else {
            continue;
        };
        let full = sigma_root.join(rtp);
        if !full.exists() {
            mismatched_path += 1;
            if !json_output {
                eprintln!(
                    "[FAIL] Rule {} regression_tests_path points to missing file: {}",
                    rule.id.as_deref().unwrap_or("unknown"),
                    rtp
                );
            }
        } else if !entry_paths.contains(full.as_path()) {
            missing_path += 1;
            if !json_output {
                eprintln!(
                    "[FAIL] Rule {} regression_tests_path exists but no matching entry: {}",
                    rule.id.as_deref().unwrap_or("unknown"),
                    rtp
                );
            }
        }
    }

    PathValidation {
        missing_path,
        mismatched_path,
    }
}

fn parse_auditd_lines(raw: &[u8]) -> (Vec<Event>, usize) {
    use linux_audit_parser::Parser;

    let parser = Parser {
        enriched: true,
        split_msg: false,
    };

    let mut dropped = 0usize;
    let events: Vec<Event> = raw
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let message = match parser.parse(line) {
                Ok(m) => m,
                Err(_) => {
                    dropped += 1;
                    return None;
                }
            };
            let mut flat = Map::new();
            for (key, value) in &message.body {
                if let Some(json) = value_to_json(value) {
                    flat.insert(key.to_string(), json);
                }
            }
            let json_raw = serde_json::json!({
                "stamp": { "timestamp": message.id.timestamp, "sequence": message.id.sequence },
                "type": message.ty.to_string(),
                "fields": flat.clone(),
            });
            flat.insert("type".into(), JsonValue::String(message.ty.to_string()));
            flat.insert("provider".into(), JsonValue::String("auditd".into()));
            flat.insert("product".into(), JsonValue::String("linux".into()));
            flat.insert("service".into(), JsonValue::String("auditd".into()));
            let mut event = Event::new(json_raw, JsonValue::Object(flat), line.to_vec());
            event.inject_logsource_fields_for("linux", Some("auditd"));
            Some(event)
        })
        .collect();
    (events, dropped)
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

fn validate_json_auxiliary(
    idx: usize,
    rule_id: &Uuid,
    regression: &SigmahqRegression,
) -> Option<String> {
    let info_path = regression.get_info_path(idx)?;
    let json_path = info_path.parent()?.join(format!("{rule_id}.json"));
    if !json_path.exists() {
        return None;
    }
    let bytes = match std::fs::read(&json_path) {
        Ok(b) => b,
        Err(e) => return Some(format!("cannot read {}: {e}", json_path.display())),
    };
    if bytes.is_empty() {
        return Some(format!("empty file: {}", json_path.display()));
    }
    if bytes.last() != Some(&b'\n') {
        return Some(format!(
            "missing trailing newline in {}",
            json_path.display()
        ));
    }
    if bytes.len() >= 2 && bytes[bytes.len() - 2] == b'\n' {
        return Some(format!(
            "multiple trailing newlines in {}",
            json_path.display()
        ));
    }
    // Accepts both a single JSON object and JSONL (multiple objects).
    // `into_iter` yields one `Result` per value in the stream.
    for value in serde_json::Deserializer::from_slice(&bytes).into_iter::<serde_json::Value>() {
        if let Err(e) = value {
            return Some(format!("invalid JSON in {}: {e}", json_path.display()));
        }
    }
    None
}

fn validate_yaml_indentation(idx: usize, regression: &SigmahqRegression) -> Option<String> {
    let info_path = regression.get_info_path(idx)?.to_path_buf();
    let mut raw = match std::fs::read_to_string(&info_path) {
        Ok(s) => s,
        Err(e) => return Some(format!("cannot read {}: {e}", info_path.display())),
    };
    raw = raw
        .strip_prefix('\u{feff}')
        .map(|s| s.to_string())
        .unwrap_or(raw);

    // Re-parse from disk so the comparison is against the current file, not a
    // possibly stale in-memory copy.
    let info = match sigmacatch_regression::info::InfoYml::load(&info_path) {
        Ok(i) => i,
        Err(e) => return Some(format!("cannot parse {}: {e}", info_path.display())),
    };
    let canonical = match info.canonical_yaml() {
        Ok(c) => c,
        Err(e) => return Some(format!("cannot canonicalize {}: {e}", info_path.display())),
    };

    for (template, indent) in yaml_lines(&raw) {
        match canonical_indent(&canonical, &template) {
            Some(expected) if expected != indent => {
                return Some(format!(
                    "info.yml indentation not SigmaHQ 4-space style: {} ({:?})",
                    info_path.display(),
                    template
                ));
            }
            None => {
                return Some(format!(
                    "info.yml key not expected: {} ({:?})",
                    info_path.display(),
                    template
                ));
            }
            _ => {}
        }
    }
    None
}

/// Compact structural key of a YAML line, ignoring indent and value:
/// `(key, is_list_item)` from e.g. `    - id: x` → `("id", true)`.
fn yaml_template(line: &str) -> Option<(String, bool)> {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let is_list = t.starts_with('-') && (t.starts_with("- ") || t.len() == 1);
    let body = if is_list {
        t.trim_start_matches('-').trim_start()
    } else {
        t
    };
    let key = body.split(':').next().unwrap_or("").trim();
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), is_list))
}

/// `(template, indent)` pairs of a YAML document (comments/blank lines excluded).
fn yaml_lines(content: &str) -> Vec<((String, bool), usize)> {
    content
        .lines()
        .filter_map(|l| {
            let indent = l.len() - l.trim_start().len();
            yaml_template(l).map(|t| (t, indent))
        })
        .collect()
}

/// Canonical indent for a template in the canonical document.
fn canonical_indent(canonical: &str, template: &(String, bool)) -> Option<usize> {
    yaml_lines(canonical)
        .into_iter()
        .find(|(t, _)| t == template)
        .map(|(_, i)| i)
}

/// Whether any significant line's indent differs from canonical, requiring a fix.
fn needs_reindent(raw: &str, canonical: &str) -> bool {
    let canonical_lines = yaml_lines(canonical);
    yaml_lines(raw).into_iter().any(|(template, indent)| {
        canonical_lines
            .iter()
            .find(|(t, _)| *t == template)
            .map(|(_, i)| i != &indent)
            .unwrap_or(true)
    })
}

/// Re-indent a YAML document to canonical 4-space SigmaHQ style while
/// preserving `#` comment lines, blank lines, and values verbatim.
fn reindent_yaml(raw: &str, canonical: &str) -> String {
    let canonical_lines = yaml_lines(canonical);
    let mut out = Vec::new();
    for line in raw.lines() {
        let t = line.trim_start();
        if t.is_empty() || t.starts_with('#') {
            out.push(line.to_string());
            continue;
        }
        let Some((key, is_list)) = yaml_template(line) else {
            out.push(line.to_string());
            continue;
        };
        let indent = canonical_lines
            .iter()
            .find(|(t2, _)| *t2 == (key.clone(), is_list))
            .map(|(_, i)| *i)
            .unwrap_or(0);
        if is_list {
            // Dash at the canonical indent, content aligned two columns after.
            out.push(format!(
                "{}- {}",
                " ".repeat(indent),
                t.trim_start_matches('-').trim_start()
            ));
        } else {
            out.push(format!("{}{}", " ".repeat(indent), t));
        }
    }
    out.join("\n")
}

fn fix_json_newlines(regression: &SigmahqRegression) -> anyhow::Result<()> {
    let root = regression.path().to_path_buf();
    if !root.exists() {
        anyhow::bail!("Regression data directory not found: {}", root.display());
    }

    let mut fixed = 0usize;
    let mut total = 0usize;
    let mut yml_fixed = 0usize;

    // Only touch files that belong to known regression entries; unrelated
    // .json artifacts are left alone.
    let mut dirs: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for idx in 0..regression.len() {
        if let Some(info_path) = regression.get_info_path(idx)
            && let Some(parent) = info_path.parent()
        {
            dirs.insert(parent.to_path_buf());
        }
    }

    for dir in dirs {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("  [ERROR] Cannot read directory {}: {e}", dir.display());
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let fname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if path.is_dir() {
                continue;
            }
            let is_json = path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
            let is_info_yml = fname.eq_ignore_ascii_case("info.yml");
            if is_json {
                total += 1;
                let bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("  [ERROR] Cannot read {}: {e}", path.display());
                        continue;
                    }
                };
                if bytes.is_empty() {
                    continue;
                }
                let needs_fix = if bytes.last() != Some(&b'\n') {
                    Some("missing trailing newline")
                } else if bytes.len() >= 2 && bytes[bytes.len() - 2] == b'\n' {
                    Some("multiple trailing newlines")
                } else {
                    None
                };
                if let Some(reason) = needs_fix {
                    let mut trimmed = bytes;
                    while trimmed.last() == Some(&b'\n') {
                        trimmed.pop();
                    }
                    trimmed.push(b'\n');
                    match std::fs::write(&path, &trimmed) {
                        Ok(()) => {
                            fixed += 1;
                            println!("[FIX] {} ({reason})", path.display());
                        }
                        Err(e) => {
                            eprintln!("  [ERROR] Cannot write {}: {e}", path.display());
                        }
                    }
                }
            } else if is_info_yml {
                let original = match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("  [ERROR] Cannot read {}: {e}", path.display());
                        continue;
                    }
                };
                match sigmacatch_regression::info::InfoYml::load(&path) {
                    Ok(info) => match info.canonical_yaml() {
                        Ok(canonical) => {
                            let original_trimmed = original.trim_end_matches('\n');
                            if needs_reindent(original_trimmed, &canonical) {
                                let rewritten = reindent_yaml(&original, &canonical);
                                let mut content = rewritten;
                                content.push('\n');
                                match std::fs::write(&path, content) {
                                    Ok(()) => {
                                        yml_fixed += 1;
                                        println!("[FIX] {} (indentation)", path.display());
                                    }
                                    Err(e) => {
                                        eprintln!("  [ERROR] Cannot write {}: {e}", path.display());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("  [ERROR] Cannot canonicalize {}: {e}", path.display());
                        }
                    },
                    Err(e) => {
                        eprintln!("  [ERROR] Cannot parse {}: {e}", path.display());
                    }
                }
            }
        }
    }

    println!(
        "\nScanned {total} JSON file(s), fixed {fixed} newline(s), {yml_fixed} YAML indentation(s)."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigmacatch_regression::SigmahqRegression;
    use sigmacatch_rule::SigmahqRules;
    use std::fs;

    fn write_file(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn write_evtx(dir: &Path, rule_id: &str) {
        let path = dir.join(format!("{rule_id}.evtx"));
        fs::create_dir_all(dir).unwrap();
        // EVTX files must be non-empty for data_file_exists to return true.
        fs::write(path, vec![0u8; 4096]).unwrap();
    }

    const RULE_YML: &str = "title: Test Rule\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    const RULE_WITH_PATH_YML: &str = "title: Test Rule\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\nlogsource:\n  product: windows\n  service: sysmon\nregression_tests_path: regression_data/rules/wrong_location/info.yml\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    const RULE_WITH_CORRECT_PATH_YML: &str = "title: Test Rule\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\nlogsource:\n  product: windows\n  service: sysmon\nregression_tests_path: regression_data/rules/test/info.yml\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n";
    const INFO_YML_DIFF_ID: &str = "id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: cccccccc-cccc-4ccc-9ccc-cccccccccccc\n    title: Other Rule\nregression_tests_info:\n  - name: test\n    type: evtx\n    path: dummy.evtx\n";
    const INFO_YML_SAME_ID: &str = "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n    title: Test Rule\nregression_tests_info:\n  - name: test\n    type: evtx\n    path: dummy.evtx\n";
    const INFO_YML_DIFF_RULE: &str = "id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\n    title: Different Rule\nregression_tests_info:\n  - name: test\n    type: evtx\n    path: dummy.evtx\n";

    #[test]
    fn validates_missing_regression_tests_path() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-missing-path");
        let _ = fs::remove_dir_all(&tmp);

        let rules_dir = tmp.join("sigma").join("rules");
        let reg_dir = tmp.join("sigma").join("regression_data");

        write_file(&rules_dir.join("test_rule.yml"), RULE_YML);

        let info_dir = reg_dir.join("rules").join("test");
        write_file(&info_dir.join("info.yml"), INFO_YML_DIFF_ID);
        write_evtx(&info_dir, "cccccccc-cccc-4ccc-9ccc-cccccccccccc");

        let rules = SigmahqRules::new_from_path(&tmp.join("sigma")).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();

        let pv = validate_regression_paths(&rules, &regression, false);
        // Entry's rule_id (cccc...) has no matching rule in SigmahqRules → missing_path=1.
        assert_eq!(pv.missing_path, 1, "expected 1 missing path");
        assert_eq!(pv.mismatched_path, 0, "expected 0 mismatched paths");

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validates_mismatched_regression_tests_path() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-mismatch");
        let _ = fs::remove_dir_all(&tmp);

        let rules_dir = tmp.join("sigma").join("rules");
        let reg_dir = tmp.join("sigma").join("regression_data");

        // Rule points to wrong location
        write_file(&rules_dir.join("test_rule.yml"), RULE_WITH_PATH_YML);

        let info_dir = reg_dir.join("rules").join("test");
        write_file(&info_dir.join("info.yml"), INFO_YML_SAME_ID);
        write_evtx(&info_dir, "aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa");

        let rules = SigmahqRules::new_from_path(&tmp.join("sigma")).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();

        let pv = validate_regression_paths(&rules, &regression, false);
        // Direction 1: rule matches entry, but rtp (wrong_location) ≠ info_path (test) → mismatch.
        // Direction 2: rule rtp (wrong_location) file doesn't exist → mismatch.
        // Both directions legitimately flag the issue: mismatched_path=2.
        assert_eq!(pv.missing_path, 0, "expected 0 missing paths");
        assert_eq!(
            pv.mismatched_path, 2,
            "expected 2 mismatched paths (rule points to wrong location)"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validates_orphaned_rule_regression_tests_path() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-orphan");
        let _ = fs::remove_dir_all(&tmp);

        let rules_dir = tmp.join("sigma").join("rules");
        let reg_dir = tmp.join("sigma").join("regression_data");

        write_file(&rules_dir.join("test_rule.yml"), RULE_WITH_CORRECT_PATH_YML);

        let info_dir = reg_dir.join("rules").join("test");
        write_file(&info_dir.join("info.yml"), INFO_YML_DIFF_RULE);
        write_evtx(&info_dir, "bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb");

        let rules = SigmahqRules::new_from_path(&tmp.join("sigma")).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();

        let pv = validate_regression_paths(&rules, &regression, false);
        // Direction 1: entry rule_id (bbbb...) doesn't match any loaded rule → missing_path=1.
        // Direction 2: rule points to info.yml, file exists, but entry_paths has bbb's path
        //              while the rule expects the same path → entry_paths.contains=true, so no
        //              additional missing_path. But the entry's rule_id is bbbb, not aaaa, so
        //              direction 1 already counted it. Direction 2 checks if the file exists
        //              (yes) and if entry_paths contains it (yes, bbb's path is there) → 0.
        // Total: missing_path=1.
        assert_eq!(pv.missing_path, 1, "expected 1 missing path");
        assert_eq!(pv.mismatched_path, 0, "expected 0 mismatched paths");

        fs::remove_dir_all(&tmp).unwrap();
    }

    const RULE_MATCH_YML: &str = "title: Test Rule\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\nlogsource:\n  product: windows\nregression_tests_path: regression_data/rules/test/info.yml\ndetection:\n  selection:\n    event_id: 1\n  condition: selection\n";

    /// Build a one-rule / one-entry scenario where the JSON data (and its
    /// auxiliary `.json`) holds a single event that matches the rule. `match_count`
    /// in `info.yml` controls whether the validation should pass or fail.
    fn setup_match_count(tmp: &Path, match_count: usize) -> (SigmahqRules, SigmahqRegression) {
        let rules_dir = tmp.join("sigma").join("rules");
        let reg_dir = tmp.join("sigma").join("regression_data");
        let info_dir = reg_dir.join("rules").join("test");
        fs::create_dir_all(&rules_dir).unwrap();
        fs::create_dir_all(&info_dir).unwrap();

        write_file(&rules_dir.join("test_rule.yml"), RULE_MATCH_YML);

        let info = format!(
            "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n\
             description: test\ndate: 2026-01-01\nauthor: test\n\
             rule_metadata:\n  - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n    title: Test Rule\n\
             regression_tests_info:\n  - name: test\n    type: json\n    match_count: {}\n    path: dummy.json\n",
            match_count
        );
        write_file(&info_dir.join("info.yml"), &info);
        // The data file doubles as the JSON auxiliary read by get_json_data.
        write_file(
            &info_dir.join("aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa.json"),
            "{\"event_id\": 1}\n",
        );

        let rules = SigmahqRules::new_from_path(&tmp.join("sigma")).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();
        (rules, regression)
    }

    /// Run the detection pipeline for entry 0 and return its hit count.
    fn detect_hits(rules: &SigmahqRules, regression: &SigmahqRegression) -> usize {
        let idx = 0;
        let raw = regression.get_raw_data(idx).expect("raw data present");
        let events = parse_json_lines(&raw);
        let mut engine = DetectionEngine::new(rules).expect("engine builds");
        engine.put_events(events);
        engine.process_events();
        let alerts = engine.get_alerts();
        let entry = regression.get_entry(idx).expect("entry present");
        alerts.iter().filter(|a| a.rule_id == entry.rule_id).count()
    }

    #[test]
    fn validates_match_count_ok_when_json_present() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-mc-ok");
        let _ = fs::remove_dir_all(&tmp);

        let (rules, regression) = setup_match_count(&tmp, 1);
        let hits = detect_hits(&rules, &regression);
        assert_eq!(hits, 1, "rule should produce exactly 1 hit");

        // Inline the match_count check logic (mirrors main()).
        let expected = regression
            .get_info(0)
            .and_then(|info| info.regression_tests_info.first())
            .map(|t| t.match_count)
            .unwrap_or(0);
        let json_present = regression.get_json_data(0).is_some();
        let verdict = if json_present && expected > 0 && hits != expected {
            Some(format!(
                "MATCH COUNT MISMATCH — expected {} hit(s), got {}",
                expected, hits
            ))
        } else {
            None
        };
        assert!(
            verdict.is_none(),
            "match_count 1 vs 1 hit should pass, got: {:?}",
            verdict
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validates_match_count_mismatch_detected() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-mc-mismatch");
        let _ = fs::remove_dir_all(&tmp);

        let (rules, regression) = setup_match_count(&tmp, 2);
        let hits = detect_hits(&rules, &regression);
        assert_eq!(hits, 1, "rule should produce exactly 1 hit");

        let expected = regression
            .get_info(0)
            .and_then(|info| info.regression_tests_info.first())
            .map(|t| t.match_count)
            .unwrap_or(0);
        let json_present = regression.get_json_data(0).is_some();
        let verdict = if json_present && expected > 0 && hits != expected {
            Some(format!(
                "MATCH COUNT MISMATCH — expected {} hit(s), got {}",
                expected, hits
            ))
        } else {
            None
        };
        assert!(verdict.is_some(), "match_count 2 vs 1 hit should fail");
        assert!(
            verdict.unwrap().contains("MATCH COUNT MISMATCH"),
            "error should report match count mismatch"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validates_match_count_skipped_when_json_absent() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-mc-nojson");
        let _ = fs::remove_dir_all(&tmp);

        let (rules, regression) = setup_match_count(&tmp, 2);
        let hits = detect_hits(&rules, &regression);
        assert_eq!(hits, 1, "rule should produce exactly 1 hit");

        // Remove the auxiliary .json so get_json_data returns None.
        let json_path = tmp
            .join("sigma")
            .join("regression_data")
            .join("rules")
            .join("test")
            .join("aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa.json");
        fs::remove_file(&json_path).unwrap();

        let expected = regression
            .get_info(0)
            .and_then(|info| info.regression_tests_info.first())
            .map(|t| t.match_count)
            .unwrap_or(0);
        let json_present = regression.get_json_data(0).is_some();
        let verdict = if json_present && expected > 0 && hits != expected {
            Some(format!(
                "MATCH COUNT MISMATCH — expected {} hit(s), got {}",
                expected, hits
            ))
        } else {
            None
        };
        assert!(
            verdict.is_none(),
            "without a .json auxiliary the match_count check must be skipped, got: {:?}",
            verdict
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn fix_json_adds_missing_newline_and_leaves_valid_files_untouched() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-fix-json");
        let _ = fs::remove_dir_all(&tmp);

        let reg_dir = tmp.join("sigma").join("regression_data");
        let json_dir = reg_dir.join("rules").join("test");
        fs::create_dir_all(&json_dir).unwrap();

        // One info.yml so the dir is a known regression entry dir.
        write_file(
            &json_dir.join("info.yml"),
            "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n    title: Test Rule\nregression_tests_info:\n  - name: test\n    type: json\n    path: dummy.json\n",
        );
        write_evtx(&json_dir, "aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa");

        let no_nl_path = json_dir.join("aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa.json");
        let has_nl_path = json_dir.join("bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb.json");
        let multi_nl_path = json_dir.join("cccccccc-cccc-4ccc-9ccc-cccccccccccc.json");
        let unrelated_path = json_dir.join("unrelated.json");
        fs::write(&no_nl_path, b"{\"k\":\"v\"}").unwrap();
        fs::write(&has_nl_path, b"{\"k\":\"v\"}\n").unwrap();
        fs::write(&multi_nl_path, b"{\"k\":\"v\"}\n\n\n").unwrap();
        fs::write(&unrelated_path, b"{\"k\":\"v\"}").unwrap();

        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();
        fix_json_newlines(&regression).unwrap();

        let expected = b"{\"k\":\"v\"}\n".to_vec();
        assert_eq!(fs::read(&no_nl_path).unwrap(), expected);
        assert_eq!(fs::read(&has_nl_path).unwrap(), expected);
        assert_eq!(fs::read(&multi_nl_path).unwrap(), expected);
        // Unrelated file within a known entry dir is still a JSON file whose
        // trailing newline is normalized (only files outside known dirs are skipped).
        assert_eq!(fs::read(&unrelated_path).unwrap(), expected);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validate_json_auxiliary_rejects_bad_json() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-json-aux");
        let _ = fs::remove_dir_all(&tmp);

        let reg_dir = tmp.join("sigma").join("regression_data");
        let json_dir = reg_dir.join("rules").join("test");
        fs::create_dir_all(&json_dir).unwrap();
        write_file(
            &json_dir.join("info.yml"),
            "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n    title: Test Rule\nregression_tests_info:\n  - name: test\n    type: json\n    path: x.json\n",
        );
        let rule_id = &"aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa"
            .parse::<Uuid>()
            .unwrap();
        let good = json_dir.join(format!("{rule_id}.json"));
        fs::write(&good, b"{\"k\":\"v\"}\n").unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();

        assert_eq!(validate_json_auxiliary(0, rule_id, &regression), None);

        fs::write(&good, b"{\"k\":\"v\"}").unwrap();
        let err =
            validate_json_auxiliary(0, rule_id, &regression).expect("missing newline should fail");
        assert!(err.contains("missing trailing newline"), "got: {err}");

        fs::write(&good, b"{\"k\":\"v\"}\n\n\n").unwrap();
        let err = validate_json_auxiliary(0, rule_id, &regression)
            .expect("multiple newlines should fail");
        assert!(err.contains("multiple trailing newlines"), "got: {err}");

        fs::write(&good, b"{\"k\":\"v\"\n").unwrap();
        let err =
            validate_json_auxiliary(0, rule_id, &regression).expect("invalid JSON should fail");
        assert!(err.contains("invalid JSON"), "got: {err}");

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn validate_yaml_indentation_accepts_comments_and_rejects_bad_indent() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-yaml-indent");
        let _ = fs::remove_dir_all(&tmp);

        let reg_dir = tmp.join("sigma").join("regression_data");
        let json_dir = reg_dir.join("rules").join("test");
        fs::create_dir_all(&json_dir).unwrap();
        let path = json_dir.join("info.yml");

        // Proper 4-space SigmaHQ style plus comment lines: must pass.
        let commented = "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa  # info id\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n    - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa  # must match rule\n      title: Test Rule\nregression_tests_info:\n    - name: test\n      type: json\n      path: x.json\n";
        fs::write(&path, commented).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();
        assert_eq!(
            validate_yaml_indentation(0, &regression),
            None,
            "4-space indent with comments must pass"
        );

        // 2-space / 0-indent style (serde default): must fail.
        let bad = "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n- id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n  title: Test Rule\nregression_tests_info:\n- name: test\n  type: json\n  path: x.json\n";
        fs::write(&path, bad).unwrap();
        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();
        let err = validate_yaml_indentation(0, &regression)
            .expect("non-conformant indentation should fail");
        assert!(err.contains("indentation"), "got: {err}");

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn reindent_yaml_preserves_comments() {
        let raw = "# top comment\nid: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nrule_metadata:\n- id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\n  title: R\n";
        let canonical = "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\nrule_metadata:\n    - id: bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb\n      title: R\n";
        let out = reindent_yaml(raw, canonical);
        assert!(
            out.starts_with("# top comment\n"),
            "comment preserved, got: {out}"
        );
        assert!(
            out.contains("    - id: bbbbbbbb-"),
            "list re-indented, got: {out}"
        );
        assert!(
            out.contains("      title: R"),
            "content re-indented, got: {out}"
        );
    }

    #[test]
    fn path_option_contract_regression_parent_is_sigma_root() {
        let tmp = std::env::temp_dir().join("regressiondata-check-test-path-option");
        let _ = fs::remove_dir_all(&tmp);

        let sigma = tmp.join("sigma");
        let reg_dir = sigma.join("regression_data");
        let info_dir = reg_dir.join("rules").join("test");
        fs::create_dir_all(sigma.join("rules")).unwrap();
        fs::create_dir_all(&info_dir).unwrap();
        write_file(
            &info_dir.join("info.yml"),
            "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n  - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n    title: Test Rule\nregression_tests_info:\n  - name: test\n    type: evtx\n    path: dummy.evtx\n",
        );

        let regression = SigmahqRegression::new_from_path(&reg_dir).unwrap();
        let parent = regression
            .path()
            .parent()
            .expect("regression path must have a parent");
        assert_eq!(
            parent,
            sigma.as_path(),
            "path().parent() must be the sigma root for validate_regression_paths auto-adaptation"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }
}
