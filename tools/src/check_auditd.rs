// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! check_auditd: validate auditd event matching against Sigma Linux rules.
//!
//! Pipeline:
//!   1. Load all Sigma rules from `./sigma`, filtered to `product: linux`
//!   2. Read an audit.log file, parse each record (with logsource injection
//!      `product: linux` / `service: auditd`)
//!   3. Evaluate the records against the detection engine
//!   4. Report per-rule matches (rule id/title + alert count) and rules with
//!      no match
//!
//! Usage:
//!   cargo run --release --bin check_auditd <audit.log> [--all-rules]
//!   cat audit.log | cargo run --release --bin check_auditd - [--all-rules]

use input_linux_auditd::event::record_to_event;
use input_linux_auditd::parser::parse_line;
use sigmacatch_detection::DetectionEngine;
use sigmacatch_rule::{SigmaFilterConfig, SigmahqRules};
use sigmacatch_types::Event;
use std::collections::HashMap;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let all_rules = args.iter().any(|a| a == "--all-rules");
    let path = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .unwrap_or("-");

    let rules = match SigmahqRules::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to load rules: {e}");
            process::exit(1);
        }
    };
    let rules = if all_rules {
        rules
    } else {
        rules.filter(SigmaFilterConfig {
            product: "linux".to_string(),
            ..Default::default()
        })
    };
    if rules.is_empty() {
        eprintln!("No rules loaded (filtered product=linux) — nothing to evaluate");
        process::exit(1);
    }
    println!(
        "Loaded {} rules{}",
        rules.len(),
        if all_rules {
            " (all products)"
        } else {
            " (product=linux)"
        }
    );

    let mut engine = match DetectionEngine::new(&rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to build engine: {e}");
            process::exit(1);
        }
    };

    let events = match load_events(path) {
        Ok(events) => events,
        Err(e) => {
            eprintln!("Failed to load audit log: {e}");
            process::exit(1);
        }
    };
    println!("Parsed {} audit event(s)", events.len());

    engine.put_events(events);
    engine.process_events();
    let alerts = engine.get_alerts();

    let mut by_rule: HashMap<String, (String, usize)> = HashMap::new();
    for alert in &alerts {
        let entry = by_rule
            .entry(alert.rule_id.to_string())
            .or_insert_with(|| (alert.rule_title.clone(), 0));
        entry.1 += 1;
    }

    let mut matched: Vec<(&str, &str, &usize)> = by_rule
        .iter()
        .map(|(id, (title, count))| (id.as_str(), title.as_str(), count))
        .collect();
    matched.sort_by_key(|(id, _, _)| *id);

    println!("\n{}", "=".repeat(60));
    println!("  MATCHED RULES ({})", matched.len());
    println!("{}", "=".repeat(60));
    for (id, title, count) in &matched {
        println!("  ✅ {} ×{} — {}", id, count, title);
    }

    // Rules with no match.
    let matched_ids: std::collections::HashSet<&str> = by_rule.keys().map(|s| s.as_str()).collect();
    let unmatched: Vec<&sigmacatch_rule::SigmaRule> = rules
        .rules()
        .iter()
        .filter(|r| r.id.as_deref().is_none_or(|id| !matched_ids.contains(id)))
        .collect();

    println!("\n{}", "=".repeat(60));
    println!("  RULES WITHOUT MATCH ({})", unmatched.len());
    println!("{}", "=".repeat(60));
    for rule in unmatched {
        println!(
            "  ⚪ {} — {}",
            rule.id.as_deref().unwrap_or("<no id>"),
            rule.title.as_str()
        );
    }
}

/// Read the audit log (a file path, or stdin for `-`), parse each line and
/// emit one event per record.
fn load_events(path: &str) -> anyhow::Result<Vec<Event>> {
    let content = if path == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(path)?
    };

    let mut events = Vec::new();
    let mut last_was_complete = true;
    for line in content.split_inclusive(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        last_was_complete = line.last() == Some(&b'\n');
        if let Some(record) = parse_line(line) {
            events.push(record_to_event(line, &record));
        }
    }
    if !last_was_complete {
        let remainder = match content.iter().rposition(|&b| b == b'\n') {
            Some(pos) => &content[pos + 1..],
            None => &content,
        };
        let mut line = remainder.to_vec();
        line.push(b'\n');
        if let Some(record) = parse_line(&line) {
            events.push(record_to_event(&line, &record));
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_events_stdin_equivalent() {
        let content = b"type=SYSCALL msg=audit(1717056137.482:90412): arch=c000003e syscall=257 pid=20488 comm=\"cat\"\n";
        let events = load_events_from_bytes(content);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_json["comm"], "cat");
        assert_eq!(events[0].event_json["service"], "auditd");
        assert_eq!(events[0].event_json["product"], "linux");
    }

    #[test]
    fn test_two_records_two_events_same_stamp() {
        let content = b"type=SYSCALL msg=audit(1717056137.482:90412): arch=c000003e syscall=257 pid=20488 comm=\"cat\"\ntype=EXECVE msg=audit(1717056137.482:90412): argc=2 a0=\"cat\" a1=\"/etc/shadow\"\n";
        let events = load_events_from_bytes(content);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_json["type"], "SYSCALL");
        assert_eq!(events[1].event_json["type"], "EXECVE");
        assert_eq!(
            events[0].event_json_raw["stamp"],
            events[1].event_json_raw["stamp"]
        );
    }

    fn load_events_from_bytes(content: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        for line in content.split_inclusive(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if let Some(record) = parse_line(line) {
                events.push(record_to_event(line, &record));
            }
        }
        events
    }
}
