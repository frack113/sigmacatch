// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! CLI diagnostics contract for the `sigmacatch` binary (AD-5): the
//! `check-filter` and `list-rules` subcommands run against a `config.yaml` +
//! local `sigma` rules dir with no collector, no network, no git.
//!
//! The binary is the only place the full dispatch chain
//! (`main.rs` → `cli::dispatch` → `Config::load` → filter ground-truth) is
//! exercised end to end.

use std::io::Write;
use std::path::Path;
use std::process::Command;

fn run_in(cwd: &Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_sigmacatch"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("binary must run");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), text)
}

/// Write a config.yaml whose sigma repo is the relative `sigma` dir and whose
/// git section bypasses every network precondition.
fn write_config(cwd: &Path) {
    let yaml = "git:\n  author: check-test\n  email: check-test@example.com\n  github_token: dummy\n  sigma_repo_path: sigma\n  offline: true\n";
    std::fs::write(cwd.join("config.yaml"), yaml).expect("write config.yaml");
}

/// A fixture covering every filter dimension the ground-truth tests exercise:
/// product (windows/linux/macos), status (stable/test/experimental/deprecated),
/// level (critical/medium/low/informational) and author list membership.
fn write_rules(cwd: &Path) {
    let rules_dir = cwd.join("sigma").join("rules");
    std::fs::create_dir_all(&rules_dir).expect("mkdir sigma/rules");

    let rules = [
        (
            "test_stable_critical.yml",
            r#"title: Windows Stable Critical
id: 11111111-1111-4111-8111-111111111111
status: stable
description: fixture
author: frack113, Elastic
date: 2026-01-01
level: critical
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
  condition: selection
"#,
        ),
        (
            "test_linux_medium.yml",
            r#"title: Linux Test Medium
id: 22222222-2222-4222-8222-222222222222
status: test
description: fixture
author: Florian Roth
date: 2026-01-01
level: medium
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Corrupted MAC on input'
  condition: keywords
"#,
        ),
        (
            "test_macos_low.yml",
            r#"title: MacOS Experimental
id: 33333333-3333-4333-8333-333333333333
status: experimental
description: fixture
author: macos-guy
date: 2026-01-01
level: low
logsource:
  product: macos
  service: process_creation
detection:
  selection:
    CommandLine: 'anything'
  condition: selection
"#,
        ),
        (
            "test_windows_deprecated.yml",
            r#"title: Windows Deprecated
id: 44444444-4444-4444-8444-444444444444
status: deprecated
description: fixture
author: other
date: 2026-01-01
level: informational
logsource:
  product: windows
  service: powershell
detection:
  selection:
    CommandLine: 'Invoke-Mimikatz'
  condition: selection
"#,
        ),
    ];
    for (name, body) in rules {
        let path = rules_dir.join(name);
        let mut file =
            std::fs::File::create(&path).unwrap_or_else(|e| panic!("create {name}: {e}"));
        file.write_all(body.trim_start().as_bytes())
            .expect("write rule");
    }
}

fn fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_config(tmp.path());
    write_rules(tmp.path());
    tmp
}

#[test]
fn check_filter_help_needs_no_config() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, out) = run_in(tmp.path(), &["--check-filter", "--help"]);
    assert_eq!(code, 0, "help must exit 0: {}", out);
    assert!(
        out.contains("validate filter dimensions"),
        "help must describe check-filter: {out}"
    );
}

#[test]
fn list_rules_help_needs_no_config() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, out) = run_in(tmp.path(), &["--list-rules", "--help"]);
    assert_eq!(code, 0, "help must exit 0: {}", out);
    assert!(out.contains("list all loaded rules"), "help text: {out}");
}

#[test]
fn top_level_help_falls_through_to_parse_args() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, out) = run_in(tmp.path(), &["--help"]);
    assert_eq!(code, 0, "top-level --help must exit 0: {out}");
    assert!(out.contains("USAGE"), "main help text: {out}");
}

#[test]
fn unknown_flag_falls_through_to_parse_args() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, out) = run_in(tmp.path(), &["--no-such-flag"]);
    assert_eq!(code, 1, "unknown flag must exit 1: {out}");
    assert!(out.contains("unknown flag"), "{out}");
}

#[test]
fn evtx_missing_value_is_a_parse_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, out) = run_in(tmp.path(), &["--evtx"]);
    assert_eq!(code, 1, "--evtx without value must exit 1: {out}");
    assert!(out.contains("requires a value"), "{out}");
}

#[cfg(not(feature = "evtx"))]
#[test]
fn evtx_requested_but_not_compiled_in() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, out) = run_in(tmp.path(), &["--evtx", "/nonexistent/file.evtx"]);
    assert_eq!(code, 1, "unbuilt evtx input must bail: {out}");
    assert!(out.contains("not compiled in"), "{out}");
}

#[test]
fn check_filter_matches_ground_truth() {
    let tmp = fixture();
    let (code, out) = run_in(tmp.path(), &["--check-filter", "--json"]);
    assert_eq!(code, 0, "check-filter must pass on fixture: {out}");
    assert!(
        out.contains("\"total_failed\": 0"),
        "no test may fail: {out}"
    );
    assert!(
        out.contains("\"total_passed\": 7"),
        "all 7 standard filter tests run: {out}"
    );
}

#[test]
fn list_rules_prints_fixture_under_default_windows_filter() {
    let tmp = fixture();
    let (code, out) = run_in(tmp.path(), &["--list-rules", "--json"]);
    assert_eq!(code, 0, "list-rules must exit 0: {out}");
    assert!(out.contains("Windows Stable Critical"), "{out}");
    assert!(out.contains("Windows Deprecated"), "{out}");
    assert!(
        !out.contains("MacOS Experimental") && !out.contains("Linux Test Medium"),
        "default filter product=windows keeps only windows rules: {out}"
    );
}

#[test]
fn check_filter_bare_runs_human_summary() {
    let tmp = fixture();
    let (code, out) = run_in(tmp.path(), &["--check-filter"]);
    assert_eq!(code, 0, "human output must exit 0: {out}");
    assert!(
        out.contains("Passed: 7") && out.contains("Failed: 0"),
        "{out}"
    );
    assert!(out.contains("Loaded 4 total rules from sigma"), "{out}");
}

#[test]
fn list_rules_coverage_human() {
    let tmp = fixture();
    let (code, out) = run_in(tmp.path(), &["--list-rules", "--coverage"]);
    assert_eq!(code, 0, "coverage must exit 0: {out}");
    assert!(out.contains("Loaded 2 rule(s)"), "{out}");
    assert!(
        out.contains("2 rule(s) without regression data"),
        "coverage summary line: {out}"
    );
}

#[test]
fn list_rules_bare_runs_human_listing() {
    let tmp = fixture();
    let (code, out) = run_in(tmp.path(), &["--list-rules"]);
    assert_eq!(code, 0, "bare list-rules must run, not print help: {out}");
    assert!(out.contains("Windows Stable Critical"), "{out}");
    assert!(out.contains("Loaded 2 rule(s)"), "{out}");
}
