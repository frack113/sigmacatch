// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Integration tests for the `sigmacatch-check` CLI binary.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_sigmacatch-check");

const INFO_YML: &str = "id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\ndescription: test\ndate: 2026-01-01\nauthor: test\nrule_metadata:\n    - id: aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa\n      title: Test Rule\nregression_tests_info:\n    - name: test\n      type: json\n      path: dummy.json\n";

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn sigmacatch-check")
}

fn make_sigma_root(dir: &std::path::Path) -> PathBuf {
    let sigma = dir.join("sigma");
    fs::create_dir_all(sigma.join("rules")).unwrap();
    let info_dir = sigma.join("regression_data").join("rules").join("fixture");
    fs::create_dir_all(&info_dir).unwrap();
    fs::write(info_dir.join("info.yml"), INFO_YML).unwrap();
    sigma
}

#[test]
fn missing_path_value_exits_1_with_help() {
    let out = run(&["--path"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Missing value for --path"), "got: {err}");
    assert!(
        err.contains("--path <DIR>"),
        "expected full help, got: {err}"
    );
}

#[test]
fn help_lists_path_option() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--path <DIR>"), "got: {stdout}");
    assert!(stdout.contains("default: ./sigma"), "got: {stdout}");
}

#[test]
fn path_option_loads_regression_from_given_root() {
    let tmp = std::env::temp_dir().join("sigmacatch-check-cli-pathload");
    let _ = fs::remove_dir_all(&tmp);
    let sigma = make_sigma_root(&tmp);

    let out = run(&["--path", sigma.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The tmp fixture has exactly one regression entry; if the binary had
    // fallen back to ./sigma the count (or an error) would differ.
    assert!(
        stdout.contains("Total entries:   1"),
        "expected the tmp root's single entry, got:\n{stdout}"
    );
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn path_option_missing_value_flag_rejected() {
    // A flag-like value must not be silently consumed as a directory.
    let out = run(&["--path", "--json"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Invalid value for --path"),
        "expected flag value rejected, got: {err}"
    );
}

#[test]
fn fix_with_path_normalizes_files_in_given_root() {
    let tmp = std::env::temp_dir().join("sigmacatch-check-cli-fixpath");
    let _ = fs::remove_dir_all(&tmp);
    let sigma = make_sigma_root(&tmp);
    let json_dir = sigma.join("regression_data").join("rules").join("fixture");
    let json_path = json_dir.join("aaaaaaaa-aaaa-4aaa-9aaa-aaaaaaaaaaaa.json");
    fs::write(&json_path, b"{\"k\":\"v\"}").unwrap(); // no trailing newline

    let out = run(&["--fix", "--path", sigma.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = fs::read(&json_path).unwrap();
    assert_eq!(bytes, b"{\"k\":\"v\"}\n", "expected trailing newline added");
    let _ = fs::remove_dir_all(&tmp);
}
