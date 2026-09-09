// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! CLI subcommands for the single `sigmacatch` binary.
//!
//! Always compiled. Dispatched from `main.rs` before `runner::run()` is
//! entered. The diagnostic logic (check-filter, list-rules) lives in
//! `sigmacatch-runner::cli` (AD-5).

// ─── Dispatch ─────────────────────────────────────────────────────────────────

/// Dispatch on argv[1]. `None` = no/unknown subcommand → caller runs the
/// normal collection loop; `Some(code)` = subcommand handled → exit with code.
pub fn dispatch() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None; // no subcommand → fall through to normal loop
    }
    match args[1].as_str() {
        "--check-filter" | "check-filter" => {
            let rest = &args[2..];
            if rest.is_empty() || (rest.len() == 1 && (rest[0] == "--help" || rest[0] == "-h")) {
                print_check_filter_help();
                Some(0)
            } else {
                Some(sigmacatch_runner::cli::cmd_check_filter(rest))
            }
        }
        "--list-rules" | "list-rules" => {
            let rest = &args[2..];
            if rest.is_empty() || (rest.len() == 1 && (rest[0] == "--help" || rest[0] == "-h")) {
                print_list_rules_help();
                Some(0)
            } else {
                Some(sigmacatch_runner::cli::cmd_list_rules(rest))
            }
        }
        _ => None, // unknown subcommand → normal loop
    }
}

fn print_check_filter_help() {
    println!(
        "\
sigmacatch check-filter — validate filter dimensions against ground truth

USAGE:
    sigmacatch check-filter [OPTIONS]

OPTIONS:
    --json    Output results as JSON instead of human-readable text
"
    );
}

fn print_list_rules_help() {
    println!(
        "\
sigmacatch list-rules — list all loaded rules with metadata

USAGE:
    sigmacatch list-rules [OPTIONS]

OPTIONS:
    --json       Output results as JSON instead of human-readable text
    --coverage   Include coverage stats (rules with/without regression data)
"
    );
}
