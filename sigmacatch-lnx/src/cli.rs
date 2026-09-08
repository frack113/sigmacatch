// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! CLI subcommands for the `sigmacatch-linux` binary.
//!
//! Always compiled. Dispatched from the shared `entry.rs` before
//! `runner::run()` is entered. The diagnostic logic (check-filter, list-rules)
//! lives in `sigmacatch-runner::cli` (AD-5).

// ─── Dispatch ─────────────────────────────────────────────────────────────────

/// Dispatch on argv[1]. `None` = no/unknown subcommand → caller runs the
/// normal collection loop; `Some(code)` = subcommand handled → exit with code.
pub fn dispatch() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None;
    }
    match args[1].as_str() {
        "check-filter" => Some(sigmacatch_runner::cli::cmd_check_filter(&args[2..])),
        "list-rules" => Some(sigmacatch_runner::cli::cmd_list_rules(&args[2..])),
        _ => None,
    }
}
