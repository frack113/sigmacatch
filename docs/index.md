# Sigmacatch

Headless tool that captures real Windows events via the **Windows Event Log API** (`winevt`) or **direct ETW** (`ferrisetw`), or Linux events via **auditd**, **builtin syslog** (central, authpriv and cron files) and **Sysmon-for-Linux**, matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules, and outputs structured regression data ready for SigmaHQ PRs.

## Workspace

The project is a cargo workspace of 12 packages (2 binary crates + 10 libraries):

| Crate | Purpose |
|---|---|
| `sigmacatch-win` | Windows binaries: `sigmacatch-channel` (winevt) and `sigmacatch-etw` (direct ETW) + `channels.rs`/`etw/` collectors + `cli.rs` diagnostics |
| `sigmacatch-lnx` | Linux binary: `sigmacatch-linux` (auditd + builtin syslog + Sysmon-for-Linux collectors in parallel, per-source availability guard) + `cli.rs` diagnostics |
| `sigmacatch-runner` | Shared pipeline (`run<C: CollectorKind>`): config, repo init, event loop, generation, commit/push |
| `sigmacatch-config` | Config YAML + CLI parsing + custom_channels.yaml |
| `sigmacatch-logger` | Two-layer tracing subscriber (stderr `error` by default, `info` with `-v`; daily rolling file debug) |
| `sigmacatch-rule` | `SigmahqRules`: rule loading, filter, dedupe, remove_id + `SigmaRuleExt` (ATT&CK techniques) |
| `sigmacatch-detection` | Thin wrapper around rsigma-eval (pipelines, bloom, LogSourceExtractor, resolve_channels) |
| `sigmacatch-regression` | `SigmahqRegression`, `InfoYml`, `DataFormat` (Evtx/Log), data generation + validation |
| `sigmacatch-evtx-writer` | Pure Rust EVTX writer for ETW / record-id-less events |
| `sigmacatch-types` | Shared types: `Event`, `Alert`, `RegressionHeader`, XML parsing, logsource tables |
| `sigmacatch-repo` | grit-lib wrapper: SigmaRepo, git operations, SSH commit signing |
| `input-windows-evtx` | Parse EVTX files into `Event` objects (used by diagnostic subcommands) |

## Quick start

```bash
cargo build --release
./target/release/sigmacatch-channel   # Winevt (Windows)
./target/release/sigmacatch-etw       # Direct ETW (Windows)
./target/release/sigmacatch-linux     # auditd + syslog + sysmon (Linux)
```

## Documentation

A built version of this documentation is published to GitHub Pages: **https://frack113.github.io/sigmacatch/**

| | English | Francais |
|---|---|---|
| Architecture | [EN](architecture/) | [FR](fr/architecture/) |
| Build | [EN](build/) | [FR](fr/build/) |
| CLI | [EN](cli/) | [FR](fr/cli/) |
| Git | [EN](git/) | [FR](fr/git/) |
| Output format | [EN](output-format/) | [FR](fr/output-format/) |
| Regression data format | [EN](regression-data-format/) | [FR](fr/regression-data-format/) |

## License

MIT
