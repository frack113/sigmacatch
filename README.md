<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# Sigmacatch

> ⚠️ **WIP** — this project is under active development. APIs, config, and output formats may change without notice. Not production-ready.

Sigmacatch captures real OS events, matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules in real time, and generates regression data ready for SigmaHQ pull requests.

| Platform | Collector | Binary |
|---|---|---|
| Windows | Windows Event Log API (`winevt`) | `sigmacatch-channel` |
| Windows | Direct ETW (`ferrisetw`) | `sigmacatch-etw` |
| Linux | auditd tail and/or syslog tails (central + authpriv + cron, incl. Sysmon-for-Linux XML) | `sigmacatch-linux` |

## How it works

```text
SigmaHQ rules (auto-cloned via grit-lib)
    ↓
Load rules → skip existing regression → filter (product / min_status / min_level)
    ↓
Resolve channels from rules (logsource → channel mapping)
    ↓
Continuous collector → mpsc
    ↓
Sigma engine evaluates every event against every loaded rule
    ↓
Every 30 s: write regression data for each matched rule
    ↓
sigma/regression_data/<rule_rel_path>/
    ├── <rule_id>.evtx    ← valid EVTX (EvtExportLog, validated ≥ 1 record)
    ├── <rule_id>.log     ← original auditd/syslog lines (Linux collectors)
    ├── <rule_id>.json    ← optional raw event (regression.add_json_output)
    └── info.yml          ← SigmaHQ-compatible metadata
    ↓
One commit per rule — single push to fork when contrib is enabled
```

The pipeline runs continuously until Ctrl+C; remaining events are flushed before exit.

## Quick start

```bash
cargo build --release
./target/release/sigmacatch-channel   # Winevt collector (Windows)
./target/release/sigmacatch-etw       # ETW collector (Windows)
./target/release/sigmacatch-linux     # auditd + builtin syslog + Sysmon-for-Linux collectors (Linux)
```

On first run a `config.yaml` is created with defaults:

```yaml
git:
  author: "your-username"
  email: "you@example.com"
  github_token: ""          # GitHub token (or set GITHUB_TOKEN env var) — required for HTTP transport when network is active
  transport: http           # http or ssh
  ssh_key_path: ""          # path to SSH private key (optional, only needed for SSH)
  sigma_repo_url: "https://github.com/SigmaHQ/sigma.git"
  sigma_repo_path: "sigma"
  offline: false            # true = zero git operations (no pull/clone/commit/push; on-disk files used as-is, .git optional)
  contrib: false            # true = push commits to remote fork. Default: false (local commits only)
log:
  level_file: "debug"
filter:
  product: windows          # windows, linux, or macos
  # min_status: stable      # optional — load rules with status >= this threshold (unset = no filter)
  # min_level: critical     # optional — load rules with level >= this threshold (unset = no filter)
  author: ""                # filter rules by author (optional, empty = no filter)
  max_rule_size: 1048576    # bytes (1MB default)
regression:
  max_failed_cycles: 3      # block a rule (no more re-capture) after N consecutive failure cycles
  add_json_output: false    # true = also write auxiliary <rule_id>.json alongside the data file
```

Rules below the configured `min_status` / `min_level` thresholds are skipped at load time; rules missing these fields are always accepted.

**Contrib is opt-in** (`git.contrib: true` or `--contrib`): pushes regression commits to your fork. By default (`false`) commits stay local. The GitHub token is only required when a network operation is active (`offline: false` or `contrib: true`). **`offline: true` neutralizes `contrib`** (forced to `false`, `warn!`): no push in offline mode.

## CLI

| Flag | Description |
|------|-------------|
| `--author <name>` | Override detected username |
| `-a`, `--all-rules` | Load all rules — skip set is disabled |
| `-c`, `--contrib` | Enable push to the remote fork for this run |
| `-o`, `--offline` | Skip all git operations (use on-disk files as-is; no commit/push) |
| `-r`, `--max-runs <N>` | Exit after N collection cycles (final flush included) |
| `-v`, `--verbose` | Show info-level logs on stderr (default: errors only) |
| `--help`, `-h` | Print help and exit |

### Collector selection

Collectors are selected via cargo features, not CLI flags:

| Binary | Feature | Backend |
|---|---|---|
| `sigmacatch-channel` | `winevt` | Windows Event Log API |
| `sigmacatch-etw` | `etw` | Direct ETW via ferrisetw |
| `sigmacatch-linux` | `auditd` + `builtin` | Three collectors guarded by their sources: **auditd** tail if `/var/log/audit/audit.log` exists; **builtin syslog** tails every existing file among central (`/var/log/messages`, `/var/log/syslog`), authpriv (`/var/log/secure`, `/var/log/auth.log`) and cron (`/var/log/cron`, `/var/log/cron.log`); **Sysmon-for-Linux** parses the `sysmon`-tagged XML lines of the central syslog (excluded from the builtin collector to avoid double capture). Bail at startup if no source exists |

Build a single collector in isolation:

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win --no-default-features --features etw
```

### Diagnostics (feature `tools`)

| Command | Description |
|---|---|
| `sigmacatch-channel check` | Deep validation of `./sigma/regression_data` — every rule must match its data (exit 1 otherwise) |
| `sigmacatch-channel check-channels` | Resolve and list the channels the engine would collect |
| `sigmacatch-channel check-filter` | Validate the filter config against the real rule set (ground-truth counts) |
| `sigmacatch-channel list-rules` | List loaded rules with techniques and ART link (`--coverage` for stats) |
| `sigmacatch-channel get-atomic` | Generate a `run_atomic.ps1` (Invoke-AtomicRedTeam chain) for rules without regression data |
| `sigmacatch-linux check` / `check-filter` / `list-rules` | Same diagnostics for the Linux binary |

## Requirements

- **Windows** with [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) installed — required for rich events (ParentImage, CommandLine, hashes, etc.)
- **Linux** with `auditd` running or a syslog source (`/var/log/messages` or `/var/log/syslog`, optionally authpriv/cron files) — for `sigmacatch-linux`; [Sysmon for Linux](https://github.com/SysmonForLinux/SysmonForLinux) optional, adds rich process/network events through the syslog stream
- Rust 2024 edition (1.85+)
- Admin rights for the `Security` and `System` Event Log channels (Windows)

## Build & cross-compilation

Cross-compilation from Linux to Windows:

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win
```

> Requires `cargo install cargo-xwin`. Downloads the Windows SDK automatically.

`.cargo/config.toml` forces `target-feature=+crt-static`: without it the binary depends on **VCRUNTIME140.dll** (Visual C++ Redistributable) and crashes if the runtime is missing on the target machine. With `+crt-static` the `.exe` is standalone.

Linux native build:

```bash
cargo build --release -p sigmacatch-lnx
```

On Linux/macOS the Windows collectors are stubs that return no events — the pipeline still runs end-to-end for testing.

## Documentation

A built version of this documentation is published to GitHub Pages: **https://frack113.github.io/sigmacatch/**

| | English | Français |
|---|---|---|
| Architecture | [EN](docs/en/architecture.md) | [FR](docs/fr/architecture.md) |
| Build | [EN](docs/en/build.md) | [FR](docs/fr/build.md) |
| Git | [EN](docs/en/git.md) | [FR](docs/fr/git.md) |
| Output format | [EN](docs/en/output-format.md) | [FR](docs/fr/output-format.md) |
| Regression data format | [EN](docs/en/regression-data-format.md) | [FR](docs/fr/regression-data-format.md) |
| CLI diagnostics | [EN](docs/en/cli.md) | [FR](docs/fr/cli.md) |

## Workspace

The project is a cargo workspace of 12 packages (2 binary crates + 10 libraries):

| Crate | Purpose |
|---|---|
| `sigmacatch-win` | Windows binaries: `sigmacatch-channel` (winevt), `sigmacatch-etw` (ETW) + `channels.rs` / `etw/` collectors + `cli.rs` diagnostics |
| `sigmacatch-lnx` | Linux binary: `sigmacatch-linux` (auditd + builtin syslog + Sysmon-for-Linux in parallel) + `cli.rs` diagnostics |
| `sigmacatch-runner` | Shared pipeline (`run<C: CollectorKind>`): config, repo init, event loop, generation, commit/push |
| `sigmacatch-config` | Config YAML + CLI parsing + custom_channels.yaml |
| `sigmacatch-logger` | Two-layer tracing subscriber (stderr `error` by default, `info` with `-v`; daily rolling file debug, max 3 kept) |
| `sigmacatch-rule` | `SigmahqRules`: rule loading, filtering, deduplication, remove_id |
| `sigmacatch-detection` | `DetectionEngine` + per-platform pipelines (win/lnx logsource + field_name) + channel_resolver + bloom pre-filter |
| `sigmacatch-regression` | `SigmahqRegression`, `InfoYml`, `DataFormat` (Evtx/Log) + validation (evtx/format/info/logtype/long_path) |
| `sigmacatch-evtx-writer` | Pure Rust EVTX writer for ETW / record-id-less events |
| `sigmacatch-types` | Shared types: `Event`, `Alert`, `RegressionHeader`, XML parsing, logsource mapping tables (phf) |
| `sigmacatch-repo` | grit-lib wrapper: `SigmaRepo`, GitHub fork detection, plumbing/porcelain git ops, SSH signing |
| `input-windows-evtx` | Parse EVTX files into `Event` objects (used by `sigmacatch-channel check`) |

## Built with

- [rsigma-eval](https://crates.io/crates/rsigma-eval) + [rsigma-parser](https://crates.io/crates/rsigma-parser) — Sigma rule loading and evaluation
- [grit-lib](https://github.com/gitbutlerapp/grit) — pure Rust git, no CLI needed
- [tokio](https://crates.io/crates/tokio) — async runtime
- [windows](https://crates.io/crates/windows) — Windows Event Log API, cfg-gated
- [ferrisetw](https://crates.io/crates/ferrisetw) — direct ETW collection, cfg-gated
- [linux-audit-parser](https://crates.io/crates/linux-audit-parser) — auditd log parsing
- [regex](https://crates.io/crates/regex) — RFC3164 syslog line parsing (builtin collector)
- [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) / [serde_yaml](https://crates.io/crates/serde_yaml) — serialization
- [roxmltree](https://crates.io/crates/roxmltree) — XML parsing for Winevt events
- [evtx](https://crates.io/crates/evtx) — EVTX file parsing

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
