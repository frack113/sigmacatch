<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# Sigmacatch

> ⚠️ **WIP** — this project is under active development. APIs, config, and output formats may change without notice. Not production-ready.

Sigmacatch captures real OS events, matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules in real time, and generates regression data ready for SigmaHQ pull requests.

| Platform | Collector | Binary |
|---|---|---|
| Windows | Windows Event Log API (`winevt`) | `sigmacatch-channel` |
| Windows | Direct ETW (`ferrisetw`) | `sigmacatch-etw` |
| Linux | auditd + builtin syslog (default, no root needed) | `sigmacatch-linux` |
| Linux | + legacy Sysmon-for-Linux XML tail | `sigmacatch-linux-sysmon` |
| Linux | + native eBPF probes (process/network/file/DNS) | `sigmacatch-linux-ebpf` |

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

The pipeline runs continuously until Ctrl+C; on exit the pipeline flushes the remaining events.

## Requirements

- **Windows** with [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) installed — required for rich events (ParentImage, CommandLine, hashes, etc.)
- **Linux** with `auditd` running or a syslog source (`/var/log/messages` or `/var/log/syslog`, optionally authpriv/cron files) — for `sigmacatch-linux`; [Sysmon for Linux](https://github.com/SysmonForLinux/SysmonForLinux) optional via `sigmacatch-linux-sysmon`; native eBPF probes via `sigmacatch-linux-ebpf` (root or CAP_BPF+CAP_PERFMON at runtime, kernel 5.14+/BTF, nightly build toolchain)
- Rust 2024 edition (1.85+)
- Admin rights for the `Security` and `System` Event Log channels (Windows)

## Quick start

```bash
cargo build --release
./target/release/sigmacatch-channel     # Winevt collector (Windows)
./target/release/sigmacatch-etw         # ETW collector (Windows)
./target/release/sigmacatch-linux       # auditd + builtin syslog (Linux, no root)
./target/release/sigmacatch-linux-sysmon  # + Sysmon-for-Linux tail (Linux)
./target/release/sigmacatch-linux-ebpf  # + eBPF probes (Linux, root required)
```

On first run a `config.yaml` is created with placeholder defaults, and the run stops (`exit 1`)
until you edit it — `author: sigmacatch` (placeholder, rejected by validation) and an empty
`email` both bail:

```yaml
git:
  author: "sigmacatch"      # PLACEHOLDER — replace with your GitHub username before the next run
  email: ""                 # required (any non-empty value)
  github_token: ""          # GitHub token (or set GITHUB_TOKEN env var) — required for HTTP transport when network is active
  transport: http           # http or ssh
  ssh_key_path: ""          # path to SSH private key (optional, only needed for SSH)
  sigma_repo_url: "https://github.com/SigmaHQ/sigma.git"
  sigma_repo_path: "sigma"  # keep the default — generation writes to ./sigma/regression_data
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

| Binary | Default features | Backend |
|---|---|---|
| `sigmacatch-channel` | `winevt` + `etw` | Windows Event Log API / Direct ETW |
| `sigmacatch-etw` | `winevt` + `etw` | Direct ETW via ferrisetw |
| `sigmacatch-linux` | `auditd` + `builtin` | Auditd parser + RFC3164 syslog parsing (no root needed) |
| `sigmacatch-linux-sysmon` | `auditd` + `builtin` + `sysmon` | + legacy Sysmon-for-Linux XML tail (reads `/var/log/messages` or syslog) |
| `sigmacatch-linux-ebpf` | `auditd` + `builtin` + `ebpf` | + native eBPF probes (needs root/CAP_BPF+CAP_PERFMON, kernel 5.14+/BTF) |

Build a single collector in isolation:

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win --no-default-features --features etw
```

For the Linux flavours always pass an explicit `--bin`: the three binaries
share one entry point, so a superset-feature build would rebuild earlier-named
bins with the wider feature set in the shared `target/` directory.

```bash
cargo build --release -p sigmacatch-lnx --bin sigmacatch-linux --no-default-features --features auditd,builtin
cargo build --release -p sigmacatch-lnx --bin sigmacatch-linux-sysmon --no-default-features --features auditd,builtin,sysmon
cargo build --release -p sigmacatch-lnx --bin sigmacatch-linux-ebpf --no-default-features --features auditd,builtin,ebpf
```

### Diagnostics (feature `tools`)

| Command | Description |
|---|---|
| `sigmacatch-channel check` | Deep validation of `./sigma/regression_data` — every rule must match its data (exit 1 otherwise) |
| `sigmacatch-channel check-channels` | Resolve and list the channels the engine would collect |
| `sigmacatch-channel check-filter` | Validate the filter config against the real rule set (ground-truth counts) |
| `sigmacatch-channel list-rules` | List loaded rules with techniques and ART link (`--coverage` for stats) |
| `sigmacatch-channel get-atomic` | Generate a `run_atomic.ps1` (Invoke-AtomicRedTeam chain) for rules without regression data |
| `sigmacatch-linux check` / `check-filter` / `list-rules` | Same diagnostics for the Linux binaries (all 3 flavours share the same `tools` output) |

## Build & cross-compilation

Cross-compile from Linux: `cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win` (requires `cargo install cargo-xwin`; isolated builds and details in [docs/fr/build.md](docs/fr/build.md)).

> `.cargo/config.toml` forces `target-feature=+crt-static`: without it the binary depends on **VCRUNTIME140.dll** (Visual C++ Redistributable) and crashes if the runtime is missing on the target machine. With `+crt-static` the `.exe` is standalone.

## Documentation

A built version of this documentation is published to GitHub Pages: **https://frack113.github.io/sigmacatch/** (source: [`docs/fr/`](docs/fr/), English mirror in [`docs/en/`](docs/en/)).

## Workspace

The project is a cargo workspace of 14 packages (3 binary crates + 11 libraries):

| Crate | Purpose |
|---|---|
| `sigmacatch-win` | Windows binaries: `sigmacatch-channel` (winevt), `sigmacatch-etw` (ETW) + `channels.rs` / `etw/` collectors + `cli.rs` diagnostics |
| `sigmacatch-lnx` | Linux binaries (3 flavours): `sigmacatch-linux` (base), `sigmacatch-linux-sysmon` (adds legacy tail), `sigmacatch-linux-ebpf` (adds native eBPF probes) — feature-gated via `sysmon` / `ebpf`; shared `sysmon_parse.rs` always compiled |
| `sigmacatch-ebpf` | eBPF probe crate (excluded workspace, nightly, `bpfel-unknown-none`) — `execve`/`exec`/`exit`/`connect`/`openat`/`sendto`/`sendmsg` tracepoints |
| `sigmacatch-ebpf-common` | Shared `no_std` types for eBPF ring buffer (`ExecEvent`, `ExitEvent`, `NetEvent`, `FileCreateEvent`, `DnsEvent`) |
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
