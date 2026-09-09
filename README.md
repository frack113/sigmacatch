<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# Sigmacatch

> ⚠️ **WIP** — this project is under active development. APIs, config, and output formats may change without notice. Not production-ready.

Sigmacatch captures real OS events, matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules in real time, and generates regression data ready for SigmaHQ pull requests.

| Platform | Input (cargo feature) | Default? | Status |
|---|---|---|---|
| Windows | Windows Event Log API (`winevt`) | yes | working |
| any | one-shot EVTX files (`evtx`, pure Rust) | no | working |
| Linux | auditd + builtin syslog (`auditd`, `builtin`, no root needed) | no | need user return |
| Linux | legacy Sysmon-for-Linux XML tail (`sysmon`) | no | need user return |
| Linux | native eBPF probes — process/network/file/DNS (`ebpf`) | no | need user return |

One binary named `sigmacatch`; the features you compile in determine which
inputs run. At runtime `--evtx <PATH>` selects the one-shot EVTX input,
Windows defaults to the live Winevt collector, and Linux runs every compiled,
available input in parallel.

## Requirements

- **Windows** with [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) installed — required for rich events (ParentImage, CommandLine, hashes, etc.)
- **Linux** with `auditd` running or a syslog source (`/var/log/messages` or `/var/log/syslog`, optionally authpriv/cron files) — `auditd`/`builtin` features; [Sysmon for Linux](https://github.com/SysmonForLinux/SysmonForLinux) optional via `sysmon`; native eBPF probes via `ebpf` (root or CAP_BPF+CAP_PERFMON at runtime, kernel 5.14+/BTF, nightly build toolchain)
- Rust 2024 edition (1.85+)
- Admin rights for the `Security` and `System` Event Log channels (Windows)

## Quick start

```bash
cargo build --release -p sigmacatch                          # Windows input (default features)
./target/release/sigmacatch                                  # Winevt collector (Windows)
# Linux — build with the wanted inputs (e.g. auditd + builtin syslog):
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin
./target/release/sigmacatch                                  # auditd + builtin syslog (Linux, no root)
# One-shot EVTX, any platform:
cargo build --release -p sigmacatch --no-default-features --features evtx
./target/release/sigmacatch --evtx /path/to/evtx/dir
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
| `--evtx <PATH>` | One-shot EVTX input: process the directory, generate regression data, exit (needs `evtx` feature) |
| `--help`, `-h` | Print help and exit |

Diagnostics subcommands (`check-filter`, `list-rules`) are always compiled into
the `sigmacatch` binary; regression validation is the standalone cross-platform
`regressiondata-check` binary — see [docs/en/cli.md](docs/en/cli.md).

## Documentation

A built version of this documentation is published to GitHub Pages: **https://frack113.github.io/sigmacatch/** (source: [`docs/fr/`](docs/fr/), English mirror in [`docs/en/`](docs/en/)).

## Workspace

The project is a cargo workspace of 12 packages, plus 1 excluded nightly crate (`sigmacatch-ebpf`):

| Crate | Purpose |
|---|---|
| `sigmacatch` | Single binary. Inputs are cargo features: `winevt` (default), `evtx`, `auditd`, `builtin` (syslog), `sysmon` (legacy tail), `ebpf` (native probes) |
| `sigmacatch-ebpf` | eBPF probe crate (excluded workspace, nightly, `bpfel-unknown-none`) |
| `sigmacatch-ebpf-common` | Shared `no_std` types for eBPF ring buffer |
| `sigmacatch-runner` | Shared pipeline (`run<C: CollectorKind>`): config, repo init, event loop, generation, commit/push |
| `sigmacatch-config` | Config YAML + CLI parsing + custom_channels.yaml |
| `sigmacatch-rule` | `SigmahqRules`: rule loading, filtering, deduplication, remove_id |
| `sigmacatch-detection` | `DetectionEngine` + per-platform pipelines + channel_resolver + bloom pre-filter |
| `sigmacatch-regression` | `SigmahqRegression`, `InfoYml`, `DataFormat` (Evtx/Log) + validation + pure-Rust EVTX writer (`evtx_writer`) |
| `sigmacatch-types` | Shared types: `Event`, `Alert`, `RegressionHeader`, XML parsing, logsource mapping tables (phf) |
| `sigmacatch-repo` | grit-lib wrapper: `SigmaRepo`, GitHub fork detection, plumbing/porcelain git ops, SSH signing |
| `input-windows-evtx` | Parse EVTX files into `Event` objects (used by `sigmacatch` and `regressiondata-check`) |
| `regressiondata-check` | Standalone cross-platform binary: regression validation (`--json`/`--ignore`) |

## Built with

- [rsigma-eval](https://crates.io/crates/rsigma-eval) + [rsigma-parser](https://crates.io/crates/rsigma-parser) — Sigma rule loading and evaluation
- [grit-lib](https://github.com/gitbutlerapp/grit) — pure Rust git, no CLI needed
- [tokio](https://crates.io/crates/tokio) — async runtime
- [windows](https://crates.io/crates/windows) — Windows Event Log API, cfg-gated
- [linux-audit-parser](https://crates.io/crates/linux-audit-parser) — auditd log parsing
- [regex](https://crates.io/crates/regex) — RFC3164 syslog line parsing (builtin collector)
- [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) / [serde_yaml](https://crates.io/crates/serde_yaml) — serialization
- [roxmltree](https://crates.io/crates/roxmltree) — XML parsing for Winevt events
- [evtx](https://crates.io/crates/evtx) — EVTX file parsing

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT

## Releases

See [CHANGELOG.md](CHANGELOG.md) for version history.

Current release: **v0.5.4** (2026-09-04)

Recent tags:

- v0.5.4 — JSONL support, lenient engine, info.yml validation, failed rules API
- v0.5.3 — regressiondata-check rename, --fix/--json/--ignore flags
- v0.5.2 — dependency updates
- v0.5.1 — various fixes
- v0.5.0 — native eBPF sysmon input, 3 release binaries

Full history: `git tag -l` or GitHub Releases page.
