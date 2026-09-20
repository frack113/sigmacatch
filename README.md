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

One binary named `sigmacatch` (plus the standalone `regressiondata-check` validator);
the features you compile in determine which inputs run. At runtime `--evtx <PATH>`
selects the one-shot EVTX input, Windows defaults to the live Winevt collector, and
Linux runs every compiled, available input in parallel.

## Requirements

- **Windows** with [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) installed — required for rich events (ParentImage, CommandLine, hashes, etc.)
- **Linux** with `auditd` running or a syslog source (`/var/log/messages` or `/var/log/syslog`, optionally authpriv/cron files) — `auditd`/`builtin` features; [Sysmon for Linux](https://github.com/SysmonForLinux/SysmonForLinux) optional via `sysmon`; native eBPF probes via `ebpf` (root or CAP_BPF+CAP_PERFMON at runtime, kernel 5.14+/BTF, nightly build toolchain)
- Rust 2024 edition (1.95+ — MSRV imposed by rsigma 0.22)
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
`email` both bail. The full reference (every field, defaults, and validation) is in the
[Configuration reference](docs/en/config.md).

**Contrib is opt-in** (`git.contrib: true` or `--contrib`): pushes regression commits to your fork. By default (`false`) commits stay local. The GitHub token is only required when a network operation is active (`offline: false` or `contrib: true`). **`offline: true` neutralizes `contrib`** (forced to `false`): no push in offline mode.

## CLI

Flags, the `check-filter`/`list-rules` diagnostics subcommands, and the standalone
`regressiondata-check` validator are documented in [docs/en/cli.md](docs/en/cli.md).

## Documentation

A built version of this documentation is published to GitHub Pages: **https://frack113.github.io/sigmacatch/** (source: [`docs/fr/`](docs/fr/), English mirror in [`docs/en/`](docs/en/)).

## Workspace

A single cargo workspace package (`sigmacatch`), plus a nested nightly-only eBPF probe crate (`sigmacatch/ebpf`) excluded from the workspace. The full layout — directory tree, cargo features, and the two binaries — is in [docs/en/architecture.md](docs/en/architecture.md).

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

Version history see [CHANGELOG.md](CHANGELOG.md).
