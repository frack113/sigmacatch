<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# Sigmacatch

> ⚠️ **WIP** — this project is under active development. APIs, config, and output formats may change without notice. Not production-ready.

Sigmacatch captures real OS events, matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules in real time, and generates regression data ready for SigmaHQ pull requests.

| Platform | Input (cargo feature) | Default? | Status |
|---|---|---|---|
| Windows | Windows Event Log API (`winevt`) | yes | working |
| Windows | native ETW, no Sysmon (`etw`) | no | working (VM-validated) |
| Windows | kernel driver, Sysmon-schema telemetry (`driver`, implies `etw`) | no | working (test-signed, VM-validated) |
| any | one-shot EVTX files (`evtx`, pure Rust) | no | working |
| Linux | auditd + builtin syslog (`auditd`, `builtin`, no root needed) | no | working (VM-validated) |
| Linux | legacy Sysmon-for-Linux XML tail (`sysmon`) | no | need user return |
| Linux | native eBPF probes — process/network/file/DNS (`ebpf`) | no | working (VM-validated) |

One binary named `sigmacatch` (plus the standalone `regressiondata-check` validator);
the features you compile in determine which inputs run. At runtime `--evtx <PATH>`
selects the one-shot EVTX input, Windows runs the Event Log channels next to exactly
one process source (the kernel driver when it is loaded, native ETW otherwise), and
Linux runs every compiled, available input in parallel.

## Requirements

- **Windows** — no Sysmon required. The `winevt` feature reads the Event Log channels;
  `etw` adds native ETW telemetry and `driver` the `sigmacatch` kernel driver (Sysmon-schema
  events under the `sigmacatch/Operational` channel). The driver is test-signed: it needs a
  Windows host with the WDK to build and test-signing enabled to load. Sysmon, when
  installed, is simply another Event Log channel.
- **Linux** with `auditd` running or a syslog source (`/var/log/messages` or `/var/log/syslog`, optionally authpriv/cron files) — `auditd`/`builtin` features; [Sysmon for Linux](https://github.com/SysmonForLinux/SysmonForLinux) optional via `sysmon`; native eBPF probes via `ebpf` (root or CAP_BPF+CAP_PERFMON at runtime, kernel 5.14+/BTF, nightly build toolchain). eBPF regression data is JSON for one event and NDJSON for several.
- Rust 2024 edition (1.96+ — MSRV imposed by rsigma 0.26)
- Admin rights for the `Security` and `System` Event Log channels (Windows), and an elevated token for ETW (the ETW source fails with a clear message otherwise)

## Quick start

```bash
cargo build --release -p sigmacatch                          # Windows input (default features)
./target/release/sigmacatch                                  # Winevt collector (Windows)
# Windows without Sysmon (Event Log + ETW, optionally + kernel driver):
cargo build --release -p sigmacatch --features etw
cargo build --release -p sigmacatch --features etw,driver
# Linux — build with the wanted inputs (e.g. auditd + builtin syslog):
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin
./target/release/sigmacatch                                  # auditd + builtin syslog (Linux, no root)
# One-shot EVTX, any platform:
cargo build --release -p sigmacatch --no-default-features --features evtx
./target/release/sigmacatch --evtx /path/to/evtx/dir
```

On first run a `config.yaml` is created with placeholder defaults, and the run stops (`exit 1`)
until you edit it — `author: sigmacatch` (placeholder, rejected by validation) and an empty
`email` both bail. On Linux, also set `filter.product: linux` or omit the key: the collector
uses `linux` as its default, but an explicit `product: windows` in the generated file is kept.
The full reference (every field, defaults, and validation) is in the
[Configuration reference](docs/user/config.md).

**Contrib is opt-in** (`git.contrib: true` or `--contrib`): pushes regression commits to your fork over SSH. By default (`false`) commits stay local. Authentication is SSH-only — the SSH agent, or `git.ssh_key_path`; there is no GitHub token. Clone/fetch use `git.sigma_repo_url` (default `git@github.com:SigmaHQ/sigma.git`), push and pending-branch fetch use `git.fork_repo_url` (default `git@github.com:<author>/sigma.git`). **`offline: true` neutralizes `contrib`** (forced to `false`): no push in offline mode.

**Performance options** (config.yaml):

- `git.shallow_clone: true` (default) — depth=1 initial clone, unshallow before push
- `hir_cache: ""` — persistent HIR cache path to warm-start the detection engine (skip rule recompilation); also via `--hir-cache <PATH>` CLI flag

## CLI

Flags, the `check-filter`/`list-rules` diagnostics subcommands, and the standalone
`regressiondata-check` validator (EVTX, log, JSON and NDJSON replay) are documented in
[`docs/user/cli.md`](docs/user/cli.md) and the dedicated [diagnostics](docs/user/diagnostics.md) and [`regressiondata-check`](docs/user/regressiondata-check.md) pages.

## Documentation

A built version of this documentation is published to GitHub Pages: **https://frack113.github.io/sigmacatch/** (source: [`docs/`](docs/)).

## Workspace

A single cargo workspace package (`sigmacatch`), plus two crates built outside the workspace: the nightly-only eBPF probe crate (`sigmacatch/ebpf`) and the Windows kernel driver (`sigmacatch/driver`). The full layout — directory tree, cargo features, and the two binaries — is in [docs/dev/architecture.md](docs/dev/architecture.md).

## Built with

- [rsigma-eval](https://crates.io/crates/rsigma-eval) + [rsigma-parser](https://crates.io/crates/rsigma-parser) — Sigma rule loading and evaluation
- [grit-lib](https://github.com/gitbutlerapp/grit) — pure Rust git, no CLI needed
- [tokio](https://crates.io/crates/tokio) — async runtime
- [windows](https://crates.io/crates/windows) — Event Log, ETW/TDH and kernel-driver client APIs, cfg-gated
- [aya](https://crates.io/crates/aya) — eBPF object loading and ring-buffer dispatch
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
