<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# Sigmacatch

Capture real Windows events via the **Windows Event Log API** (`winevt`), match them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules, and output structured regression data ready for SigmaHQ PRs.

## What it does

```
SigmaHQ rules (auto-cloned)
    ↓
WinevtCollector (live Windows events)
    ↓
Sigma engine evaluation (every event against all rules)
    ↓
regression_data/<rule>/
    ├── <rule_id>.json    ← flat event (Sigma keys)
    ├── <rule_id>.evtx    ← valid EVTX (via EvtExportLog) or .xml fallback
    └── info.yml          ← SigmaHQ-compatible metadata
```

## Quick start

```bash
cargo build --release
./target/release/sigmacatch
```

On first run, a `config.yaml` is created with defaults:

```yaml
author: "your-username"
email: "you@example.com"
github_token: ""          # GitHub token (or set GITHUB_TOKEN env var) — required for fork push
log:
  level_file: "debug"
sigma:
  min_status: "stable"    # load rules with status >= this threshold
  min_level: "critical"   # load rules with level >= this threshold
```

Rules below the configured `min_status` / `min_level` thresholds are skipped at load time.
Rules missing a `status` or `level` field are always accepted.

### CLI flags

| Flag | Description |
|------|-------------|
| `--author <name>` | Override detected username |

## Requirements

- **Windows** with [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) installed — required for rich events (ParentImage, CommandLine, hashes, etc.)
- Rust 2021 edition (1.70+)
- Admin rights for `Security` and `System` Event Log channels

## Cross-compilation (Linux → Windows)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

> Nécessite `cargo install cargo-xwin`. Télécharge automatiquement le Windows SDK.

On Linux/macOS the collector is a stub (returns empty vec) — the pipeline still runs end-to-end for testing.

## Documentation

A built version of this documentation is published to GitHub Pages: **https://frack113.github.io/sigmacatch/**

| | English | Francais |
|---|---|---|
| Architecture | [EN](docs/en/architecture.md) | [FR](docs/fr/architecture.md) |
| Architecture reference | [EN](docs/en/architecture-reference.md) | [FR](docs/fr/architecture-reference.md) |
| Build | [EN](docs/en/build.md) | [FR](docs/fr/build.md) |
| Output format | [EN](docs/en/output-format.md) | [FR](docs/fr/output-format.md) |
| Regression data format | [EN](docs/en/regression-data-format.md) | [FR](docs/fr/regression-data-format.md) |
| Nice-to-have | [EN](docs/en/nice-to-have.md) | [FR](docs/fr/nice-to-have.md) |

## Built with

- [rsigma-eval](https://crates.io/crates/rsigma-eval) + [rsigma-parser](https://crates.io/crates/rsigma-parser) — Sigma rule loading and evaluation (rule engine, `parse_sigma_yaml`, `add_collection`)
- [grit-lib](https://github.com/anoma/grit-lib) — pure Rust git library for clone, fetch, push, branch, commit, checkout. No `git` CLI needed.
- [tokio](https://crates.io/crates/tokio) — async runtime for git ops and orchestration
- [windows](https://crates.io/crates/windows) — Windows Event Log API (`EvtQueryW`/`EvtNext`/`EvtRender`/`EvtExportLog`), cfg-gated
- [rayon](https://crates.io/crates/rayon) — parallel rule parsing
- [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) / [serde_yaml](https://crates.io/crates/yaml_serde) — config and event/regression serialization
- [tracing](https://crates.io/crates/tracing) + [tracing-subscriber](https://crates.io/crates/tracing-subscriber) — logging

## License

MIT
