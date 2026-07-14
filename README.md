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
    ├── <rule_id>.evtx    ← valid EVTX (via EvtWriteFile)
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
offline: false
log:
  level_file: "debug"
```

### CLI flags

| Flag | Description |
|------|-------------|
| `--author <name>` | Override detected username |
| `--offline` | Use existing SigmaHQ repo (no git fetch) |
| `--create-config` | Create `config.yaml` with defaults |

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

| | English | Francais |
|---|---|---|
| Architecture | [EN](docs/en/architecture.md) | [FR](docs/fr/architecture.md) |
| Architecture reference | [EN](docs/en/architecture-reference.md) | [FR](docs/fr/architecture-reference.md) |
| Build | [EN](docs/en/build.md) | [FR](docs/fr/build.md) |
| Output format | [EN](docs/en/output-format.md) | [FR](docs/fr/output-format.md) |
| Regression data format | [EN](docs/en/regression-data-format.md) | [FR](docs/fr/regression-data-format.md) |

## License

MIT
