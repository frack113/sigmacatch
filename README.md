<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# Sigmacatch

> ⚠️ **WIP** — this project is under active development. APIs, config, and output formats may change without notice. Not production-ready.

Capture real Windows events via the **Windows Event Log API** (`winevt`), match them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules, and output structured regression data ready for SigmaHQ PRs.

## What it does

```text
SigmaHQ rules (auto-cloned via grit-lib)
    ↓
Load rules → skip existing regression → filter Windows → apply pipeline
    ↓
Resolve channels from rules (logsource → channel mapping)
    ↓
Continuous collector (live Windows events via EvtQueryW) → mpsc
    ↓
Sigma engine evaluates every event against all loaded rules
    ↓
Every 30s: generate regression triplet for each matched rule
    ↓
sigma/regression_data/<rule_rel_path>/
    ├── <rule_id>.json    ← flat event (Sigma keys)
    ├── <rule_id>.evtx    ← valid EVTX (via EvtExportLog, validated ≥1 record; no data on non-Windows)
    └── info.yml          ← SigmaHQ-compatible metadata
    ↓
commit + push to fork (continuous until Ctrl+C)
```

## Quick start

```bash
cargo build --release
./target/release/sigmacatch
```

On first run, a `config.yaml` is created with defaults:

```yaml
git:
  author: "your-username"
  email: "you@example.com"
  github_token: ""          # GitHub token (or set GITHUB_TOKEN env var) — required for HTTP transport when network is active
  transport: http           # http or ssh
  ssh_key_path: ""          # path to SSH private key (optional, only needed for SSH)
  sigma_repo_url: "https://github.com/SigmaHQ/sigma.git"
  sigma_repo_path: "sigma"
  offline: false            # true = skip pull at startup (use existing repo as-is)
  contrib: true             # true = push commits to remote fork. Default: false (local commits only)
log:
  level_file: "debug"
filter:
  product: windows          # windows, linux, or macos
  min_status: "stable"      # load rules with status >= this threshold
  min_level: "critical"     # load rules with level >= this threshold
  author: ""                # filter rules by author (optional, empty = no filter)
  max_rule_size: 1048576    # bytes (1MB default)
```

Rules below the configured `min_status` / `min_level` thresholds are skipped at load time.
Rules missing a `status` or `level` field are always accepted.

**Contrib is opt-in** (`git.contrib: true` or `--contrib`): pushes regression commits to your fork. By default (`false`) commits stay local. The GitHub token is only required when a network operation is active (`offline: false` or `contrib: true`).

### CLI flags

| Flag | Description |
|------|-------------|
| `--author <name>` | Override detected username |
| `--dry-run` | Git diagnostics only (no collection) |
| `--channels-only` | List resolved channels and exit (no collection) |
| `--all-rules` | Load all rules — skip set is disabled |
| `--list-rules` | List rules without regression data, showing techniques (attack.* tags) and ART link (no collection) |
| `--offline` | Skip pull at startup (use existing repo as-is) |
| `--contrib` | Enable push to the remote fork for this run |
| `--help`, `-h` | Print help and exit |

## Git clone performance (grit-lib vs native git)

The Sigma repo (~131K objects) is cloned and pulled through grit-lib (pure Rust, no git CLI). A **fresh clone** is slower and larger than a native `git clone`:

| | `git clone` (native, single-branch) | sigmacatch (grit-lib + pack) |
|---|---|---|
| Time | ~3s | ~70s |
| `.git/` size | 52 MB | 218 MB |
| Pack file | 47 MB (delta-compressed) | 215 MB (no delta) |
| `git fsck --strict` | clean | clean |

Why the difference:

- Native git writes the server's already delta-compressed pack directly to disk — no post-processing.
- grit-lib's `http_fetch` unpacks every object to a loose file (131K files, ~650 MB), then sigmacatch re-packs them (no delta compression) to keep `.git/` small (218 MB vs 650 MB, 3x).

The download itself is identical (~47 MB); the gap is local post-processing, inherent to grit-lib. This cost is paid **once at first clone** — subsequent pulls only transfer deltas (sub-second when nothing changed). On a slow VM the first clone can take a few minutes.

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
| Tools | [EN](docs/en/tools.md) | [FR](docs/fr/tools.md) |

## Workspace

The project is a cargo workspace of 11 crates (9 libraries + 2 binary crates):

| Crate | Purpose |
|---|---|
| `sigmacatch` | Binary + orchestration (continuous loop) |
| `sigmacatch-config` | Config YAML + CLI parsing + custom_channels.yaml + dry-run git diagnostics |
| `sigmacatch-logger` | Two-layer tracing subscriber (stderr info + daily rolling file debug) |
| `sigmacatch-rule` | `SigmahqRules`: rule loading, filtering, deduplication, channel resolution |
| `sigmacatch-detection` | Thin wrapper around rsigma-eval (pipelines, bloom, LogSourceExtractor) |
| `input-windows-channels` | Multi-channel Winevt collector (EvtQueryW/EvtNext/EvtRender) |
| `sigmacatch-regression` | `SigmahqRegression`, `InfoYml`, regression triplet generation |
| `sigmacatch-types` | Shared types: `Event`, `Alert`, `RegressionHeader`, XML parsing, logsource tables |
| `sigmacatch-repo` | grit-lib wrapper: SigmaRepo, GitHub fork detection, commit workflow |
| `input-evtx` | Parse EVTX files into `Event` objects for the detection engine |
| `localcheck` | Dev tools: `check_filter` (filter validation) + `check_evtx` (regression validation) |

## Built with

- [rsigma-eval](https://crates.io/crates/rsigma-eval) + [rsigma-parser](https://crates.io/crates/rsigma-parser) — Sigma rule loading and evaluation
- [grit-lib](https://github.com/anoma/grit-lib) — pure Rust git, no CLI needed
- [tokio](https://crates.io/crates/tokio) — async runtime
- [windows](https://crates.io/crates/windows) — Windows Event Log API, cfg-gated
- [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) / [yaml_serde](https://crates.io/crates/yaml_serde) — serialization
- [roxmltree](https://crates.io/crates/roxmltree) — XML parsing for Winevt events
- [evtx](https://crates.io/crates/evtx) — EVTX file parsing

## License

MIT
