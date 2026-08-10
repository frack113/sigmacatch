# Sigmacatch

Headless tool that captures real Windows events via the **Windows Event Log API** (`winevt`), matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules, and outputs structured regression data ready for SigmaHQ PRs.

## Workspace

The project is a cargo workspace of 11 crates (9 libraries + 2 binary crates):

| Crate | Purpose |
|---|---|
| `sigmacatch` | Binary + orchestration (continuous loop) |
| `sigmacatch-config` | Config YAML + CLI parsing + custom_channels.yaml + dry-run git diagnostics |
| `sigmacatch-logger` | Two-layer tracing subscriber (stderr info + daily rolling file debug) |
| `sigmacatch-rule` | `SigmahqRules`: rule loading, filter, dedupe, remove_id + `SigmaRuleExt` (ATT&CK techniques) |
| `sigmacatch-detection` | Thin wrapper around rsigma-eval (pipelines, bloom, LogSourceExtractor, resolve_channels) |
| `input-windows-channels` | Multi-channel Winevt collector (EvtQueryW/EvtNext/EvtRender) |
| `sigmacatch-regression` | `SigmahqRegression`, `InfoYml`, regression triplet generation |
| `sigmacatch-types` | Shared types: `Event`, `Alert`, `RegressionHeader`, XML parsing, logsource tables |
| `sigmacatch-repo` | grit-lib wrapper: SigmaRepo, git operations |
| `input-evtx` | Parse EVTX files into `Event` objects (used by `tools`) |
| `tools` | Dev tools: `check_dry_run`, `check_channels`, `list_rules`, `check_filter`, `check_evtx`, `get_atomic`, `coverage` |

## Quick start

```bash
cargo build --release
./target/release/sigmacatch
```

## Documentation

A built version of this documentation is published to GitHub Pages: **https://frack113.github.io/sigmacatch/**

| | English | Francais |
|---|---|---|
| Architecture | [EN](architecture/) | [FR](fr/architecture/) |
| Architecture reference | [EN](architecture-reference/) | [FR](fr/architecture-reference/) |
| Build | [EN](build/) | [FR](fr/build/) |
| Git | [EN](git/) | [FR](fr/git/) |
| Output format | [EN](output-format/) | [FR](fr/output-format/) |
| Regression data format | [EN](regression-data-format/) | [FR](fr/regression-data-format/) |
| Nice-to-have | [EN](nice-to-have/) | [FR](fr/nice-to-have/) |
| Tools | [EN](tools/) | [FR](fr/tools/) |

## License

MIT
