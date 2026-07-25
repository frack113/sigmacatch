# Sigmacatch

Headless tool that captures real Windows events via the **Windows Event Log API** (`winevt`), matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules, and outputs structured regression data ready for SigmaHQ PRs.

## Workspace

The project is a cargo workspace of 7 crates:

| Crate | Purpose |
|---|---|
| `sigmacatch` | Binary + pipeline, all orchestration |
| `detection-engine` | Thin wrapper around rsigma-eval for loading pipelines and rules, then evaluating events |
| `input-windows-channels` | Multi-channel Windows Event Log collector (EvtQueryW, EvtNext, EvtRender) |
| `input-evtx` | Parse EVTX files into `Event` objects for the detection engine |
| `sigma-mapping` | LogSource resolution, taxonomy tables, custom channel mappings |
| `sigma-regression` | SigmaHQ regression data format (InfoYml, SkipSet, triplet) |
| `sigmacatch-types` | Shared types: Event, Alert, RegressionHeader, XML/JSON parsing |

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
| Output format | [EN](output-format/) | [FR](fr/output-format/) |
| Regression data format | [EN](regression-data-format/) | [FR](fr/regression-data-format/) |
| Nice-to-have | [EN](nice-to-have/) | [FR](fr/nice-to-have/) |

## License

MIT
