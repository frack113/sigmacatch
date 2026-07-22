# Sigmacatch

Headless tool that captures real Windows events via the **Windows Event Log API** (`winevt`), matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules, and outputs structured regression data ready for SigmaHQ PRs.

## Workspace

The project is a cargo workspace of 4 crates:

| Crate | Purpose |
|---|---|
| `sigmacatch` | Binary + pipeline, all orchestration |
| `winevt-xml` | `WinevtEvent` struct + XML/JSON parsing |
| `sigma-mapping` | LogSource resolution, taxonomy tables, custom mappings |
| `sigma-regression` | SigmaHQ regression data format (InfoYml, SkipSet, triplet) |

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
