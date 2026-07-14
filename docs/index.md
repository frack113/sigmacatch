# Sigmacatch

Headless tool that captures real Windows events via the **Windows Event Log API** (`winevt`), matches them against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules, and outputs structured regression data ready for SigmaHQ PRs.

## Quick start

```bash
cargo build --release
./target/release/sigmacatch
```

## Documentation

| | English | Francais |
|---|---|---|
| Architecture | [EN](en/architecture.md) | [FR](fr/architecture.md) |
| Architecture reference | [EN](en/architecture-reference.md) | [FR](fr/architecture-reference.md) |
| Build | [EN](en/build.md) | [FR](fr/build.md) |
| Output format | [EN](en/output-format.md) | [FR](fr/output-format.md) |
| Regression data format | [EN](en/regression-data-format.md) | [FR](fr/regression-data-format.md) |

## License

MIT
