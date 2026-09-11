# Sigmacatch

Headless tool that captures real OS events: **Windows Event Log API**
(`winevt`), **EVTX files** one-shot (cross-platform), and on Linux **auditd**,
**builtin syslog** (central, authpriv and cron files), **Sysmon-for-Linux**
(XML tail) and **native eBPF probes**. It matches them against
[SigmaHQ](https://github.com/SigmaHQ/sigma) rules and outputs structured
regression data ready for SigmaHQ PRs.

One binary named `sigmacatch`: the inputs are selected at compile time by cargo
features and at runtime by the `--evtx` argument (one-shot EVTX), otherwise the
live Winevt collector on Windows and every compiled, available Linux input in
parallel.

The project is a single cargo workspace package (`sigmacatch`), plus a nested
nightly-only eBPF probe crate (`sigmacatch/ebpf`); the full tree and each
module's role are detailed in [architecture.md](architecture.md).

## Quick start

```bash
cargo build --release -p sigmacatch                          # Windows input (default features)
./target/release/sigmacatch                                  # Winevt (Windows)
# Linux — build with the wanted inputs (e.g. auditd + builtin syslog):
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin
./target/release/sigmacatch                                  # auditd + syslog builtin (Linux, no root)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,sysmon     # + Sysmon-for-Linux tail (Linux)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,ebpf       # + native eBPF probes (root + nightly required — separate build, never merged with sysmon)
# One-shot EVTX, any platform:
cargo build --release -p sigmacatch --no-default-features --features evtx
./target/release/sigmacatch --evtx /path/to/evtx/dir
cargo build --release -p sigmacatch --bin regressiondata-check # Cross-platform regression validation (Linux & Windows)
```

## Documentation

A built version of this documentation is published to GitHub Pages:
**https://frack113.github.io/sigmacatch/**

| | Français | English |
|---|---|---|
| Architecture | [FR](../fr/architecture.md) | [EN](architecture.md) |
| Build | [FR](../fr/build.md) | [EN](build.md) |
| CLI | [FR](../fr/cli.md) | [EN](cli.md) |
| Git | [FR](../fr/git.md) | [EN](git.md) |
| Output format | [FR](../fr/output-format.md) | [EN](output-format.md) |
| Regression data format | [FR](../fr/regression-data-format.md) | [EN](regression-data-format.md) |

## License

MIT
