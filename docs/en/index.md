# Sigmacatch

Headless tool that captures real Windows events via the **Windows Event Log API**
(`winevt`) or **direct ETW** (`ferrisetw`), or Linux events via **auditd**, **builtin
syslog** (central, authpriv and cron files) and **Sysmon-for-Linux**. It matches them
against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules and outputs structured
regression data ready for SigmaHQ PRs.

The project is a cargo workspace of 14 packages, plus 1 excluded nightly crate (`sigmacatch-ebpf`);
the full tree and each crate's role are detailed in [architecture.md](architecture.md).

## Quick start

```bash
cargo build --release
./target/release/sigmacatch-channel       # Winevt (Windows)
./target/release/sigmacatch-etw           # ETW direct (Windows)
./target/release/sigmacatch-linux         # auditd + syslog builtin (Linux, no root)
./target/release/sigmacatch-linux-sysmon  # + tail Sysmon-for-Linux (Linux)
./target/release/sigmacatch-linux-ebpf    # + native eBPF probes (Linux, root required)
cargo build --release -p regressiondata-check # Cross-platform regression validation (Linux & Windows)
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
