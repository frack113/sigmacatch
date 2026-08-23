# Sigmacatch

Headless tool that captures real Windows events via the **Windows Event Log API**
(`winevt`) or **direct ETW** (`ferrisetw`), or Linux events via **auditd**, **builtin
syslog** (central, authpriv and cron files) and **Sysmon-for-Linux**. It matches them
against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules and outputs structured
regression data ready for SigmaHQ PRs.

The project is a cargo workspace of 12 packages; the full tree and each crate's role are
detailed in [architecture.md](en/architecture.md).

## Quick start

```bash
cargo build --release
./target/release/sigmacatch-channel   # Winevt (Windows)
./target/release/sigmacatch-etw       # Direct ETW (Windows)
./target/release/sigmacatch-linux     # auditd + syslog + sysmon (Linux)
```

## Documentation

A built version of this documentation is published to GitHub Pages:
**https://frack113.github.io/sigmacatch/**

| | English | Français |
|---|---|---|
| Architecture | [EN](en/architecture.md) | [FR](fr/architecture.md) |
| Build | [EN](en/build.md) | [FR](fr/build.md) |
| CLI | [EN](en/cli.md) | [FR](fr/cli.md) |
| Git | [EN](en/git.md) | [FR](fr/git.md) |
| Output format | [EN](en/output-format.md) | [FR](fr/output-format.md) |
| Regression data format | [EN](en/regression-data-format.md) | [FR](fr/regression-data-format.md) |

## License

MIT
