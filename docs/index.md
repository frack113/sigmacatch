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
nightly-only eBPF probe crate (`sigmacatch/ebpf`); the main tree and each
module's role are detailed in [architecture.md](dev/architecture.md).

## Quick start

```bash
# Windows (default features):
cargo build --release -p sigmacatch
./target/release/sigmacatch            # Winevt live
# Linux (auditd + builtin syslog, no root):
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin
./target/release/sigmacatch            # auditd + builtin syslog
# One-shot EVTX (cross-platform):
cargo build --release -p sigmacatch --no-default-features --features evtx
./target/release/sigmacatch --evtx /path/to/evtx/dir
```

The full feature matrix (`sysmon`, `ebpf`), the `regressiondata-check`
validation binary, and the build/test commands are in [build.md](dev/build.md).
The first run generates a `config.yaml` that must be edited before the next
run — the end-to-end setup is in [Getting started](getting-started.md).

## Documentation

A built version of this documentation is published to GitHub Pages:
**https://frack113.github.io/sigmacatch/**

- **Getting started**
  - [First run](getting-started.md)
- **User**
  - [CLI](user/cli.md)
  - [Configuration](user/config.md)
  - [Troubleshooting](user/troubleshooting.md)
- **Regression data**
  - [Overview](regression_data/index.md)
  - [info.yml](regression_data/info-yml.md)
  - [Data files](regression_data/data-files.md)
  - [Validation](regression_data/validation.md)
- **Dev**
  - [Architecture](dev/architecture.md)
  - [Collectors](dev/collectors.md)
  - [Pipeline](dev/pipeline.md)
  - [Design notes](dev/design-notes.md)
  - [Build](dev/build.md)
  - [SigmaHQ workflow](dev/git.md)

## License

MIT
