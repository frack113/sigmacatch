# Sigmacatch

Headless tool that captures real OS events: on Windows the **Windows Event Log
API** (`winevt`), **native ETW** (`etw`) and the **`sigmacatch` kernel driver**
(`driver`) — no Sysmon required; **EVTX files** one-shot (cross-platform); and
on Linux **auditd**, **builtin syslog** (central, authpriv and cron files),
**Sysmon-for-Linux** (XML tail) and **native eBPF probes**. It matches them
against [SigmaHQ](https://github.com/SigmaHQ/sigma) rules and outputs structured
regression data ready for SigmaHQ PRs.

One binary named `sigmacatch`: the inputs are selected at compile time by cargo
features and at runtime by the `--evtx` argument (one-shot EVTX). Otherwise the
Windows collector runs the Event Log channels next to exactly one process source
(the kernel driver when it is loaded, native ETW otherwise), and on Linux every
compiled, available input runs in parallel.

The project is a single cargo workspace package (`sigmacatch`), plus two nested
crates built outside the workspace — the nightly-only eBPF probes
(`sigmacatch/ebpf`) and the Windows kernel driver (`sigmacatch/driver`). The main
tree and each module's role are detailed in
[architecture.md](dev/architecture.md).

## Quick start

```bash
# Windows (default features — Event Log channels):
cargo build --release -p sigmacatch
./target/release/sigmacatch            # winevt

# Windows without Sysmon (Event Log + ETW, or + kernel driver):
cargo build --release -p sigmacatch --features etw
cargo build --release -p sigmacatch --features etw,driver

# Linux (auditd + builtin syslog, no root):
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin
./target/release/sigmacatch            # auditd + builtin syslog

# One-shot EVTX (cross-platform):
cargo build --release -p sigmacatch --no-default-features --features evtx
./target/release/sigmacatch --evtx /path/to/evtx/dir
```

The full feature matrix (`sysmon`, `ebpf`), the kernel-driver build, the
`regressiondata-check` validation binary and the build/test commands are in
[build.md](dev/build.md). The first run generates a `config.yaml` that must be
edited before the next run — the end-to-end setup is in
[Getting started](getting-started.md).

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
  - [Windows without Sysmon](dev/etw-collector.md)
  - [Sysmon vs sigmacatch](dev/sysmon-vs-sigmacatch.md)
  - [Pipeline](dev/pipeline.md)
  - [Design notes](dev/design-notes.md)
  - [Build](dev/build.md)
  - [Windows dev VM](dev/windows-vm.md)
  - [SigmaHQ workflow](dev/git.md)

## License

MIT
