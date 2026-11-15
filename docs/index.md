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

<!-- markdownlint-disable MD033 -->
<iframe src="media/interactive/docs-map-user.html?embed=1" loading="lazy" title="User documentation map, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:1212/690;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*Use, configure and fix: the everyday pages.*

<!-- markdownlint-disable MD033 -->
<iframe src="media/interactive/docs-map-dev.html?embed=1" loading="lazy" title="Developer documentation map, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:1185/1122;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*Architecture, collectors and Windows telemetry, with the reference pages kept
apart.*

One question per page, 32 pages in five groups. The
[complete map](media/interactive/docs-map.html) puts both halves in one
diagram; drag to pan, scroll to zoom, and the Flow animation starts on its own.

A built version of this documentation is published to GitHub Pages:
**https://frack113.github.io/sigmacatch/**

## License

MIT
