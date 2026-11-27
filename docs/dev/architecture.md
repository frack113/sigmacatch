# Architecture

One binary, `sigmacatch`, captures real OS events, matches them against
[SigmaHQ](https://github.com/SigmaHQ/sigma) rules and writes regression data.
Cargo features select which inputs are compiled in and `main.rs` picks the
runtime input. A second binary, `regressiondata-check`, validates regression
data without a collector.

The cargo workspace has 20 members: the binary, the common library, the
detection engine, the runner, one crate per collector and per persist backend,
the git and regression crates, and the shared driver-protocol crate. The
nightly-only eBPF probes (`sigmacatch/ebpf`) and the Windows kernel driver
(`sigmacatch/driver`) are built outside it. The exact tree and crate graph are
in [Layout](layout.md).

The top-level layout mirrors the product's building blocks: `collector/`
(adapters in), `detection/` (domain), `runner/` (orchestration), `persist/`
(adapters out) and `common/` (the shared data models and services).

## An event's life

<!-- markdownlint-disable MD033 -->
<iframe src="../media/interactive/event-life.html?embed=1" loading="lazy" title="An event's life, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:1068/512;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*From any collector to a committed regression set; the per-stage detail is in
[Pipeline](pipeline.md).*

The collectors, the logsource injection and the regression formats are in
[Collectors](collectors/index.md); the run loop and its timeouts are in
[Pipeline](pipeline.md).

## The parts

| Part | Crate / path | Role |
|---|---|---|
| Dispatch | `sigmacatch/src/main.rs`, `src/orchestrators/mod.rs` | Runtime input selection; crate aliases and the Windows/Linux orchestrators |
| Collectors | `sigmacatch-input-*` (`collector/`) | One adapter per source; each crate owns its feature × platform gates |
| Runner | `sigmacatch-runner` (`runner/`) | `run<C: CollectorKind>`: spawn producer, drain events, generate every 30 s, final flush |
| Config + CLI | `sigmacatch-core` (`common/core/src/config.rs`, `cli.rs`) | `config.yaml`, `CliArgs`, `parse_args`, diagnostics, custom channel map |
| Rules | `sigmacatch-core` (`common/core/src/rule/`) | Load / filter / dedupe / remove ids, thresholds, ATT&CK discovery |
| Detection | `sigmacatch-detection` (`detection/`) | rsigma engine, per-platform pipelines, channel resolution |
| Regression | `common/core/src/regression/`, `sigma-regression`, `sigmacatch-output-regression` (`persist/regression`) | Shared vocabulary, `info.yml`, data formats, sink and `SigmahqRegression` |
| Git | `sigmacatch-repo` (`sigmacatch/repo/`) | grit-lib wrapper: branch, signing, transport, per-rule commits |
| Types | `sigmacatch-core` (`common/core/src/exchange.rs`, `types.rs`) | `Event`, `Alert`, XML parsing, logsource tables, `ChannelResolver` |
| EVTX | `sigmacatch-core` (`evtx_reader`), `sigmacatch-output-evtx` (`persist/evtx`) | EVTX file parsing → `Event` (reader) and the pure-Rust static-event writer |

Which collector runs:

| Input | Crate / path | Feature |
|---|---|---|
| Event Log + one process source | `sigmacatch/src/orchestrators/windows.rs` | `winevt` (+ `etw`, `driver`) |
| Event Log channels | `sigmacatch-input-winevt` (`collector/winevt`) | `winevt` |
| Native ETW + shared helpers | `sigmacatch-input-etw`, `sigmacatch-input-etw-common` (`collector/`) | `etw` |
| Kernel sensor client | `sigmacatch-input-etw-driver` (`collector/etw-driver`) | `driver` |
| Linux orchestrator | `sigmacatch/src/orchestrators/linux.rs` | `auditd`, `builtin`, `sysmon`, `ebpf` |
| auditd / syslog / Sysmon tail / eBPF + tail driver | `sigmacatch-input-{auditd,syslog,sysmon,ebpf,tail}` (`collector/`) | same |
| Endpoint Security (macOS) | `sigmacatch-input-macos` (alias `orchestrators::macos_es`) | `macos` |
| One-shot EVTX | `sigmacatch-input-evtx` (`collector/evtx`) | `evtx` |

The Windows side has its own pages: [Windows telemetry](windows/index.md)
(driver and ETW internals) and [Sysmon coverage](windows/coverage.md).

## The other binary

`regressiondata-check` (in `sigmacatch/src/bin/`) reuses `sigmacatch-detection`
plus `sigmacatch-core`'s `rule`, `regression` and `evtx_reader` modules, and
`audit_reader` for `.log` entries. The diagnostic subcommands
(`common/core/src/cli.rs`) parse their flags by hand and use `serde` for JSON
output; both are always compiled.
