# Architecture

One binary, `sigmacatch`, captures real OS events, matches them against
[SigmaHQ](https://github.com/SigmaHQ/sigma) rules and writes regression data.
Cargo features select which inputs are compiled in and `main.rs` picks the
runtime input. A second binary, `regressiondata-check`, validates regression
data without a collector.

The project is a single cargo workspace package, plus two crates built outside
the workspace: the nightly-only eBPF probes (`sigmacatch/ebpf`) and the Windows
kernel driver (`sigmacatch/driver`). The exact tree and module graph are in
[Layout](layout.md).

## An event's life

```text
collector            one adapter (channels, driver, ETW, tail, eBPF, EVTX)
  ↓ Event            parsed event + injected logsource (product/service/category)
runner               shared pipeline: mpsc → DetectionEngine
  ↓ Alert            rule matched, with the original payload
regression           one set per rule: info.yml + .evtx/.log/.json
  ↓
git                  one commit per rule, one push if contrib is on
```

The collectors, the logsource injection and the regression formats are in
[Collectors](collectors/index.md); the run loop and its timeouts are in
[Pipeline](pipeline.md).

## The parts

| Part | Module | Role |
|---|---|---|
| Collectors | `inputs/` | One adapter per source; the feature × platform gate matrix is `inputs/mod.rs` |
| Runner | `runner.rs` | `run<C: CollectorKind>`: spawn producer, drain events, generate every 30 s, final flush |
| Config | `config.rs` | `config.yaml`, `CliArgs`, `parse_args`, custom channel map |
| Rules | `rule/` | Load / filter / dedupe / remove ids, thresholds, ATT&CK discovery |
| Detection | `detection/` | rsigma engine, per-platform pipelines, channel resolution |
| Regression | `regression/` | `SigmahqRegression`, `info.yml`, data formats, pure-Rust EVTX writer |
| Git | `repo/` | grit-lib wrapper: branch, signing, transport, per-rule commits |
| Types | `types.rs` | `Event`, `Alert`, XML parsing, logsource tables |
| EVTX reader | `evtx_reader.rs` | EVTX file parsing → `Event`, shared by both binaries |
| Diagnostics | `cli.rs` | `check-filter`, `list-rules` |

Which collector runs:

| Input | Module | Feature |
|---|---|---|
| Event Log + one process source | `inputs/windows.rs` | `winevt` (+ `etw`, `driver`) |
| Native ETW (Windows) | `inputs/etw.rs` | `etw` |
| Kernel sensor client (Windows) | `inputs/etw_driver.rs` | `driver` |
| auditd / syslog / Sysmon tail / eBPF | `inputs/linux.rs` | `auditd`, `builtin`, `sysmon`, `ebpf` |
| One-shot EVTX | `inputs/evtx.rs` | `evtx` |

The Windows side has its own pages: [Windows telemetry](windows/index.md)
(driver and ETW internals) and [Sysmon coverage](windows/coverage.md).

## The other binary

`regressiondata-check` reuses `detection`, `rule`, `regression`, `types` and
`evtx_reader`, plus `linux-audit-parser` for `.log` entries. The diagnostic
subcommands (`cli.rs`) parse their flags by hand and use `serde` for JSON
output; both are always compiled.
