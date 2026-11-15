# Collectors

Each input is a `CollectorKind`: one struct that names the input, exposes the
channels it can read, builds its event producer, and declares the regression
format it writes. The feature × platform gate matrix lives in
`inputs/mod.rs`; `main.rs` picks the runtime input.

| Input | Page | Feature | Regression format |
|---|---|---|---|
| Windows Event Log + driver/ETW | [Windows](windows.md) | `winevt`, then `etw` / `driver` | `.evtx` |
| One-shot EVTX files | [EVTX](evtx.md) | `evtx` | `.evtx` |
| auditd, syslog, Sysmon-for-Linux, eBPF | [Linux](linux.md) | `auditd`, `builtin`, `sysmon`, `ebpf` | `.log` / `.json` |

## The `CollectorKind` contract

Every input implements
`name()`/`mode()`/`channels()`/`build()`/`regression_format()`/`live_capture()`.
The Linux inputs share a single `LinuxCollector` (`inputs/linux.rs`), the
Windows inputs a single `WindowsCollector` (`inputs/windows.rs`).

- **Regression format** comes from `regression_format()`: `DataFormat::Evtx`
  for winevt, EVTX, ETW and driver events; `DataFormat::Log` for
  auditd/syslog/Sysmon-tail data; `DataFormat::Json` for eBPF. The runner
  refines it per alert, so auditd events keep `.log` even when eBPF is active
  in the same binary. JSON is one pretty document (`type: json`) or NDJSON
  (`type: ndjson`).
- **`live_capture()`** is intrinsic, not a CLI flag: `true` by default,
  overridden only by `evtx` (`false`). A continuous collector loops until the
  stop file; a one-shot collector lets `EventProducer::run()` return, the mpsc
  sender drops, and the shared `run()` exits.
- **`name()`** is `sigmacatch` for every input; **`mode()`** names the live
  sources (`windows winevt+driver+etw`, `linux auditd+syslog+sysmon(ebpf)`).

The pipeline that consumes these producers is the same for every input; see
[Pipeline](../pipeline.md). The module map is in [Layout](../layout.md).
