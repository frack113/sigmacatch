# Windows collector: channels + one process source

Windows always collects the **Event Log channels** resolved from the loaded
rules (`sigmacatch-input-winevt`, feature `winevt`). Everything richer comes from
exactly one *process source*, so an activity is never reported twice:

- **Kernel driver (`driver`, implies `etw`)** — preferred when the
  `sigmacatch` service is loaded and answers the current wire-protocol version
  on `\\.\sigmacatch`. It owns process, file, registry-rename, image, pipe and
  thread events (`PsSetCreateProcessNotifyRoutineEx`,
  `PsSetLoadImageNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`,
  `ObRegisterCallbacks`, a minifilter and `CmRegisterCallbackEx`), with exact
  creation-time command lines and race-free file paths.
- **Native ETW (`etw`)** — the fallback with no driver: two realtime sessions
  (`Kernel-Process` with small buffers for process latency, the burst-tolerant
  main session for network, registry, file and DNS). Process creation is rebuilt
  from the live process (Toolhelp snapshot + per-pid facts) because
  `ProcessStart` is not delivered in realtime; EID 5 is not produced on this
  path.
- **Channels only (`winevt` alone)** — the default build: no Sysmon-schema
  process telemetry, only what the Event Log already contains.

When the driver is loaded, the ETW main session still runs
(`EventCollector::main_only`) because network connections, DNS, WMI, registry
create/set and image/driver unload are only observable in user mode; it no
longer starts the process session.

The rendered events are Sysmon-**schema** — same EventIDs and field names — but
published under the `sigmacatch` provider and the `sigmacatch/Operational`
channel, which `common/core/src/exchange.rs` maps to `service: sysmon`, so
the stock Sysmon rules match unchanged. They carry no `EventRecordID`, which is
what makes the EVTX format take the pure-Rust writer instead of `EvtExportLog`
(the channel does not exist in the Event Log). Each input crate owns its gates;
`sigmacatch/src/orchestrators/mod.rs` only aliases them, and the orchestrator is
`sigmacatch/src/orchestrators/windows.rs` (`mode` is `windows winevt+etw` or
`windows winevt+driver+etw`).

The ETW path needs an **elevated token** (`SeSystemProfilePrivilege`); without
it the source fails with a warning and the channels keep running. The driver
path only needs the device to be openable — when it is not, the collector
quietly falls back to ETW.

Internals: [Windows telemetry](../windows/index.md) (driver, ETW, coverage).

## Windows logsource and PowerShell categories

Windows rules are constrained by the `1_win_logsource.yml` pipeline (`add_condition` on
EventIDs + `change_logsource` to the service): the PowerShell categories are bounded to
their EventIDs — `ps_module` (4103), `ps_script` (4104) → `service: powershell`;
`ps_classic_start` (400), `ps_classic_provider_start` (600) and `ps_classic_script` (800) →
`service: powershell-classic`. Without a `category` field injected on the event, rsigma's
`LogSourceExtractor` evaluates every event fail-open against all rules.

Classic PowerShell events (400/600/800 …) emit `<Data>` elements **without** a `Name`
attribute: the parser exposes them under positional keys (`Data0`, `Data1`, …), and
`inject_logsource_fields_for` surfaces the `EventData` content under the generic Sigma
`Data` field so `Data|contains` matching works (rsigma has no dedicated `powershell_classic`
field mapping).
