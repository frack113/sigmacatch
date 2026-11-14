# Windows "sans Sysmon" collector (ETW) — plan

A native Windows telemetry collector that produces Sysmon-schema events without
installing Sysmon, mirroring the Linux eBPF collector (`feature ebpf`). This is
a plan, not an implementation.

## Scope and decisions

- **Environment**: the QEMU Windows 11 test VM (`heiter-test-vms-qemu`). No
  distribution target, no code-signing budget. A kernel driver that must be
  distributed as a Microsoft-signed artifact is out of scope for this plan; see
  [Phase 2 (optional)](#phase-2-optional-test-signed-driver).
- **No ferrisetw**: the crate is dormant (last push 2025-10), pins `windows`
  0.61 against our 0.62, and its manifest decode is re-implementable on the
  `windows` crate we already depend on. Hand-roll on `windows` 0.62.2
  (`Win32_System_Diagnostics_Etw`: `StartTraceW`, `EnableTraceEx2`, `OpenTraceW`,
  `ProcessTrace`; TDH: `TdhGetEventInformation`, `TdhGetPropertySize`,
  `TdhGetProperty`).
- **No kernel driver** for the first cut. Pure user-mode ETW. The coverage it
  cannot reach is documented, not approximated.

## Why ETW

Sysmon itself is an ETW consumer **plus** a mini-filter driver. The driver buys
reliable full file paths (`FLT_FILE_NAME_INFORMATION`), process-access
`GrantedAccess` (`ObRegisterCallbacks`) and named pipes; everything else Sysmon
reports is available to a plain user-mode ETW consumer on the built-in
`Microsoft-Windows-Kernel-*` providers. This mirrors the Linux split exactly:
eBPF tracepoints are the "no-Sysmon" source there, kernel ETW providers are the
"no-Sysmon" source here.

Reference implementation: [Rustinel](https://github.com/Karib0u/rustinel)
(same stack: Rust + Sigma + Sysmon-style fields, ships no driver). Its
provider table, field maps and buffer findings are the authority for this plan.

## Coverage matrix

Sysmon Event IDs to the ETW provider that can produce them, and the verdict for
regression-data generation. Provider GUIDs, keywords and event IDs are in
[Rustinel `providers.rs`](https://github.com/Karib0u/rustinel/blob/main/src/sensor/windows/etw/providers.rs);
field mappings in
[`field_maps.rs`](https://github.com/Karib0u/rustinel/blob/main/src/sensor/windows/field_maps.rs).

| Sysmon EID | Name | ETW provider | Verdict |
|---|---|---|---|
| 1 | ProcessCreate | Kernel-Process (ProcessStart) | ✅ generate |
| 3 | NetworkConnect | Kernel-Network (TcpIp/Udp) | ✅ generate |
| 5 | ProcessTerminate | Kernel-Process (ProcessStop) | ✅ generate |
| 7 | ImageLoad | Kernel-Process (ImageLoad) | ✅ generate (dense) |
| 11/23 | FileCreate/Delete | Kernel-File | ⚠️ only when path complete |
| 12/13/14 | Registry | Kernel-Registry | ⚠️ NT paths, `Details` via undocumented option |
| 22 | DnsQuery | DNS-Client (3008) | ✅ generate |
| 2 | FileCreateTime | — | ❌ not covered |
| 6 | DriverLoad | (partial) | ⚠️ verify |
| 10 | ProcessAccess | — | ❌ needs `ObRegisterCallbacks` |
| 15 | FileCreateStreamHash | — | ❌ needs driver |
| 17/18 | PipeCreate/Connect | — | ❌ needs driver |
| 25 | ProcessTampering | — | ❌ protected-process-light only, even Sysmon fakes it |
| 26 | FileDeleteDetected | — | ❌ needs driver |

Non-Sysmon sources reachable the same way: PowerShell (4103/4104),
WMI-Activity, TaskScheduler (106). These are optional extensions, not the core.

## Fidelity principle

Regression data is **committed** to `sigma/regression_data` and validated by
`regressiondata-check`. Unlike an alerter (which drops ambiguous events and
counts them), a wrong or truncated field that we commit **poisons the SigmaHQ
regression corpus**. Therefore:

> **Committed regression data must be exact. Ambiguous telemetry is excluded,
> never approximated.**

Concretely:

- `CommandLine` is truncated by ETW at 1024 chars. Back-fill from the live
  process (Rustinel marks it `derived`); when the process is gone, emit the
  event with `CommandLine` absent rather than the truncated value.
- File create/delete/rename events whose path cannot be resolved completely are
  **not** committed. A partial `TargetFilename` is worse than no event.
- Registry `TargetObject` is an NT path (`\REGISTRY\MACHINE\...`), never
  `HKLM\...`. The committed value must be the NT path (that is what the field
  carries), not a re-mapped guess.

## Architecture (mirrors the eBPF collector)

```
sigmacatch/src/inputs/
├── etw.rs          # feature `etw` (windows-only): session + callback loop, the
│                   #   analogue of ebpf.rs (loader + ring-buffer dispatch)
├── etw_event.rs    # TDH property → nested Sysmon XML/JSON builder, the
│                   #   analogue of ebpf_event.rs
└── windows.rs      # Windows orchestrator: MultiCollector (winevt channels + etw),
                    #   the analogue of linux.rs (does not exist yet — today winevt.rs
                    #   is a single-source CollectorKind)
```

- **Feature `etw`**, `target_os = "windows"` only; entry in the `mod.rs` gate
  matrix.
- **Rendering**: unlike eBPF (nested JSON, Linux), produce Sysmon-shaped data
  and feed the existing Windows pipeline through `Event::from_xml_injected` —
  the whole Windows path (`1_win_logsource.yml`, `parse_winevt_xml`) is already
  built around winevt XML.
- **Regression format**: `DataFormat::Evtx` (these are Windows events), reusing
  the pure-Rust EVTX writer — not `Json` as eBPF uses.
- **Dispatch**: `main.rs` gains a Windows arm that runs the orchestrator.
- **Privileges**: `has_required_privileges()` — admin token / `SeDebugPrivilege`
  to enable kernel providers; bail at startup otherwise (mirror `ebpf_planned`).

## Session design

From Rustinel's findings (each a numbered regression in their repo), adapted to
our mission:

- **Two sessions**: a low-latency Kernel-Process session (32 KB buffers) and a
  burst-tolerant main session (256 KB buffers, explicit min/max pool). The split
  exists because a large buffer delays delivery past a short-lived process's
  exit (#349); for regression data the same race costs us *complete* command
  lines, not just real-time alerts.
- **No per-processor buffering**: event order is load-bearing (path pairing).
- **Classic kernel logger** supplies creation-time command lines + SIDs, joined
  to Kernel-Process events by PID/PPID/time.
- For our VM (regression, not alerting) the burst pool may be smaller than
  Rustinel's; validate on the VM rather than assume.

## Inherited invariants (encode as tests)

Each is a bug Rustinel fixed the hard way; our `etw.rs` encodes it as a test:

1. **Buffer sizing** (#312): `ferrisetw`'s defaults lost 12-60 % of process
   starts under a fork tree. We set buffer size/count explicitly.
2. **Process-session latency** (#349): small buffers or command-line back-fill
   misses short processes.
3. **Registry keywords** (#279): off-by-a-nibble keywords subscribe to reads
   and silently miss every value write. Verify each keyword against the
   manifest.
4. **`IntegrityLevel`** (#294): not a Kernel-Process property; it is the
   `MandatoryLabel` SID on ProcessStart.
5. **Command-line truncation** (#306): the process flusher is required, else
   short-lived capture falls to ~16 %.

## Milestones

- **M0 — spike on the win11 VM**: confirm `windows` 0.62.2 exposes the ETW+TDH
  surface we need, enable the four core providers, capture a short trace, and
  verify the coverage verdicts (CommandLine presence, file-path quality,
  registry NT paths). No Rust collector yet.
- **M1 — session scaffold** (`etw.rs`): privilege check, `StartTraceW`/
  `EnableTraceEx2`/`OpenTraceW`/`ProcessTrace` callback loop, the two-session
  split, clean shutdown.
- **M2 — builder** (`etw_event.rs`): TDH decode + field mapping (provider table
  from `providers.rs`, field maps from `field_maps.rs`) → Sysmon-shaped data →
  `from_xml_injected`. Start with EID 1/3/5/22.
- **M3 — orchestrator** (`windows.rs`): MultiCollector (winevt + etw), feature
  wiring, `mod.rs` gate, `main.rs` dispatch, docs.
- **M4 — regression** (`DataFormat::Evtx` + `regressiondata-check`): generate
  and validate on the VM; apply the fidelity rule (exclude ambiguous paths).
- **M5 — extend coverage**: image load, file (path-complete only), registry,
  PowerShell/WMI/TaskScheduler; document the gap table in `collectors.md`.

## Phase 2 (optional): test-signed driver

Closes the file-path / process-access / named-pipe gaps. In the QEMU VM this is
signing-free (`bcdedit /set testsigning on` + Secure Boot off + self-signed cert
via `signtool`) — but it is a kernel-mode mini-filter/`ObRegisterCallbacks`
driver where a fault BSODs the host, and it can never be distributed as a
"clone → build → run" component (each rebuild needs its own signature). Treat it
as a separate project, not a milestone of this one.
