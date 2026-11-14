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
- Registry `TargetObject` must be an NT path (`\REGISTRY\MACHINE\...`), never a
  re-mapped `HKLM\...` guess. Measured: the provider's `RelativeName` is only a
  full NT path when the base key is a root, so an event is committed only when
  the `BaseObject`/`KeyObject` chain resolves to a root.

## Architecture (mirrors the eBPF collector)

```
sigmacatch/src/inputs/
├── etw.rs          # feature `etw` (windows-only): session + callback loop, the
│                   #   analogue of ebpf.rs (loader + ring-buffer dispatch)
├── etw_event.rs    # TDH property → typed fields, the analogue of ebpf_event.rs
├── etw_process.rs  # live-process facts (CommandLine, User, parent, creation)
├── etw_sysmon.rs   # Sysmon-schema rendering (EID 1 today)
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
  registry NT paths). No Rust collector yet. **Done — see
  [M0 results](#m0-results-win11-vm-2026-11-14).**
- **M1 — session scaffold** (`etw.rs`): privilege check, `StartTraceW`/
  `EnableTraceEx2`/`OpenTraceW`/`ProcessTrace` callback loop, the two-session
  split, clean shutdown. **Done** (`etw.rs` + `etw_event.rs` + the
  `examples/etw_dump.rs` probe).
- **M2 — builder** (`etw_event.rs`): TDH decode + field mapping (provider table
  from `providers.rs`, field maps from `field_maps.rs`) → Sysmon-shaped data →
  `from_xml_injected`. Start with EID 1/3/5/22.
- **M3 — orchestrator** (`windows.rs`): MultiCollector (winevt + etw), feature
  wiring, `mod.rs` gate, `main.rs` dispatch, docs.
- **M4 — regression** (`DataFormat::Evtx` + `regressiondata-check`): generate
  and validate on the VM; apply the fidelity rule (exclude ambiguous paths).
- **M5 — extend coverage**: image load, file (path-complete only, rename via
  events 20/27 + the `FileKey` path cache), registry, PowerShell/WMI/
  TaskScheduler; document the gap table in `collectors.md`.

## M0 results (win11 VM, 2026-11-14)

Measured with `logman`/`tracerpt` in file mode and with the Rust probe
(`sigmacatch/examples/etw_dump.rs`, feature `etw`) in realtime mode.

**Surface.** `windows` 0.62.2 exposes everything the design needs
(`Win32_System_Diagnostics_Etw` + `Win32_System_Time`): `StartTraceW`,
`EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`, `ControlTraceW`, `CloseTrace`,
`TdhGetEventInformation`, `TdhGetProperty(Size)`. The WinRM session on the test
VM carries a **high-integrity token**, so kernel providers can be enabled; the
skill's "no elevated admin" note is stale.

**What the providers actually give us.**

| Provider | Fields observed | Verdict |
|---|---|---|
| Kernel-Process 1 (ProcessStart) | `ProcessID`, `ParentProcessID`, `CreateTime`, `MandatoryLabel`, `ImageName` (device path), `ProcessTokenIsElevated` | no `CommandLine`, no `UserSID` |
| Kernel-Process 2 (ProcessStop) | exit stats; `ImageName` is a **basename only** | usable for EID 5, image path via the start cache |
| Kernel-Process 5 (ImageLoad) | `ImageName` (device path), `ImageBase`, `ImageChecksum`, `TimeDateStamp` | no signature fields |
| Kernel-Network 10/11/12/15/42/43 | `PID`, `saddr`/`daddr`, `sport`/`dport`, `size` | EID 3 without hostnames/image |
| Kernel-File 12/13/14/… | `FileName` as `\Device\HarddiskVolume3\...`, caller-preserved case, ~1 % empty | device→DOS mapping required |
| Kernel-Registry 1/2/5/6/13 | `RelativeName` (**sometimes** `\Registry\Machine\...`, sometimes `Software\...`), `KeyName` empty on `SetValueKey`, `BaseName` always empty | pairing by `KeyObject` required |
| DNS-Client 3006/3008/3010/3020 | `QueryName`, `QueryResults`, `QueryStatus`, `ClientPID` | EID 22 |
| Classic kernel logger (opcode 1) | `ProcessId`, `ParentId`, `UserSID`, `ImageFileName`, `CommandLine`, `PackageFullName`, `ApplicationId` | the only source of EID 1 `CommandLine`/`User` |

**Corrections to the design.**

1. **Registry paths are not NT paths.** `RelativeName` is a full NT path only
   when the base object is a root; otherwise it is relative to the base key and
   must be rebuilt through the `BaseObject`/`KeyObject` chain. The fidelity rule
   becomes: emit `TargetObject` only when the chain resolves to a root, never
   as a guessed `HKLM\...` mapping.
2. **The classic kernel logger needs the system-logger bit.**
   `EVENT_TRACE_REAL_TIME_MODE` alone starts the session, delivers its
   configuration events and then goes silent; `EVENT_TRACE_SYSTEM_LOGGER_MODE`
   is what makes live process events flow.
3. **TDH does not decode classic (MOF) kernel events.** They arrive with the
   Process MOF provider GUID `3d6fa8d0-…` and `EventID 0`; `TdhGetEventInformation`
   returns the `MSNT_SystemTrace` generic template (`GroupMask*`), not the
   `CommandLine` fields `tracerpt` shows. Command lines and SIDs therefore need
   either a hand-written MOF (`PERFINFO_PROCESS`) parser or the live-process PEB
   back-fill.
4. **Keyword filtering suppresses the events we need.** Enabling
   `Microsoft-Windows-Kernel-Process` with its own manifest keywords
   (`0x10 | 0x40`) delivers `ImageLoad` but **no** `ProcessStart`; only a
   keyword-less subscription (level `Verbose`) delivers the process lifecycle —
   the same class of silent-miss bug as Rustinel #279. DNS-Client behaves the
   same way: events 3006/3008 carry keyword `0`, so the Operational-channel mask
   never receives them.

**Process creation (EID 1) does not come from ETW here.** In realtime mode,
`ProcessStart`/`ProcessStop` are delivered for long-lived processes only: five
`cmd /c ping` runs produced zero `ProcessStart` records in a 20 s window while a
concurrent `logman` file-mode session on the same provider captured 34/34, and
the identical run through `ferrisetw` 1.2 — an independent consumer — produced
the same empty result. Buffer size (32 KiB/256 KiB), pool depth, flush timer,
`EVENT_TRACE_USE_PAGED_MEMORY`, private-logger mode and per-processor buffering
all leave the result unchanged, and the session reports `EventsLost = 0`.

EID 1 is therefore built from the **live process**, which is also the only
source of its two mandatory fields (`CommandLine` and `User` are never published
by the manifest provider):

- `QueryFullProcessImageNameW` → `Image`;
- `NtQueryInformationProcess(ProcessCommandLineInformation)` → `CommandLine`;
- `NtQueryInformationProcess(ProcessBasicInformation)` → `ParentProcessId`;
- `GetProcessTimes` → `UtcTime` (the real creation time, not our observation
  time);
- the process token → `User`, `UserSid`, `IntegrityLevel`.

The trigger is a 50 ms Toolhelp snapshot of the process table, with ETW events
from an unknown PID as the fast path; a process is only reported when its
creation time falls inside the capture, so nothing pre-existing is invented.
Sysmon-only enrichments that cannot be sourced exactly (`ProcessGuid`,
`LogonGuid`, `Hashes`, `FileVersion`, `Company`, ...) are omitted rather than
approximated.

## Decision: the driver is the target

Recorded on 2026-11-14, after M0/M1 showed what user mode cannot reach.

The project exists **to produce Sysmon-schema telemetry on hosts that do not
have Sysmon**. "Hosts without Sysmon" is therefore the target environment, not
an edge case: relying on Sysmon's channel for EID 10/17/18/2/15/26 would
defeat the purpose.

Two layers, same output:

- **User-mode path (M0–M5, done for EID 1)** — no driver, no signature, works
  on any elevated Windows host: ETW kernel providers + live-process facts.
  Covers EID 1, 3, 5, 7, 11/23, 12/13/14, 22, rename (20/27 + `FileKey`
  cache), DNS, network. This stays as the portable fallback and as the
  reference the driver output is compared against.
- **Driver path (D0–D2)** — a `sigmacatch` kernel component that closes what
  user mode cannot: EID 2/15/26 (creation time, alternate data streams,
  detected deletes), EID 10 `GrantedAccess` (`ObRegisterCallbacks`), EID 17/18
  named pipes, and race-free file paths (`FLT_FILE_NAME_INFORMATION`).

Constraints accepted up front, unchanged from the original Phase 2 note:

- the WDK is **not** in the `cargo xwin` chain: the driver builds on a Windows
  host (or a Windows CI runner) with the WDK, in its own crate outside this
  workspace, like `sigmacatch/ebpf`;
- every build needs its own signature; in the test VM that is test-signing
  (`bcdedit /set testsigning on`, Secure Boot off, self-signed cert), and a
  distributable build needs an EV certificate;
- a kernel bug is a BSOD, so the driver never becomes a hard dependency: the
  user-mode path must keep working when the driver is absent, refused by HVCI,
  or not loaded.

The crate is `sigmacatch/driver/` (excluded from the workspace, built by
`.github/workflows/driver.yml` on a `windows-latest` runner with the WDK and
LLVM). D0 — the control device and its version IOCTL — compiles there today.

Milestones:

- **D0 — process creation**: `PsSetCreateProcessNotifyRoutineEx` →
  EID 1/5 with the creation-time command line, no polling and no PEB race.
  This is the smallest driver that proves the channel end to end.
- **D1 — file system**: a minifilter for creation/rename/delete with complete
  `FLT_FILE_NAME_INFORMATION` paths, closing the "path incomplete → drop the
  event" cases.
- **D2 — the rest**: `ObRegisterCallbacks` for EID 10, named pipes for EID
  17/18, and the EID 2/15/26 cases.

The user-mode collector keeps its own process trigger (snapshot + ETW) so the
same event is never lost, and the two paths are deduplicated by `(pid,
creation time)`.

## Phase 2 (optional): test-signed driver (superseded by the decision above)## Phase 2 (optional): test-signed driver (superseded)

Closes the file-path / process-access / named-pipe gaps. In the QEMU VM this is
signing-free (`bcdedit /set testsigning on` + Secure Boot off + self-signed cert
via `signtool`) — but it is a kernel-mode mini-filter/`ObRegisterCallbacks`
driver where a fault BSODs the host, and it can never be distributed as a
"clone → build → run" component (each rebuild needs its own signature). Treat it
as a separate project, not a milestone of this one.
