# Windows "sans Sysmon" collector — ETW + kernel driver

A native Windows telemetry collector that replaces Sysmon on hosts that do not
have it, mirroring the Linux eBPF collector (`feature ebpf`). It emits the same
taxonomy on both platforms — the Sysmon-schema ids plus the sigmacatch 5xx
extensions. User-mode ETW (`feature etw`) covers what kernel providers expose;
the `sigmacatch` kernel driver (`sigmacatch/driver/`, `feature driver`) is the
source of everything ETW cannot reach, and is the active work item.

## Scope and decisions

- **Environment**: the QEMU Windows 11 test VM (`heiter-test-vms-qemu`). No
  distribution target, no code-signing budget: the kernel driver is
  test-signed there, and a distributable build is a separate signing effort.
  See [the driver decision](#decision-the-driver-replaces-sysmon).
- **No ferrisetw**: the crate is dormant (last push 2025-10), pins `windows`
  0.61 against our 0.62, and its manifest decode is re-implementable on the
  `windows` crate we already depend on. Hand-roll on `windows` 0.62.2
  (`Win32_System_Diagnostics_Etw`: `StartTraceW`, `EnableTraceEx2`, `OpenTraceW`,
  `ProcessTrace`; TDH: `TdhGetEventInformation`, `TdhGetPropertySize`,
  `TdhGetProperty`).
- **The kernel driver is the primary source.** `sigmacatch/driver/` (feature
  `driver`) supplies what user-mode ETW cannot reach (process create/exit,
  process access, file paths); see
  [the driver decision](#decision-the-driver-replaces-sysmon). User-mode ETW
  stays as the portable fallback and the reference the driver output is
  compared against.

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

The verdicts above are the original user-mode plan. M0 corrected EID 1/5
(`ProcessStart`/`ProcessStop` do not deliver in realtime) and the driver now
sources EID 1/5/6/10: see [M0 results](#m0-results-win11-vm-2026-11-14) and
[the driver decision](#decision-the-driver-replaces-sysmon).

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

```text
sigmacatch/src/inputs/
├── etw.rs          # feature `etw` (windows-only): session + callback loop, the
│                   #   analogue of ebpf.rs (loader + ring-buffer dispatch)
├── etw_event.rs    # TDH property → typed fields, the analogue of ebpf_event.rs
├── etw_process.rs  # live-process facts (CommandLine, User, parent, creation)
├── etw_sysmon.rs   # Sysmon-schema rendering (EID 1/5/6/7/10 today)
├── etw_driver.rs   # feature `driver` (implies `etw`): client for the kernel
│                   #   sensor — opens `\\.\sigmacatch`, drains the ring, maps
│                   #   kind → Sysmon-schema event
└── windows.rs      # Windows orchestrator: MultiCollector (winevt channels + etw),
                    #   the analogue of linux.rs (does not exist yet — today winevt.rs
                    #   is a single-source CollectorKind)

sigmacatch/driver/  # kernel sensor, excluded from the workspace like ebpf:
                    #   control device + process/image/access callbacks into a ring
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
  TaskScheduler; update the coverage matrix and taxonomy table above.

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

## Decision: the driver replaces Sysmon

Recorded on 2026-11-14, after M0/M1 showed what user mode cannot reach; this
is now the active work item, not a future option. The driver is what delivers
the sigmacatch taxonomy — the Sysmon-schema ids plus the 5xx extensions — in
place of Sysmon.

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

Constraints accepted up front, unchanged from the original driver note:

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
LLVM). D0/D1/D2a — the channel, process create/exit and process access — are
implemented and validated in the VM; see [VM validation](#vm-validation-2026-11-14).

One taxonomy, both platforms. The Linux eBPF collector emits Sysmon-schema
events plus a set of sigmacatch extensions in the 5xx range (500-508); the
Windows side must emit the same event ids so one rule set runs on both. The
driver is the source of the ids user-mode ETW cannot produce; the rest stay in
user mode, and two are Linux-only.

| id | meaning | Windows source |
|---|---|---|
| 1, 5 | process create / exit | driver — D1, `PsSetCreateProcessNotifyRoutineEx` |
| 2, 11, 23 | file create / change / delete | driver — D2, minifilter |
| 3, 22 | network connect / DNS query | user-mode ETW (Kernel-Network / DNS-Client) |
| 6 | image (driver) load | driver — D1, `PsSetLoadImageNotifyRoutine` |
| 7 | image load | user-mode ETW (Kernel-Process `ImageLoad`) |
| 9 | raw access | driver — D2 (no clean public hook) |
| 10 | process access | driver — D2a, `ObRegisterCallbacks` |
| 17 | pipe create | driver — D2 (no public callback, hardest gap) |
| 25 | process tampering | driver — D2, `ObRegisterCallbacks` post-op heuristic |
| 500 | network listen | user-mode ETW (Kernel-Network accept) |
| 501 | credential change | Linux-only (`setuid`) — no Windows equivalent |
| 502 | capability change | Linux-only (capabilities) — no Windows equivalent |
| 503 | file rename | driver — D2, minifilter `FileRenameInformation` |
| 504 | file chmod (ACL) | driver — D2, minifilter `IRP_MJ_SET_SECURITY` |
| 505 | file chown (owner) | driver — D2, minifilter `IRP_MJ_SET_SECURITY` |
| 506 | file truncate | driver — D2, minifilter `FileEndOfFileInformation` |
| 507 | module unload | user-mode ETW (Kernel-Process `ImageUnload`) |
| 508 | DNS response | user-mode ETW (DNS-Client 3008/3010/3020) |

Milestones:

- **D0 — channel** (done): control device `\Device\sigmacatch`, version
  IOCTL; compiles in CI.
- **D1 — process creation** (done): `PsSetCreateProcessNotifyRoutineEx` (EID
  1/5) and `PsSetLoadImageNotifyRoutine` (EID 6) into a ring, drained via
  `IOCTL_READ_EVENTS`.
- **D2a — process access** (done): `ObRegisterCallbacks` → EID 10, validated in
  the VM.
- **D2b.1 — image/driver load** (done): `PsSetLoadImageNotifyRoutine` → EID
  6/7, validated in the VM.
- **D2b.2 — file system**: minifilter for 2/11/23/503/504/505/506 with complete
  `FLT_FILE_NAME_INFORMATION` paths (needs a hand-written `fltmgr` FFI), and
  9/17 where a public hook exists.
- **D3 — parity**: the Windows collector emits the same event-id set as the
  Linux collector; 501/502 documented as Linux-only.

The user-mode collector keeps its own process trigger (snapshot + ETW) so the
same event is never lost, and the two paths are deduplicated by `(pid,
creation time)`.

## VM validation (2026-11-14)

The driver was loaded and exercised end to end on the QEMU test VM.

**Setup** — test-signing in the VM:

1. Secure Boot was **disabled at the firmware level**: swap the libvirt
   `<loader>` to the non-secure `OVMF_CODE_4M.qcow2` and give the domain a
   *fresh* non-secure `OVMF_VARS_4M.qcow2`. Keeping the secure-boot VARS with
   the non-secure CODE dumped Windows into recovery (`minint-*`); a fresh VARS
   boots normally through the `\EFI\Boot\bootx64.efi` fallback. The
   original domain XML is the revert point.
2. `bcdedit /set testsigning on` + reboot.
3. Self-signed code-signing cert (`New-SelfSignedCertificate`) +
   `Set-AuthenticodeSignature` on the `.sys`.
4. `sc create sigmacatch type= kernel` + `sc start`.

**Bugs the run surfaced** (each is now a fix in the driver):

- `sc create type= kernel` loads a **legacy** service, so KMDF never calls
  `EvtDriverDeviceAdd`: the control device must be allocated in `DriverEntry`
  with `WdfControlDeviceInitAllocate`.
- the queue is not the default unless `DefaultQueue` is set, so IOCTLs are not
  dispatched to `EvtIoDeviceControl`.

**Result** — `sigmacatch/examples/etw_driver_probe.rs` drained the ring and
produced, under provider `sigmacatch`:

- EID 1 with the creation-time `CommandLine` (exact), `Image`, `User`,
  `IntegrityLevel`, and the full `ParentImage`/`ParentCommandLine`/`ParentUser`
  chain from the pid cache;
- EID 5 with `ProcessId`/`Image`/`User`.

`User`/`IntegrityLevel`/`UtcTime` are enriched best-effort from the still-alive
process, so fast-exiting processes may omit them (never approximated).

**D2a — process access (EID 10)** is validated in the same run.
`ObRegisterCallbacks` registers pre/post callbacks for process-handle
create/duplicate, filters on the injection-relevant rights
(`PROCESS_VM_READ/WRITE/OPERATION`, `CREATE_THREAD`, `DUP_HANDLE`,
`CREATE_PROCESS`, `SUSPEND_RESUME`, `TERMINATE`, `SET_INFORMATION`), and pushes
`PROCESS_ACCESS` records (source pid, target pid, granted mask). The user-mode
side renders EID 10 with `SourceImage`/`TargetImage` resolved from the pid
cache. Measured: `OpenProcess(PROCESS_VM_READ)` from PowerShell produced an EID
10 with `GrantedAccess=0x1FFFFF` and the target image from the cache.

Two wdk-sys gaps were worked around: `PsProcessType` is declared as an extern
static (not bound), and `KeQuerySystemTime` is not in the WDK import lib, so
the consumer timestamps records at read time (`Utc::now()` when the record
carries 0) — a few milliseconds late, acceptable for EID 5/10.

**D2b.1 — image and driver load (EID 6/7)** is validated too.
`PsSetLoadImageNotifyRoutine` reports every image mapped into memory; the
`SystemModeImage` bit (0x100 of `IMAGE_INFO.Properties`) splits kernel images
(EID 6) from user images (EID 7). Measured in the VM:

- EID 7: `ImageLoaded=\Device\HarddiskVolume3\Windows\System32\kernel.appcore.dll`,
  `ProcessId` of the loading process, `Image` from the pid cache;
- EID 6: `ImageLoaded=\Device\HarddiskVolume3\Windows\System32\drivers\wimmount.sys`
  after `sc start wimmount`.

Paths are the NT paths the callback carries (exact), not DOS-mapped.

**D2b.2 — the minifilter is blocked on bindings.** `wdk-sys` does **not** bind
`fltmgr` (`FltRegisterFilter`, `FLT_REGISTRATION`, `FLT_CALLBACK_DATA`,
`FltGetFileNameInformation`, ...), and no maintained Rust binding exists
(`fsfilter-rs` is a 2023 user-mode loader pinned to `windows` 0.44). File
events 2/11/23/503/504/505/506 therefore need a hand-written `fltmgr` FFI in
the driver crate (`#[link(name = "fltmgr")]` plus the structure definitions),
which is the next sub-project.

**End to end on a Sysmon-less host.** With the driver loaded, the collector ran
one cycle against the SigmaHQ clone: its EID 7 events matched real
`image_load` rules (e.g. *Potential DLL Sideloading Of DBGHELP.DLL*) and the
regression set was written and validated:

```yaml
regression_tests_info:
    - name: Positive Detection Test
      type: evtx
      provider: sigmacatch
      match_count: 1
```

The synthetic events deliberately carry **no `EventRecordID`**: that is the
signal `regression::evtx::write_evtx` uses to write the `.evtx` from the event
XML with the pure-Rust writer, instead of `EvtExportLog` on
`sigmacatch/Operational` (a channel that does not exist in the Event Log).

**D2b.2a — file create (EID 11)** is validated. The minifilter is a
hand-written `fltmgr` FFI (wdk-sys does not bind it), transcribed from the WDK
22621 `fltkernel.h`: `FLT_REGISTRATION` (2.03), the operation table, the
`FLT_CALLBACK_DATA` and `FLT_IO_PARAMETER_BLOCK` prefixes, and
`FLT_FILE_NAME_INFORMATION`. Only `FltRegisterFilter`, `FltStartFiltering`,
`FltGetFileNameInformation`, `FltParseFileNameInformation`,
`FltReleaseFileNameInformation` and `FltGetRequestorProcessId` are needed.

Two bugs cost a bugcheck each:

- **`FLT_POST_OPERATION_CALLBACK` takes `Data` first**, not `FltObjects`. The
  driver had the two swapped, so it read `IoStatus` out of
  `FLT_RELATED_OBJECTS` — every create looked like a non-create with a
  pointer-shaped `Information`.
- **`FltStartFiltering` delivers callbacks immediately.** Starting it before
  `create_device` built the ring's KMDF spinlock gave a
  `WDF_VIOLATION (0x10D)` bugcheck on load. `register` and `start` are now
  separate, and `start` runs after the spinlock exists.

Measured in the VM: creating files produced EID 11 with the normalized NT
path, e.g.
`TargetFilename=\Device\HarddiskVolume3\Users\...\probe11k.out`, the
requestor pid, and the image from the pid cache.

**D2b.2b — rename, delete, truncate, ACL and owner (EID 503/23/506/504/505)**
is validated. The same registration grows `IRP_MJ_SET_INFORMATION` and
`IRP_MJ_SET_SECURITY`; the parameter block is the `SetFileInformation` /
`SetSecurity` member of the `FLT_PARAMETERS` union.

Two more bugs, both found in the VM:

- **`FileInformationClass` is declared `POINTER_ALIGNMENT`** in
  `fltkernel.h` (8-byte aligned on x64), so the field sits at offset 8 with
  four bytes of padding in front of it. Transcribing the struct field by field
  put it at offset 4 and every `IRP_MJ_SET_INFORMATION` read the padding:
  class 0, no event. The struct now carries the explicit padding.
- **`FltGetDestinationFileNameInformation` takes seven parameters starting
  with `PFLT_INSTANCE`.** The FFI declared eight with `Data` first, so the
  call faulted with `0x3B` / `0xC0000005`.

Renames and deletes are reported from the **pre-op**, not the post-op: the
destination name (`FILE_RENAME_INFORMATION`) is consumed by the file system
and the file object already carries the new name afterwards, while a
disposition marks the file for deletion before the post-op runs. The pre-op
handles `FileRenameInformation` (10) and `FileRenameInformationEx` (65),
`FileDispositionInformation` (13) and `FileDispositionInformationEx` (64); the
post-op keeps `FileEndOfFileInformation` (20) and is the only place that
reports successful truncation. ACL and owner changes come from
`IRP_MJ_SET_SECURITY`, whose `SECURITY_INFORMATION` is a plain `ULONG` at
offset 0 — no `POINTER_ALIGNMENT` — which is why 504/505 worked before the
`SetFileInformation` fix.

Measured in the VM (8-second probe, one script):

| Operation | EID | EventData |
| --- | --- | --- |
| `Set-Content b2h1.txt` | 11 | `TargetFilename` = NT path |
| `Remove-Item b2h1.txt` | 23 | `TargetFilename` = NT path |
| `Move-Item b2h2.txt b2h3.txt` | 503 | `SourceFilename` → `TargetFilename` |
| `icacls /deny` | 504 | `TargetFilename` |
| `takeown /f` | 505 | `TargetFilename` |
| `File.Open().SetLength(1)` | 506 | `TargetFilename`, `Size` |

Each event carries the requestor pid and, from the pid cache, the requesting
image (`Image`). Category mapping already covers 23/503/504/505/506, so
`file_delete`, `file_rename`, `file_chmod`, `file_chown` and `file_truncate`
rules are selected for them.

**D2c — creation time, raw reads and named pipes (EID 2/9/17)** is validated
too. Three hooks that the first pass had written off as unreachable:

- **EID 2** comes from `IRP_MJ_SET_INFORMATION` with `FileBasicInformation`
  (4). The new stamp is `CreationTime` in the buffer; the previous one is
  queried with `FltQueryInformationFile` on the same file object in the
  pre-op. `ChangeTime` must **not** be read: it is the metadata-change stamp,
  and at boot kernel components write it as `-1` ("now") across hundreds of
  files — reading it produced 358 false EID 2 in eight seconds. Protocol v6
  carries both stamps in `value_a`/`value_b`; a `-1` ("now") set has
  `value_b == 0` and the mapper fills the event time in.
- **EID 9** is an `IRP_MJ_READ` whose file object has **no name and no
  parent** — a handle opened on the volume itself (`\\.\C:`). The operation
  is registered with `SKIP_PAGING_IO | SKIP_CACHED_IO` and reported from the
  **pre-op**, because the post-op can run at DPC level where
  `FltGetVolumeName` (which supplies `Device`) is not allowed.
- **EID 17** is `IRP_MJ_CREATE_NAMED_PIPE` — major function **`0x01`**, not
  `0x11` (`0x11` is `IRP_MJ_LOCK_CONTROL`, which silently produced file
  paths). fltmgr only attaches a filter to the pipe and mailslot volumes when
  `FLT_REGISTRATION.Flags` sets `FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS`
  (**`0x2`**; `0x4` is `SUPPORT_DAX_VOLUME`). The pipe name is the file
  object's relative `FileName` (`\sigmacatch-test`), the volume is compared
  with `FltGetVolumeName` (both sides ASCII-folded — folding one side only
  made `\Device\NamedPipe` never match), and a client connecting to an
  existing pipe (`IRP_MJ_CREATE` on NPFS) is dropped: that is EID 18, which
  is not produced.

Measured with the same probe, one PowerShell script per run:

| Operation | EID | EventData |
| --- | --- | --- |
| `(Get-Item f).CreationTimeUtc = …` | 2 | `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` |
| `[IO.File]::Open('\\.\C:').Read(…)` | 9 | `Device`, `Image` |
| `New-Object IO.Pipes.NamedPipeServerStream('x')` | 17 | `PipeName`, `Image` |
| `.LastWriteTimeUtc = …` (control) | — | correctly **not** reported |

Remaining gaps: EID 18 (pipe connect) is deliberately not produced, and the
Windows collector still has no EID 8/19-22/24-29 network/WMI/clipboard
sources — those need ETW providers rather than kernel hooks.
