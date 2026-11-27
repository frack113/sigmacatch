# Measurements and VM validation

Reference page: what the Windows ETW providers actually expose, and how the
driver was verified on the Windows 11 test VM. Read [ETW](etw.md) and
[Kernel driver](driver.md) first; the per-id result is
[Sysmon coverage](coverage.md).

## ETW provider measurements

Measured with `logman`/`tracerpt` in file mode and with a Rust ETW probe
(feature `etw`) in realtime mode.

**Surface.** `windows` 0.62.2 exposes everything the design needs
(`Win32_System_Diagnostics_Etw` + `Win32_System_Time`): `StartTraceW`,
`EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`, `ControlTraceW`, `CloseTrace`,
`TdhGetEventInformation`, `TdhGetProperty(Size)`. The WinRM session on the test
VM carries a **high-integrity token**, so kernel providers can be enabled.

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

## VM validation

The driver was loaded and exercised end to end on the QEMU test VM.

**Setup** — test-signing in the VM:

1. Secure Boot **must be disabled at the firmware level**: swap the libvirt
   `<loader>` to the non-secure `OVMF_CODE_4M.qcow2` and give the domain a
   *fresh* non-secure `OVMF_VARS_4M.qcow2`. Keeping the secure-boot VARS with
   the non-secure CODE dumped Windows into recovery (`minint-*`); a fresh VARS
   boots normally through the `\EFI\Boot\bootx64.efi` fallback. The
   original domain XML is the revert point.
2. `bcdedit /set testsigning on` + reboot.
3. Self-signed code-signing cert (`New-SelfSignedCertificate`) +
   `Set-AuthenticodeSignature` on the `.sys`.
4. `sc create sigmacatch type= kernel` + `sc start`.

**Driver constraints** (each handled in the driver):

- `sc create type= kernel` loads a **legacy** service, so KMDF never calls
  `EvtDriverDeviceAdd`: the control device must be allocated in `DriverEntry`
  with `WdfControlDeviceInitAllocate`.
- the queue is not the default unless `DefaultQueue` is set, so IOCTLs are not
  dispatched to `EvtIoDeviceControl`.

**Result** — a Rust kernel-sensor probe drained the ring and produced, under
provider `sigmacatch`:

- EID 1 with the creation-time `CommandLine` (exact), `Image`, `User`,
  `IntegrityLevel`, and the full `ParentImage`/`ParentCommandLine`/`ParentUser`
  chain from the pid cache;
- EID 5 with `ProcessId`/`Image`/`User`.

`User`/`IntegrityLevel`/`UtcTime` are enriched best-effort from the still-alive
process, so fast-exiting processes may omit them (never approximated).

**Process access (EID 10)** is validated in the same run.
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

**Image and driver load (EID 6/7)** is validated too.
`PsSetLoadImageNotifyRoutine` reports every image mapped into memory; the
`SystemModeImage` bit (0x100 of `IMAGE_INFO.Properties`) splits kernel images
(EID 6) from user images (EID 7). Measured in the VM:

- EID 7: `ImageLoaded=\Device\HarddiskVolume3\Windows\System32\kernel.appcore.dll`,
  `ProcessId` of the loading process, `Image` from the pid cache;
- EID 6: `ImageLoaded=\Device\HarddiskVolume3\Windows\System32\drivers\wimmount.sys`
  after `sc start wimmount`.

Paths are the NT paths the callback carries (exact), not DOS-mapped.

**The minifilter uses a hand-written FFI.** `wdk-sys` does not bind `fltmgr`
(`FltRegisterFilter`, `FLT_REGISTRATION`, `FLT_CALLBACK_DATA`,
`FltGetFileNameInformation`, ...) and no maintained Rust binding exists, so file
events 2/11/23/503/504/505/506 are built on a hand-written `fltmgr` FFI in
`driver/windows/src/flt.rs` (`#[link(name = "fltmgr")]` plus the structure
definitions).

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

**File create (EID 11).** The minifilter is a
hand-written `fltmgr` FFI (wdk-sys does not bind it), transcribed from the WDK
22621 `fltkernel.h`: `FLT_REGISTRATION` (2.03), the operation table, the
`FLT_CALLBACK_DATA` and `FLT_IO_PARAMETER_BLOCK` prefixes, and
`FLT_FILE_NAME_INFORMATION`. Only `FltRegisterFilter`, `FltStartFiltering`,
`FltGetFileNameInformation`, `FltParseFileNameInformation`,
`FltReleaseFileNameInformation` and `FltGetRequestorProcessId` are needed.

Two ordering/signature rules avoid a bugcheck:

- **`FLT_POST_OPERATION_CALLBACK` takes `Data` first**, not `FltObjects`.
  Reversing them reads `IoStatus` out of `FLT_RELATED_OBJECTS`, so every create
  looks like a non-create with a pointer-shaped `Information`.
- **`FltStartFiltering` delivers callbacks immediately.** `start` therefore
  runs after `create_device` has built the ring's KMDF spinlock; starting it
  earlier gives a `WDF_VIOLATION (0x10D)` bugcheck on load.

Measured in the VM: creating files produced EID 11 with the normalized NT
path, e.g.
`TargetFilename=\Device\HarddiskVolume3\Users\...\probe11k.out`, the
requestor pid, and the image from the pid cache.

**Rename, delete, truncate, ACL and owner (EID 503/23/506/504/505).** The
same registration grows `IRP_MJ_SET_INFORMATION` and
`IRP_MJ_SET_SECURITY`; the parameter block is the `SetFileInformation` /
`SetSecurity` member of the `FLT_PARAMETERS` union.

Two FFI details matter on x64:

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

**Creation time, raw reads and named pipes (EID 2/9/17).** Three less obvious
sources:

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
  made `\Device\NamedPipe` never match). A client connecting to an
  existing pipe (`IRP_MJ_CREATE` on NPFS) is the other kind — EID 18, see
  [Pipes, ADS and threads](driver-events.md#pipes-alternate-data-streams-and-remote-threads).

Measured with the same probe, one PowerShell script per run:

| Operation | EID | EventData |
| --- | --- | --- |
| `(Get-Item f).CreationTimeUtc = …` | 2 | `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` |
| `[IO.File]::Open('\\.\C:').Read(…)` | 9 | `Device`, `Image` |
| `New-Object IO.Pipes.NamedPipeServerStream('x')` | 17 | `PipeName`, `Image` |
| `.LastWriteTimeUtc = …` (control) | — | correctly **not** reported |
