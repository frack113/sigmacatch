# Sysmon vs sigmacatch

What sigmacatch reports, compared with Sysmon, on a host where **Sysmon is not
installed**. The two produce the same EventIDs and the same field names, so the
stock SigmaHQ Sysmon rules match unchanged; only the provenance differs:

| | Sysmon | sigmacatch |
|---|---|---|
| Provider | `Microsoft-Windows-Sysmon` | `sigmacatch` |
| Channel | `Microsoft-Windows-Sysmon/Operational` | `sigmacatch/Operational` |
| Service (Sigma `service:`) | `sysmon` | `sysmon` (same resolution) |
| Kernel driver | `SysmonDrv` | `sigmacatch` (minifilter + notify routines + registry callback) |
| User-mode sources | — | ETW (`Kernel-Network`, `Kernel-Registry`, `Kernel-Process`, `DNS-Client`, `WMI-Activity`) |
| Event Log channels | — | all Windows channels (PowerShell, Security, System, …) |

Every "✅" below was produced and read back on the Windows 11 test VM; the
method is the same for all of them — `etw_dump --map` for the user-mode path
and `etw_driver_probe` for the kernel path, plus one end-to-end run through the
detector for the field predicates (`match_count: 1`).

## Sysmon Event IDs

| EID | Sysmon event | Sigma category | sigmacatch source | State | Missing vs Sysmon |
|---|---|---|---|---|---|
| 1 | ProcessCreate | `process_creation` | driver `PsSetCreateProcessNotifyRoutineEx` | ✅ | `ProcessGuid`, `ParentProcessGuid`, version/company fields, `LogonGuid`/`LogonId`, `TerminalSessionId`; `Hashes` is SHA1+SHA256+MD5 of the image |
| 2 | FileCreateTime | `file_change` | driver `IRP_MJ_SET_INFORMATION`/`FileBasicInformation` | ✅ | `ProcessGuid` |
| 3 | NetworkConnect | `network_connection` | ETW `Kernel-Network` 12 / 42 | ✅ | `ProcessGuid`, `User`; `DestinationHostname` is filled from the session's own DNS answers |
| 4 | SysmonServiceStateChanged | `sysmon_status` | — | ❌ | nothing to report: it describes Sysmon itself |
| 5 | ProcessTerminate | `process_termination` | driver process notify (exit path) | ✅ | `ProcessGuid` |
| 6 | DriverLoad | `driver_load` | driver `PsSetLoadImageNotifyRoutine` (`SystemModeImage`) | ✅ | `Signature` (name) is absent for catalog-signed binaries — see below |
| 7 | ImageLoad | `image_load` | driver `PsSetLoadImageNotifyRoutine` | ✅ | `ProcessGuid`, version/company fields, `User`; `Signature` absent for catalog-signed binaries |
| 8 | CreateRemoteThread | `create_remote_thread` | driver `PsSetCreateThreadNotifyRoutine` | ✅ | `SourceProcessGuid`/`TargetProcessGuid`, `StartAddress`, `StartModule`, `StartFunction` (not reachable from the callback) |
| 9 | RawAccessRead | `raw_access_thread` | driver `IRP_MJ_READ` on an unnamed file object | ✅ | `ProcessGuid` |
| 10 | ProcessAccess | `process_access` | driver `ObRegisterCallbacks` | ✅ | `SourceProcessGuid`/`TargetProcessGuid`, `SourceThreadId`, `CallTrace` |
| 11 | FileCreate | `file_event` | driver minifilter `IRP_MJ_CREATE` | ✅ | `ProcessGuid`, `CreationUtcTime` |
| 12 | CreateKey / DeleteKey | `registry_event` (`registry_add`) | ETW `Kernel-Registry` 1/2/3 | ✅ | `ProcessGuid` |
| 13 | SetValue / DeleteValue | `registry_event` (`registry_set`) | ETW `Kernel-Registry` 5/6 | ✅ | `ProcessGuid`; `Details` is the value data (needs the undocumented `CapturedData` request) |
| 14 | RenameKey | `registry_event` (`registry_rename`) | driver `CmRegisterCallbackEx`/`RegNtPreRenameKey` | ✅ | `ProcessGuid` |
| 15 | FileCreateStreamHash | `create_stream_hash` | driver minifilter (name carries `:stream`) | ✅ | `CreationUtcTime`, `ProcessGuid`; `Hash` is SHA1 of the first 16 MiB |
| 16 | ServiceConfigurationChange | `sysmon_status` | — | ❌ | nothing to report: it is Sysmon's own config change |
| 17 | PipeCreated | `pipe_created` | driver `IRP_MJ_CREATE_NAMED_PIPE` | ✅ | `ProcessGuid` |
| 18 | PipeConnected | `pipe_created` | driver minifilter create on the NPFS volume | ✅ | `ProcessGuid` |
| 19 | WmiEventFilter | `wmi_event` | ETW `WMI-Activity` 5858 | ⚠️ | `Query`, `ProcessGuid` — `Name`, `EventNamespace`, `Operation`, `User` are present |
| 20 | WmiEventConsumer | `wmi_event` | ETW `WMI-Activity` 5858 | ⚠️ | `Type`, `Destination`, `ProcessGuid` — `Name`, `EventNamespace`, `Operation`, `User` are present |
| 21 | WmiEventConsumerToFilter | `wmi_event` | ETW `WMI-Activity` 5858 | ✅ | `ProcessGuid`; `Consumer` and `Filter` are present |
| 22 | DnsQuery | `dns_query` | ETW `DNS-Client` 3008 | ✅ | `ProcessGuid`, `User` |
| 23 | FileDelete | `file_delete` | driver minifilter disposition (13/64) | ✅ | `ProcessGuid`, `Hashes`, `IsExecutable`, `Archived` |
| 24 | ClipboardCapture | `clipboard_capture` | — | ❌ | no public ETW provider nor documented kernel hook |
| 25 | ProcessTampering | `process_tampering` | ETW `Kernel-Process` 6, when the unloaded image is the process's own and it is still running | ✅ | `ProcessGuid`; only `Type=ImageUnloaded` (no herpaderping) |
| 26 | FileDeleteDetected | `file_delete_detected` | driver, the same disposition that reports 23 | ✅ | `Hashes`, `IsExecutable`, `Archived`, `ProcessGuid` — no archive is kept, so 23 and 26 carry the same shape |
| 27 | FileBlockExecutable | `file_block_executable` | — | ❌ | Sysmon's own blocking feature |
| 28 | FileBlockShredding | `file_block_shredding` | — | ❌ | Sysmon's own blocking feature |
| 29 | FileExecutableDetected | `file_executable_detected` | user mode, ~300 ms after a created file, when it starts with `MZ` | ✅ | `ProcessGuid`; `Hashes` over the first 16 MiB, `TargetFilename`/`Image` present |
| 255 | SysmonError | `sysmon_error` | — | ❌ | nothing to report: Sysmon's own error stream |

## sigmacatch extensions (Sysmon has no such IDs)

| EID | Meaning | Source | State |
|---|---|---|---|
| 500 | network listen | ETW `Kernel-Network` 15 (accept) | ✅ emitted on **accept**, not on `listen()` (the provider has no listen event) |
| 501 | credential change | — | Linux only (`setuid`); no Windows equivalent |
| 502 | capability change | — | Linux only (capabilities); no Windows equivalent |
| 503 | file rename | driver minifilter rename pre-op | ✅ `SourceFilename` + `TargetFilename` |
| 504 | file chmod (ACL) | driver `IRP_MJ_SET_SECURITY` (`DACL`) | ✅ |
| 505 | file chown (owner) | driver `IRP_MJ_SET_SECURITY` (`OWNER`) | ✅ |
| 506 | file truncate | driver `FileEndOfFileInformation` | ✅ includes `Size` |
| 507 | module unload | ETW `Kernel-Process` 6 (`ImageUnload`) | ✅ `ModuleName` |
| 508 | DNS response | — | ❌ 3008 is already EID 22; its `QueryStatus` is a Win32 error where this extension carries the DNS RCODE |
| 509 | file open for write | driver minifilter create post-op, `FILE_OPENED` + `DesiredAccess` | ✅ best effort: write/append opens only, 64 events/s |
| 510 | file write | driver minifilter `IRP_MJ_WRITE`, uncached only | ⚠️ best effort: one report per file per second, 32 events/s; cached writes are invisible |
| 511 | driver unload | ETW `Kernel-Process` 6, record with `ProcessID=0` | ✅ `ModuleName` (measured on `bindflt.sys`) |

## Fields that are absent everywhere

These are structural, not per-event, and rules that depend on them will not
match on a sigmacatch host:

- **`ProcessGuid`** — every event carries `ProcessId` and `Image`, never a
  per-process GUID. Pivoting on `ProcessGuid` is impossible; `ProcessId` +
  `Image` + `UtcTime` is the equivalent.
- **`Hashes`** — present on 1, 6, 7, 15 and 29 (SHA1/SHA256/MD5/IMPHASH computed
  in user mode from the file on disk, first 16 MiB); absent on 23, which would
  need the deleted file's content. On 6/7 it is computed once per image path
  and cached.
- **Authenticode** — `Signed` and `SignatureStatus` on 6/7 come from
  `WinVerifyTrust`, with a second pass through the security catalogs (most
  Windows binaries are catalog-signed, and reporting them as unsigned would be
  exactly what the "unsigned binary" rules look for). `Signature` (the signer
  display name) is read from the *embedded* signature, so it is present for
  embedded-signed images and absent for catalog-signed ones.
- **`User` / `LogonId` / `IntegrityLevel`** — present on 1 and 5 only, absent
  from the file/network/registry events.

## EDR-Telemetry categories

The [EDR Telemetry](https://www.edr-telemetry.com/telemetry-categories) project
compares EDR agents on 57 Windows telemetry categories. What sigmacatch covers
of that list, including the categories Sysmon itself does **not** produce:

| Category (sub-category) | Sysmon | sigmacatch |
|---|---|---|
| Process creation / termination / access | ✅ | EID 1 / 5 / 10 |
| Image/library loaded | ✅ | EID 7 |
| Remote thread creation | ✅ | EID 8 |
| Process tampering | ✅ | EID 25 (`Type=ImageUnloaded`) |
| Win32 API telemetry | ❌ | ❌ — ETW-TI requires a PPL/ELAM producer |
| Process call stacks | ✅ | ❌ — no kernel stack walking |
| File creation / deletion | ✅ | EID 11 / 23 + 26 |
| File renaming | ❌ | EID 503 |
| File opened | ❌ | ⚠️ EID 509, write/append opens only |
| File modification | ❌ | ⚠️ EID 510 (uncached writes) + 2 / 506 |
| Registry key/value create, modify, delete | ✅ | EID 12 / 13 |
| Registry key rename | ❌ | EID 14 |
| TCP / UDP connection | ✅ | EID 3 |
| DNS query | ✅ | EID 22 |
| URL, file downloaded | ❌ | ❌ — browser/proxy telemetry, out of scope |
| MD5, SHA | ✅ | EID 1 / 15 / 29 (`Hashes`, first 16 MiB) |
| IMPHASH | ✅ | ❌ — needs PE import-table parsing |
| JA3 / JA3s | ❌ | ❌ — TLS interception, out of scope |
| Scheduled task create/modify/delete | ❌ | ✅ via the Event Log channels (Security 4698/4699/4702, TaskScheduler 106/140-142) |
| Service create/modify/delete | ❌ | ✅ via the Event Log channels (System 7045/7046/7040) |
| Driver loaded | ✅ | EID 6 |
| Driver unloaded | ❌ | EID 511 |
| Driver modification | ❌ | ❌ — no source |
| Virtual disk mount, USB mount/unmount | ❌ | ❌ — PnP/System events exist but no rule needs them yet |
| Group Policy modification | ❌ | ✅ via the Event Log channels (Security 5136) |
| Volume shadow copy deletion | ❌ | ✅ indirectly, through the `process_creation` rules that invoke `vssadmin`/`wmic` |
| Named pipe creation / connection | ✅ | EID 17 / 18 |
| WMI filter / consumer / binding | ✅ | EID 19 / 20 / 21 (`Query`, `Type`, `Destination` absent: the provider never publishes them) |
| BITS jobs | ❌ | ✅ via the Event Log channels (BITS-Client/Operational) when a rule asks for it |
| PowerShell script block | ❌ | ✅ via the Event Log channel (4104) |
| User account creation/modification/deletion, logon, logoff | ❌ | ✅ via the Event Log channels (Security 4720/4722/4724/4726, 4624/4634) |
| Agent start/stop/install/uninstall/keep-alive/errors | — | without object: this is the agent describing itself (Sysmon 4/255) |

"Via the Event Log channels" means the Winevt collector already feeds those
events to the same rule engine: sigmacatch does not re-encode them under a
Sysmon id, it reads the channel the rule names.

## Reproducing the table

```text
etw_dump.exe --sessions main --map --seconds 12      # EID 2/3/12/13/14/19-22/500/507
etw_driver_probe.exe                                 # EID 1/5-11/15/17/18/23/503-506
```

`docs/dev/etw-collector.md` holds the per-milestone evidence, the provider
quirks and the measurements behind each row.
