# Driver events: files, images, pipes, registry and threads

The per-event implementation notes for the ids the kernel sensor owns beyond
process telemetry. Start with [Kernel driver](driver.md) for the
mechanism (callbacks, minifilter, ring protocol) and [Sysmon coverage](coverage.md)
for the full id-by-id state.

## Pipes, alternate data streams and remote threads

Three ids the kernel sensor reports:

- **EID 18** — a client connecting to a named pipe is an `IRP_MJ_CREATE` on the
  NPFS volume (`FILE_OPENED`); the server's creation stays EID 17
  (`IRP_MJ_CREATE_NAMED_PIPE`).
- **EID 15** — a create whose normalized name carries a `:stream` component.
  `FltParseFileNameInformation` leaves `FLT_FILE_NAME_INFORMATION.stream`
  **empty** for a normalized name, so the driver scans the path for a `:` after
  the last separator instead. `TargetFilename` keeps the stream
  (`…\file.txt:hidden`); `Hash` stays absent (the driver does not read it).
- **EID 8** — `PsSetCreateThreadNotifyRoutine`: the routine runs in the creator's
  context, so `current pid != new thread's pid` is a thread injected into
  another process. Two filters keep the noise out: the first thread of a new
  process has `ThreadId == ProcessId`, and `CreateProcess` creates that thread
  from the parent's context, so a target younger than 2 s
  (`PsGetProcessCreateTimeQuadPart` vs `KeQuerySystemTimePrecise`) is skipped.
  Without them every process start was reported as an injection (17 false
  positives in 8 s). `StartAddress`/`StartModule` are not reachable from this
  callback and stay absent.

Measured: `CreateRemoteThread` from PowerShell into a `cmd.exe` that had been up
for 5 s produced exactly one EID 8 (`SourceImage` powershell, `TargetImage`
cmd.exe, `NewThreadId`).

## Registry key rename (EID 14)

EID 14 (rename key) has no ETW source at all: `Kernel-Registry` publishes no
rename record, and Windows exposes no user-mode rename API. It comes from the
driver's `CmRegisterCallbackEx` (`RegNtPreRenameKey`): the old path is the full
name returned by `CmCallbackGetKeyObjectIDEx`, `REG_RENAME_KEY_INFORMATION.NewName`
is only the new **leaf**, and the mapper joins it onto the old parent before
abbreviating. Measured with `ntdll!NtRenameKey` (the only way to trigger it):
`HKU\…\Software\sigmacatch-ren-src` → `HKU\…\Software\sigmacatch-ren-dst`.

The registry create/set/delete ids (12/13) come from ETW instead; see
[ETW — registry](etw-events.md#registry-eid-121314).

## File open for write (EID 509)

The EDR comparison matrix has a "File Opened" category Sysmon does not cover.
The minifilter's create post-op sees it: `IoStatus.Information == FILE_OPENED`
plus the requested `DesiredAccess` from `FLT_PARAMETERS.Create` (via
`IO_SECURITY_CONTEXT`, offset 16 on x64). Read-only opens are the overwhelming
majority and carry little signal, so only `FILE_WRITE_DATA`/`FILE_APPEND_DATA`
are reported.

Best effort by design: the driver keeps a per-second budget (64 events, a
`KeQuerySystemTimePrecise` second window and two atomics) and drops the rest,
so an installer touching thousands of files cannot overflow the 1024-slot ring
and starve the other kinds. Measured: a 200-write burst produced 93 EID 509 in
the window — the budget held, and the other kinds kept their normal volume.

## File write (EID 510)

The EDR matrix also has a "File Modification" category. The minifilter's
`IRP_MJ_WRITE` post-op sees the writes that matter and are cheap to spot:
`SKIP_PAGING_IO | SKIP_CACHED_IO` keeps the cached traffic — the bulk — out, so
only writes that reach the file system directly are reported, `Size` carrying
the write length. Best effort by design: one report per file object and per
second (a 256-slot cache keyed by the file object), plus a 32-events-per-second
budget. Measured with `robocopy /J` (unbuffered) of a 50 MB file: exactly one
EID 510 for the destination, where a per-chunk report would have produced fifty.

## Images: hashes and Authenticode

`Hashes` on 1/6/7/15/29 is `SHA1=…,SHA256=…,MD5=…,IMPHASH=…`, computed in user
mode: the kernel never reads file content. The IMPHASH follows FireEye's
`pefile` algorithm (lowercased DLL name without `.dll`/`.ocx`/`.sys`, then each
imported function, joined and MD5'd) — `inputs/pe_format.rs` implements it as a
pure, bounds-checked reader, and it was cross-checked against an independent
Python implementation on `cmd.exe`: 287 import pairs, same digest
(`010b165e4c37f484601d3dbd700c9423`). Ordinals of `ws2_32.dll`/`oleaut32.dll`
are hashed as `ord<NN>` where `pefile` resolves a name, the only divergence.

`Signed`/`SignatureStatus` on 6/7 come from `WinVerifyTrust`. **A single call is
not enough**: most Windows binaries carry no embedded signature and are signed
through a security catalog, so `cmd.exe` came back "unsigned" — measured: 41
false negatives out of 247 image loads. The catalog pass
(`CryptCATAdminCalcHashFromFileHandle2` → `CryptCATAdminEnumCatalogFromHash` →
`WTD_CHOICE_CATALOG`) fixed it: 527 valid, 16 unsigned, and the 16 are the
`.ni.dll` native images .NET generates locally. `Signature` (the signer name)
still comes from the embedded certificate only, so it is absent for
catalog-signed images.

## File, process and image events

The create-time, create/delete/rename, ACL/owner, truncate, raw-read, driver
load and PE-detected events (EID 2/11/23/503/504/505/506/9/6/29) are covered by
the minifilter and the image/process callbacks; their implementation details
and measured traces are in the [validation journal](evidence.md#vm-validation-2026-11-14).
