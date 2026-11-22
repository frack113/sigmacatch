# sigmacatch-driver

Kernel sensor for the Windows flavour of sigmacatch: Sysmon-schema telemetry
on hosts that do **not** have Sysmon installed.

This crate is deliberately **outside the root workspace** (like
`sigmacatch/ebpf`): it only builds on a Windows host with the WDK and LLVM,
while the rest of the project keeps building from Linux with `cargo xwin`.

## Why

The user-mode collector (`sigmacatch/src/inputs/etw*.rs`) already produces
EID 1 (from the live process), 3, 5, 7, 11/23, 12/13/14, 22 and rename
events from ETW. What it cannot produce without Sysmon is:

| Sysmon EID | Needs |
|---|---|
| 1 / 5 creation-time details | `PsSetCreateProcessNotifyRoutineEx` |
| 2, 15, 26 (creation time, ADS, detected delete) | a minifilter |
| 10 `ProcessAccess` (incl. `GrantedAccess`) | `ObRegisterCallbacks` |
| 17/18 named pipes | object callbacks / filter |

The driver exists only for those. The user-mode path must keep working when
the driver is absent, refused by HVCI, or not loaded: the two layers are
deduplicated by `(pid, creation time)`.

## Coverage and milestones

Delivered and validated in the test VM:

- **D0 — channel** (done): control device `\Device\sigmacatch` + DOS alias,
  and the version IOCTL.
- **D1 — process creation** (done): `PsSetCreateProcessNotifyRoutineEx` into a
  fixed ring; EID 1/5 with the creation-time command line.
- **D2a — process access** (done): `ObRegisterCallbacks` on process handles,
  filtered to the injection-relevant rights; EID 10.
- **D2b.1 — image/driver load** (done): `PsSetLoadImageNotifyRoutine`; the
  `SystemModeImage` bit splits EID 6 (driver) from EID 7 (image).

Blocked / remaining:

- **D2b.2a — file create** (done): hand-written `fltmgr` FFI (wdk-sys does not
  bind it), `IRP_MJ_CREATE` post-op → EID 11 with the normalized NT path.
  Installed with `sc create` plus the `Instances`/`DefaultInstance` registry
  keys (altitude 380000).
- **D2b.2b — the other file kinds** (done): rename (503), delete (23),
  truncate (506), ACL (504) and owner (505). Renames and deletes are reported
  from the `IRP_MJ_SET_INFORMATION` pre-op (the name is only reliable there),
  truncate from the post-op, and the security changes from
  `IRP_MJ_SET_SECURITY`. Validated in the VM against `Move-Item`,
  `Remove-Item`, `icacls /deny`, `takeown /f` and `File.SetLength`.
- **D2c — creation time, raw reads, pipes** (done): EID 2 from
  `FileBasicInformation` (creation stamp only — `ChangeTime` is the metadata
  stamp and would report the boot-time `-1` rewrite as a false creation),
  EID 9 from an `IRP_MJ_READ` on an unnamed file object (volume handle, pre-op
  because the post-op may run at DPC), and EID 17 from
  `IRP_MJ_CREATE_NAMED_PIPE` (`0x01`) on the NPFS volume, which fltmgr only
  attaches with `FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS` (`0x2`).
- **D2e — registry rename** (done): EID 14 from `CmRegisterCallbackEx`
  (`RegNtPreRenameKey`); the old path comes from
  `CmCallbackGetKeyObjectIDEx`, the new name is the leaf the callback carries.
- **D2d — pipes, streams, remote threads** (done): EID 18 from a client create
  on the NPFS volume, EID 15 from a create whose name carries a `:stream` (the
  parsed `stream` member is empty for normalized names, so the driver scans the
  path), and EID 8 from `PsSetCreateThreadNotifyRoutine` with a creator/target
  mismatch, minus the first thread of a fresh process (initial threads are
  created from the parent's context, which made every process start look like
  an injection).

The ring record is kind-tagged (`sigmacatch/driver/protocol/`, shared with
the user-mode client as `sigmacatch-driver-protocol`), so adding a kind does
not change the IOCTL layout.

## Build

Windows host (or the `Driver` GitHub workflow):

```pwsh
# WDK 10.0.22621 or newer, LLVM 17, Visual Studio with the C++ workload
cargo build --release --target x86_64-pc-windows-msvc
```

The `wdk-build` build script configures linking against `ntoskrnl`, `wdfldr`
and friends; the workspace metadata in `Cargo.toml` declares KMDF 1.33.

## Load in the test VM

Test-signing only — a distributable build needs its own EV signature.

```pwsh
bcdedit /set testsigning on      # reboot required; Secure Boot must be off
# self-signed cert, signtool sign /fd sha256 /a /ac ... sigmacatch_driver.sys
sc.exe create sigmacatch type= kernel start= demand binPath= C:\sigmacatch_driver.sys
sc.exe start sigmacatch
```

The artifact is produced as `sigmacatch_driver.dll` (Rust `cdylib`); rename it
to `.sys` for the service.

## Protocol

`DeviceIoControl` on `\\.\sigmacatch`:

| IOCTL | Input | Output |
|---|---|---|
| `IOCTL_SIGMACATCH_GET_VERSION` (`0x00222000`) | — | `u32` protocol version |
| `IOCTL_READ_EVENTS` (`0x00222004`) | — | array of `SensorEvent` (kind-tagged) |

The user-mode side refuses a version it does not know, so a driver and a
collector from different builds cannot silently mismatch.
