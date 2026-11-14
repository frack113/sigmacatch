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

## Milestones

- **D0 (this crate today)** — the channel: control device
  `\Device\sigmacatch` with the DOS alias `\DosDevices\sigmacatch`, and one
  IOCTL (`IOCTL_SIGMACATCH_GET_VERSION`, `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800,
  METHOD_BUFFERED, FILE_READ_DATA)`) returning the protocol version as `u32`.
- **D1** — `PsSetCreateProcessNotifyRoutineEx` into a fixed ring buffer, read
  through an IOCTL; EID 1/5 for the user-mode side.
- **D2** — minifilter (file paths, EID 2/15/26), `ObRegisterCallbacks`
  (EID 10), pipes (17/18).

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

The user-mode side refuses a version it does not know, so a driver and a
collector from different builds cannot silently mismatch.
