# Kernel driver

`sigmacatch/driver/` is a KMDF driver outside the cargo workspace, built by
`.github/workflows/driver.yml` on a `windows-latest` runner (WDK + LLVM). It
supplies what user-mode ETW cannot reach and publishes Sysmon-schema events
through a versioned ring buffer that the collector drains on
`\\.\sigmacatch`.

The per-id result is [Sysmon coverage](coverage.md); the event-by-event
implementation notes are [Driver events](driver-events.md); the validation
journal is [Measurements](evidence.md#vm-validation-2026-11-14).

## Decision: the driver replaces Sysmon

Recorded on 2026-11-14, after the ETW spike showed what user mode cannot reach.
The driver is what delivers the sigmacatch taxonomy — the Sysmon-schema ids plus
the 5xx extensions — in place of Sysmon; it is implemented and validated on the
VM.

The project exists **to produce Sysmon-schema telemetry on hosts that do not
have Sysmon**. "Hosts without Sysmon" is therefore the target environment, not
an edge case: relying on Sysmon's channel for EID 10/17/18/2/15/26 would
defeat the purpose.

Two layers, same output:

- **User-mode path (`etw`)** — no driver, no signature, works on any elevated
  Windows host: ETW kernel providers + live-process facts. It produces EID 1
  (live process), 3, 12/13, 19/20/21, 22, 25, 500, 507 and 511. This stays the
  portable fallback and the reference the driver output is compared against.
- **Driver path (`driver`)** — a `sigmacatch` kernel component that closes what
  user mode cannot: EID 1/5 (process), 2 (creation time), 6/7 (image and driver
  load), 8 (remote thread), 9 (raw read), 10 (`GrantedAccess`), 11/15/17/18/
  23/26 (files, streams, pipes, deletes), 14 (key rename), 29 (PE written),
  503-506 (rename/chmod/chown/truncate) and 509/510 (open for write, write).
  With the driver loaded, the ETW **main** session alone still runs (network,
  DNS, WMI, registry 12/13, image/driver unload): `inputs/windows.rs` starts one
  process source, the two producers share the pid→image cache, and nothing is
  reported twice.

Constraints accepted up front:

- the WDK is **not** in the `cargo xwin` chain: the driver builds on a Windows
  host (or a Windows CI runner) with the WDK, in its own crate outside this
  workspace, like `sigmacatch/ebpf`;
- every build needs its own signature; in the test VM that is test-signing
  (`bcdedit /set testsigning on`, Secure Boot off, self-signed cert), and a
  distributable build needs an EV certificate;
- a kernel bug is a BSOD, so the driver never becomes a hard dependency: the
  user-mode path keeps working when the driver is absent, refused by HVCI, or
  not loaded.

## How the pieces fit

```text
sigmacatch/driver/            # kernel sensor (excluded from the workspace)
├── src/lib.rs                # DriverEntry, control device \Device\sigmacatch,
│                             #   IOCTLs, ring buffer, process/image/thread/registry callbacks
└── src/flt.rs                # hand-written fltmgr FFI + minifilter (file/pipe events)

sigmacatch/src/windows/       # shared with the driver crate via #[path]
├── driver_protocol.rs        # wire record + IOCTLs (one source of truth, v6)
├── nt_file.rs                # NT path helpers, same_file, hashes
├── signature.rs              # WinVerifyTrust + security-catalog pass
└── version_info.rs           # PE version resource

sigmacatch/src/inputs/etw_driver.rs  # client: open device, check version,
                                     # drain IOCTL_READ_EVENTS, map kind → Sysmon event
```

The ring record is kind-tagged: one fixed layout carries every event, and the
mapping to a Sysmon id happens in user mode. A version mismatch is refused on
both sides, so a driver and a collector from different builds cannot silently
misread each other; the collector logs it and runs on ETW alone.

## Build and load

On a Windows host with WDK 10.0.22621, LLVM 17.0.6 and the Visual Studio C++
workload:

```pwsh
cargo build --release --target x86_64-pc-windows-msvc   # inside sigmacatch/driver/
```

The artifact is `sigmacatch_driver.dll`; rename it to `.sys` for the service.
Loading needs test-signing (`bcdedit /set testsigning on`, Secure Boot off, a
self-signed certificate). The [Dev VM](vm.md) automates the loop
(`scripts/dev_win_build.sh`), and [Build](../build.md#kernel-driver) has the
collector-side features.
