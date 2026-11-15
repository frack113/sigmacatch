# Windows telemetry without Sysmon

A native Windows collector that replaces Sysmon on hosts that do not have it,
mirroring the Linux eBPF collector. It emits the Sysmon event ids plus the
sigmacatch 5xx extensions, under the `sigmacatch` provider and the
`sigmacatch/Operational` channel — the stock Sysmon rules match unchanged.

Two sources, one per purpose:

- **User-mode ETW** (`feature etw`) — network, DNS, registry, WMI, unloads;
  no driver, works on any elevated Windows host.
- **Kernel driver** (`feature driver`, implies `etw`) — process, file, image,
  pipe and thread events that ETW cannot reach.

`inputs/windows.rs` runs the Event Log channels next to **exactly one** process
source: the driver when its service is loaded and answers the current protocol
version, native ETW otherwise. The ETW main session keeps running next to the
driver, because network, DNS, registry, WMI and unloads are user-mode only.

What sigmacatch produces today, per Sysmon event id and with the fields that
stay absent, is [Sysmon coverage](coverage.md). The pages here explain the
machinery behind it:

| Page | Content |
|---|---|
| [ETW](etw.md) | sessions, TDH decoding, provider quirks |
| [ETW events](etw-events.md) | network, DNS, registry, WMI, unloads |
| [Kernel driver](driver.md) | why a driver, callbacks, minifilter, protocol |
| [Driver events](driver-events.md) | files, pipes, registry and thread events, 509/510 |
| [Coverage](coverage.md) | event-by-event comparison with Sysmon (reference) |
| [Measurements](evidence.md) | M0 provider measurements and the VM validation journal (reference) |
| [Dev VM](vm.md) | the QEMU box used to build and load the driver |

## Scope and decisions

### Environment

The QEMU Windows 11 test VM (`heiter-test-vms-qemu`). No distribution target,
no code-signing budget: the kernel driver is test-signed there, and a
distributable build is a separate signing effort. See
[the driver decision](driver.md#decision-the-driver-replaces-sysmon).

### No ferrisetw

The crate is dormant (last push 2025-10), pins `windows` 0.61 against our 0.62,
and its manifest decode is re-implementable on the `windows` crate we already
depend on. Hand-roll on `windows` 0.62.2 (`Win32_System_Diagnostics_Etw`:
`StartTraceW`, `EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`; TDH:
`TdhGetEventInformation`, `TdhGetPropertySize`, `TdhGetProperty`).

### The kernel driver is the primary source

`sigmacatch/driver/` supplies what user-mode ETW cannot reach (process
create/exit, process access, file paths); see
[the driver decision](driver.md#decision-the-driver-replaces-sysmon). User-mode
ETW stays as the portable fallback and the reference the driver output is
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

## Status

The user-mode path is complete for its ids (M0-M5); the driver is implemented
and validated on the VM (D0-D2). Current per-id state: [Sysmon coverage](coverage.md).

| Milestone | State |
|---|---|
| M0 — ETW/TDH spike on the VM | done, [measurements](evidence.md#m0-results-win11-vm-2026-11-14) |
| M1 — session scaffold | done |
| M2 — TDH builder (EID 1, 3, 12/13, 19-21, 22, 25, 500, 507, 511) | done |
| M3 — Windows orchestrator | done |
| M4 — regression path end to end | done |
| M5 — extend coverage | done, mostly through the driver |
| D0-D2 — kernel driver (channel, process, access, images, minifilter) | done, [validation](evidence.md#vm-validation-2026-11-14) |
| D3 — parity | documented in [coverage](coverage.md) |
