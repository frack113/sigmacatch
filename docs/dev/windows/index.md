# Windows telemetry without Sysmon

A native Windows collector that replaces Sysmon on hosts that do not have it,
mirroring the Linux eBPF collector. It emits the Sysmon event ids plus the
sigmacatch 5xx extensions, under the `sigmacatch` provider and the
`sigmacatch/Operational` channel — the stock Sysmon rules match unchanged.

<!-- markdownlint-disable MD033 -->
<iframe src="../../media/interactive/windows-telemetry.html?embed=1" loading="lazy" title="Windows telemetry path, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:1068/512;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*User-mode ETW (`etw`) covers network, DNS, registry, WMI and unloads with no
driver; the kernel driver (`driver`, implies `etw`) adds process, file, image,
pipe and thread events that ETW cannot reach.*

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

## What works today

- **Event Log channels** — always: they are in the default `winevt` build.
- **`etw`** — adds Sysmon-schema process, network, registry, DNS, WMI and
  unload events with no Sysmon and no driver: EID 1, 3, 12/13, 19/20/21, 22,
  25, 500, 507 and 511. EID 5 is not produced on this path.
- **`driver`** — when the `sigmacatch` service is loaded, the kernel sensor
  owns process, file, image, pipe and thread events (1/2/5/6/7/8/9/10/11/14/
  15/17/18/23/26/29/503-506/509/510) and ETW only keeps what user mode can
  observe. Without the driver, the same build falls back to ETW.

The limits are deliberate: no `ProcessGuid`, no `Hashes` on deleted files, no
signer name for catalog-signed images, and 509/510 are rate-limited. The
event-by-event state is [Sysmon coverage](coverage.md); the measurements are
[Measurements](evidence.md).
