# macOS support

macOS is the third platform in sigmacatch, after Windows and Linux. Its sole
input is the **Endpoint Security** framework (cargo feature `macos`): a live
collector that reads Apple's kernel telemetry and writes `product: macos`
regression data. The collector is documented in
[macOS collector](../collectors/macos.md); the QEMU test VM that validates it
is in [macOS dev VM](vm.md).

## Why Endpoint Security

Apple's security-telemetry options narrow to one:

- **audit(4)** — deprecated since macOS 11, disabled by default since 14, and
  slated for removal by Apple (the OS documents this in
  `/etc/security/audit_control.example`).
- **kext / DTrace** — both require SIP disabled. On the QEMU dev VM, SIP
  **cannot** be disabled: the installer's `csrutil` cannot write the `SIP`
  NVRAM variable (SIP blocks the write), and with SIP on, DTrace's kernel
  probes (`execve-success`, …) are unavailable.
- **os_log / system.log** — measured on the dev VM: `log show --last 5m`
  returns ~144k events, and they produce **0 matches** against the 69
  `product: macos` rules. The stream is flooded with generic daemon events
  that carry no argv, so `process_creation` rules cannot be fed from it.

Endpoint Security (`ESClient`) is what real macOS EDRs (Fleet, Santa,
Crescendo, mac-monitor, NuwaStone) all use: it delivers kernel-level process,
file and privilege telemetry **with SIP enabled**, and has Rust bindings
(the `endpoint-sec` crate).

## The entitlement problem

An ES client must:

1. carry the `com.apple.developer.endpoint-security.client` entitlement — a
   *restricted* entitlement that only Apple can grant (Fleet, Santa, …);
2. be approved by the user (a TCC prompt on first connection);
3. run as root.

Point 1 is the hard part. A locally built sigmacatch binary cannot satisfy
it: ad-hoc signing with the entitlement is **killed by AMFI at launch**
(`Code=-424 "adhoc signed but contains restricted entitlements"`), and
self-signed-certificate signing fails headless (no valid identity,
`errSecInternalComponent`).

[`collector/macos/sign.sh`](https://github.com/frack113/sigmacatch/blob/main/collector/macos/sign.sh)
wraps the attempt: it signs `target/release/sigmacatch` (or the binary you
pass) with `collector/macos/endpoint-security.entitlements`, ad-hoc by default
and with `SIGN_IDENTITY=<keychain identity>` when ad-hoc is refused — useful to
reproduce the failure modes on a desktop macOS box, never a way around Apple's
grant.

The collector therefore offers two backends:

- **`eslogger`** — the path that works out of the box. Apple's first-party
  `/usr/bin/eslogger` is itself entitled, runs as root with SIP on, and emits
  one NDJSON object per notification. sigmacatch parses it with a pure,
  cross-platform parser.
- **native** — sigmacatch's own `endpoint-sec` client, used when the binary
  *is* entitled (a vendor build).

The default backend is **`auto`**: try the native client first, fall back to
`eslogger` when it reports it is not entitled (a warning is logged); any other
native failure is fatal — no fallback.

## What it captures

The collector subscribes to exec, create, rename, unlink, setuid, sudo,
kext-load and console-login notifications. `open` and `write` are excluded
from the default set: on a live system they fire thousands of times per
second and would drown the runner channel.

Each notification becomes one JSON document with the Sigma field names the
`product: macos` rules use — `Image`, `CommandLine`, `ParentImage`,
`TargetFilename`, `User`/`UserId`, `ProcessId`/`ParentProcessId`, `UtcTime` —
plus a `category` for rule pruning (`process_creation`, `file_event`,
`file_rename`, `driver_load`). Regression data is written as JSON
(`DataFormat::Json`, provider `sigmacatch-endpoint-security`); upstream
SigmaHQ has no `regression_data/rules/macos/` directory yet, so captured sets
create it.

## Building and running

- **macOS host required** — the executable cannot be linked from Linux (the
  `aarch64-apple-darwin` linker and the C dependencies need the Apple SDK).
  The `macos-latest` CI job builds and tests the arm64 binary; see
  [Build](../build.md#macos).
- **Root** — the collector runs under root, same as the Linux auditd path.
- **CI coverage** — build, test, lint and release jobs run on `macos-latest`
  (arm64) runners; the release archive targets `aarch64-apple-darwin`. The
  in-VM build stays the gate for native entitlement behaviour.

The `eslogger` backend is verified live on the [dev VM](vm.md): NDJSON
parsed, events pushed, `product: macos` rules loaded and matching.

## Known behaviours

- `eslogger` suppresses notifications from its own process tree: a capture
  started from a shell reports nothing for that shell's children, but
  unrelated processes are reported fine. Irrelevant for sigmacatch, which
  runs as a standalone root process.
- `ParentImage` is the pre-exec image of the exec'ing process — in the usual
  fork+exec sequence, the shell that spawned the new image.
- Setuid/sudo/login kinds carry no Sigma `category` (the taxonomy has none);
  the engine fails open on them instead of pruning rules that might match.
