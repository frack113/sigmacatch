# macOS support

Progress on adding macOS as a third platform: a macOS VM under QEMU/KVM on
the Linux host, a data-source survey to decide how regression data is
produced, and a prototype collector.

Status (2026-11-21): **Phases 1–3 done. Endpoint Security is the sole macOS
input.** The ES collector `inputs/macos_es.rs` (`MacosEsCollector`, implementing
`CollectorKind` and `EventProducer`) has two backends: the native
`endpoint-sec` client, and Apple's first-party `eslogger`
(`/usr/bin/eslogger`) as an automatic fallback. The native client is **killed
by AMFI at launch** when the binary carries the
`com.apple.developer.endpoint-security.client` entitlement without Apple's
signature (see "AMFI findings" below), so the `eslogger` fallback is the path
that works on a stock machine with SIP enabled; it is verified live in the VM
(exec/create/rename/unlink notifications with args, target path, ppid, audit
tokens). Plan A (os_log/system.log) was tested and **removed**: 69 macOS rules
loaded, 864+ events/cycle, **0 matches** — the os_log stream floods with
generic daemon events whose values do not match Sigma rule patterns.
**Plan B decision (2026-11-20):** the kext path is
blocked (SIP cannot be disabled on this OVMF VM — see "SIP findings" below)
and DTrace's kernel probes are SIP-gated. Research on how real macOS EDRs
capture telemetry (Fleet, Santa, Crescendo, mac-monitor, NuwaStone,
santamon) shows they all use Apple's **Endpoint Security framework**
(`ESClient`), which works with **SIP enabled** and has Rust bindings (the
`endpoint-sec` crate). **Plan B is re-scoped to the ES framework** — no
kext, no SIP disable, no DTrace.
**Plan:**

- **Plan A (user-mode, removed):** the os_log/system.log reader was validated
  in the existing Tahoe VM (0 matches) and then deleted — the Endpoint
  Security framework supersedes it as the sole macOS telemetry source.
- **Plan B (Endpoint Security, the sole macOS mode):** ES framework captures
  kernel telemetry (process, file, driver events) — the macOS equivalent of
  the Windows KMDF driver / Sysmon. Works with SIP enabled; no separate VM
  needed.

## Phase 1 — macOS VM under QEMU (done)

Setup on the AMD host (all steps verified):

- OSX-KVM cloned at `~/Games/Qemu/OSX-KVM`; `kvm_amd.conf` tweak applied
  (`ignore_msrs=1`, required on AMD or macOS panics at boot).
- `dmg2img` installed locally without root: `dnf download dmg2img lzfse-libs.x86_64`,
  extract the RPMs under `~/opt/dmg2img`, run with
  `LD_LIBRARY_PATH=$HOME/opt/dmg2img/usr/lib64`. Needed because the rpm is
  not in the base install and `sudo` is password-gated.
- macOS **Tahoe 26.7.3** (25G342) installed **fresh** from its own BaseSystem
  (`fetch-macOS-v2.py --shortname tahoe`, converted with `dmg2img`; the
  chunklist verification step fails harmlessly when not run from a TTY,
  `Errno 25`). The first VM went Sequoia 15.8.3 → auto-upgraded to Tahoe and
  hit a boot panic; the clean re-install is the supported state. Installer
  language **French**, keyboard **AZERTY** (the Sequoia VM had been set up
  on a QWERTY mapping, so the typed `azerty` password landed as `qwerty` —
  avoid that surprise by fixing the layout at install time).
- Disk: `~/Games/Qemu/qcow2/macos.qcow2` (128 GiB), same location as the
  other VM disks; qcow2 internal snapshot **`clean-install`** taken after
  provisioning (`qemu-img snapshot -c`, VM stopped). The polluted
  Sequoia-era disk is kept aside as `macos-old-sequoia.qcow2` (~50 GiB,
  deletable once the new VM is trusted). Not a libvirt domain — QEMU is
  launched directly, so it does not appear in virt-manager; the boot
  script is the launcher.
- Boot script: `~/Games/Qemu/OSX-KVM/sigmacatch-macos-boot.sh`
  (8 GiB RAM, 8 vCPU, monitor on `unix:/tmp/opencode/macos-monitor.sock`,
  SSH forward `tcp/2222 → 22`).
- Guest account `frack113` / `azerty` (house convention), SSH key
  `~/.ssh/id_sigmacatch` installed in `authorized_keys` (verified
  passwordless after the clean install + reboot).
- Auto-updates fully locked on Tahoe too (system and user plists:
  check/download/install/critical all false, verified on disk) — the
  Sequoia VM had been force-upgraded to Tahoe that way once; never click
  "Upgrade Now" in that VM.

### SMC device must stay disabled on Tahoe

The upgrade VM panicked at boot with `kSMCBadCommand (0x82)`: QEMU's
`isa-applesmc` only implements `APPLESMC_READ_CMD`, and macOS ≥ 15.4
enumerates SMC keys by index (`GET_KEY_BY_INDEX_CMD 0x12`) — on Sequoia
that just pinned `PerfPowerServices` at 100 % of a core, on Tahoe it
panics. Fix: no `-device isa-applesmc` at all; the `VirtualSMC.kext`
already enabled in OSX-KVM's OpenCore supplies the OSK keys (verified:
`PerfPowerServices` idle, `dockur/macos#583`, `acidanthera/bugtracker#2480/#2513`).
Watch for the fallback symptom (stuck at `AppleKeyStore operation failed`),
which would mean re-adding the device.

### CPU model is the load-bearing setting

The first boots panic'd or hung (friendly "restarted because of a
problem" screen; then a hang at `[EB|LOG:EXITBS:START]` with
`Haswell-noTSX`, the CPU `notes.md` recommends for Sonoma). The working
model for Sequoia on AMD Ryzen is **`Skylake-Client,-hle,-rtm`** —
confirmed by several Ryzen users in OSX-KVM PR #252 comments. With
`boot-args = keepsyms=1 -v debug=0x100` in `OpenCore/config.plist`
(verbose boot, panic text stays on screen instead of auto-reboot) any
regression will be diagnosable.

To change OpenCore config: edit `OpenCore/config.plist` (python
`plistlib`), then rebuild the EFI image without sudo —
`cd OpenCore && ./opencore-image-ng.sh --cfg config.plist --img
OpenCore.qcow2.new` works as a user (libguestfs direct backend); only the
script's trailing `sudo rm` cleanup fails (cosmetic). The trailing
`-hle,-rtm` matters on hosts without those features.

### Unattended boot (no picker, no disk selection)

Getting the VM to boot macOS on its own took three separate fixes; two of
them look like the same symptom, which is why this is worth writing down:

1. **Installer media detached** from the boot script (`BaseSystem.img` was
   still attached on `sata.3`, so a second bootable volume showed up). The
   two lines are commented out in `sigmacatch-macos-boot.sh`; re-attach
   them to reinstall.
2. **`Misc/Boot/ShowPicker=false`** in `OpenCore/config.plist` — necessary
   but not sufficient.
3. **Matching OVMF varstore size** — the real root cause. OSX-KVM's own
   boot scripts pair `OVMF_CODE_4M.fd` (3 653 632 bytes) with a 128 KiB
   `OVMF_VARS-*.fd`; a 4 MiB firmware needs a **540 672-byte** varstore
   (3 653 632 + 540 672 = 4 MiB). With the mismatch the firmware rejects
   the store and reinitialises NVRAM on **every** boot, so OpenCore can
   never keep its default entry and macOS loses NVRAM variables across
   power cycles. The visible effect: OpenCore tried to boot its default
   entry, which is the ESP ("EFI") holding OpenCore itself, failed, and
   fell back to the picker — with no timeout, since the fallback picker is
   not the timed one. Every cold start waited for a human.

   Fix: a real 4 MiB varstore, kept **outside** the git clone so QEMU's
   writes never dirty OSX-KVM:

   ```sh
   qemu-img convert -O raw /usr/share/edk2/ovmf/OVMF_VARS_4M.qcow2 \
     /home/papa/Games/Qemu/ovmf-vars-4m.fd     # 540672 bytes
   # boot script: -drive if=pflash,format=raw,file="$OVMF_VARS"
   ```

   Then select **MacOS** once in the picker and press **Ctrl+Enter** (with
   `Misc/Security/AllowSetDefault=true`) to store it as the default. After
   that, cold starts go straight to the Apple logo (verified twice, plus
   `nvram` variables surviving a power cycle).

   Rollback to a virgin NVRAM: delete `ovmf-vars-4m.fd` and re-run the
   `qemu-img convert` above; the next boot needs one manual selection
   again. On the guest side, `sudo nvram -d <var>` removes a variable.

Boot is still verbose (`boot-args = keepsyms=1 -v debug=0x100`): kernel
messages scroll before the Apple logo. That is deliberate for a dev VM
(panics stay readable). To get the clean graphical boot, drop `-v` from the
`boot-args` in `OpenCore/config.plist` and regenerate the EFI image with the
command above.

## Phase 2 — Data-source survey (done, measured)

Method: run each candidate on the VM, check the field vocabulary against
the existing Sigma `product: macos` rules (upstream has
`rules/macos/{process_creation,file_event}`; the rules use Sysmon-style
fields — `Image`, `CommandLine`, `ParentImage`, `User` — under
`category: process_creation, product: macos`).

### Unified Logging (os_log) — rich, but no process_creation

- `sudo /usr/bin/log show --style ndjson --last 5m` returned **144 240
  events** on the freshly installed VM (~28k/min) — the volume is real;
  regression captures will need `--predicate` scoping.
- NDJSON fields available: `timestamp`, `processImagePath`, `processID`,
  `senderImagePath`, `subsystem`, `category`, `messageType`,
  `eventMessage`, `bootUUID`, `traceID`… NDJSON is a `logtype` the
  SigmaHQ spec accepts, so captures may be storable as-is.
- No argv / CommandLine anywhere in the records — os_log alone cannot
  feed `process_creation` rules.
- Two gotchas: the macOS default shell is zsh and `log show` gets
  misparsed there (`zsh:log: too many arguments`) — always use the full
  path `/usr/bin/log`; and full fidelity (all processes/levels) requires
  root.

### OpenBSM audit(4) — the only free process stream (deprecated upstream)

Hard fact found in `/etc/security/audit_control.example`:

> audit(4) has been deprecated since macOS 11.0, disabled since macOS
> 14.0, and WILL BE REMOVED in a future version of macOS. Applications
> that require a security event stream should use the EndpointSecurity(7)
> API instead.

EndpointSecurity requires an Apple-granted entitlement — a hard blocker
for an *in-process* ES client (a locally signed binary carrying the
entitlement is killed by AMFI, see "AMFI findings" below). The workaround
found 2026-11-21: Apple ships its own entitled ES client,
`/usr/bin/eslogger`, which runs as root with SIP on and emits NDJSON —
that is Plan B's working backend. Meanwhile audit(4) is re-enablable on
15.8.3, which was done on the VM:

1. `cp /etc/security/audit_control.example /etc/security/audit_control`
   (the file ships as `.example` only; `auditd` is not even loaded).
2. `flags:lo,aa,ex` (exec class) and `policy:cnt,argv` (record argv).
3. `launchctl enable system/com.apple.auditd` as root, then reboot
   (required).

Verified: `auditd` runs after reboot; `/var/audit/*not_terminated` BSM
files appear; `praudit` shows `execve` records with `path,/usr/bin/tail`
(→ `Image`), `exec arg,tail,-20` (→ `CommandLine`), `subject,frack113,…`
(→ `User`). No `ParentImage` equivalent — the parent must be resolved
from a process table, like the Linux auditd path already does.

Flat files (`install.log`, httpd) remain the fallback tail source, same
shape as the Linux `builtin` collector.

### Format decision (for Phase 3)

**Direction set by the project's own principle: sigmacatch captures by
itself — no dependency on audit(4)** (deprecated, disabled by default
since macOS 14, slated for removal). The audit(4) findings above stay as
measured context, not as a plan component.

- Process events (`process_creation` fields `Image`, `CommandLine`,
  `User`, `ParentImage`): **superseded by Plan B** — the Endpoint Security
  framework (eslogger backend) delivers real `exec` notifications with
  args, cwd, target path, ppid and audit tokens, no polling gap. The proc
  poller (`KERN_PROC_ALL` diff + `proc_pidpath` + `KERN_PROCARGS2`) stays
  documented as the measured fallback only.
- Everything else from os_log: store NDJSON captures as `ndjson`
  regression data directly (`/usr/bin/log` full path, root).
- Upstream SigmaHQ has **no** `regression_data/rules/macos/` yet — our
  sets would create it (format machinery in `sigmacatch/src/regression/`
  supports `logtype: json|ndjson|log`; the ES collector emits
  `json`).

## Phase 3 — Collector prototype (done)

One live collector:

- **`inputs/macos_es.rs`**: `MacosEsCollector`, live Endpoint Security
  collector, `live_capture() = true`. Default backend `Auto`: try the native
  `endpoint-sec` client first, fall back to Apple's `eslogger` when the
  client is not entitled (the AMFI case).

Wiring (all existing extension points):

- New cargo feature `macos`, gated `target_os = "macos"` in
  `sigmacatch/src/inputs/mod.rs`. The Linux features are gated
  `target_os = "linux"` and therefore silently inert elsewhere — macOS
  gets its own gates, it cannot borrow them.
- Orchestrator `inputs/macos_es.rs` and an arm in
  `main.rs::dispatch_collector()` (currently exactly one platform arm is
  live per build).
- A `CollectorKind` returning `channels() -> None`,
  `rule_product() -> "macos"`, and `regression_format()` per Phase 2
  (Plan B: `DataFormat::Json`); an `EventProducer` (single async method
  pushing `Event`s, honouring the `stop` watch, dropping the sender when
  done). Reference patterns: `inputs/evtx.rs` (one-shot) and
  `inputs/linux.rs` (multi-source live).

Toolchain constraint: cross-compiling Rust to darwin from Linux needs
osxcross plus an Apple SDK (fragile and legally grey). A **type-check-only
darwin cross-check** works from the host with the musl/x86_64-apple-darwin
cc (`CRATE_CC_NO_DEFAULTS=1 CC_x86_64_apple_darwin=cc … cargo check
--target x86_64-apple-darwin`); the real gate is the native in-VM build
(`rustup` stable, target `x86_64-apple-darwin` — the QEMU guest is x86_64
on this host). The host build gate (`cargo xwin build` for Windows) has no
macOS equivalent in CI; for now the native in-VM build is the gate.

## Phase 4 — Regression-data loop

1. Run the one-shot collector in the VM → regression sets under
   `sigma/regression_data/rules/.../` (data file + `info.yml`, provider
   `sigmacatch`, `regression_tests_path` annotated on the rule) — the
   `sigmacatch/src/regression/` machinery is collector-agnostic and needs
   no changes if Phase 2's format decision holds.
2. Pull the sets to the host over SSH (small transport script, the
   macOS analogue of `scripts/winrm_vm.py`).
3. Validate on the host with
   `sigmacatch/src/bin/regressiondata-check.rs` (cross-platform, no
   collector required).
4. Push rule-by-rule as today (`SigmaRepo::upload_rule_batches`).

Milestone for "macOS supported": one Sigma rule with
`logsource.product: macos` passes `regressiondata-check` end to end from
VM-captured ndjson.

## Risks / open questions

- ✅ Sequoia-in-QEMU stability on AMD: **resolved** — `Skylake-Client,-hle,-rtm`
  (OSX-KVM PR #252), verbose boot-args kept as a diagnostic net.
- Apple will remove audit(4) entirely (documented in the OS itself); the
  EndpointSecurity replacement needs an Apple entitlement. This no longer
  matters for the plan — the collector does not depend on audit(4), and
  the in-process ES client is not the only ES path: Apple's own entitled
  `eslogger` binary is the working fallback (see "AMFI findings").
- macOS auto-update is fully disabled on this VM (system and user plists:
  check/download/install/critical all false — verified on disk). A Sequoia
  VM got force-upgraded to Tahoe on 2026-11-16 despite the locks; the clean
  Tahoe install is the reaction (fresh BaseSystem, snapshot
  `clean-install`). Re-verify the locks after any update attempt.
- Tahoe is now the baseline OS for macOS work. The Sequoia-era audit(4)
  survey was measured on the previous disk (kept as
  `macos-old-sequoia.qcow2`); on the clean Tahoe VM `ps` exposes image
  paths and full argv, root sees everything.
- `eslogger` suppresses notifications from its own process tree (a
  capture started from a shell reports nothing for that shell's children,
  but reports unrelated processes fine) — irrelevant for sigmacatch,
  which runs as a standalone root process.
- The macOS VM is not a libvirt domain (plain QEMU from the boot script);
  no `virsh` snapshot/reset support. Clean-room rollback is the qcow2
  internal snapshot: stop QEMU, `qemu-img snapshot -a clean-install`. A
  `scripts/reset_macos.sh` wrapper is still to be created, and a libvirt
  conversion (via OSX-KVM's `macOS-libvirt-Catalina.xml`) is an option.
- `log stream`/`log show` need root for full fidelity; the collector runs
  under root (same as the Linux auditd path), which is now proven via
  SSH and `sudo` on the VM.
- audit(4) is off by default; enabling it (`audit_control`, launchctl,
  reboot) belongs in VM provisioning, not the collector — done on this VM
  for the survey, not as a collector dependency.
- No CI runner for macOS: the native in-VM build gate must be documented
  as the review requirement until that changes.
- The macOS VM is not a libvirt domain (plain QEMU from the boot script);
  see the snapshot note above.

## SIP findings (why the kext/DTrace paths were blocked, 2026-11-20)

The kext path requires SIP disabled. On this OVMF VM, SIP **cannot be
disabled**:

- `csrutil disable` run in the BaseSystem installer Terminal does **not**
  persist: after a clean shutdown, the OVMF varstore contains **no** `SIP`
  NVRAM variable. The installer environment's `csrutil` cannot write the
  `SIP` variable (SIP blocks the write).
- The guest `nvram SIP` command reads "data was not found" and the write
  `nvram SIP=2` is silent (blocked by SIP); `csrutil status` stays
  "enabled".
- The remaining option — writing the `SIP` NVRAM variable from the host into
  `ovmf-vars-4m.fd` — is complex (the OVMF variable-store layout is non-
  trivial) and the exact `SIP` byte value is not confirmable from a live
  source. Abandoned in favour of the ES framework, which needs no SIP change.

DTrace, the other kernel-telemetry candidate, is also SIP-gated: with SIP
on, the kernel probes (`proc:::execve-success`, `syscall:::execve`,
`begin`/`end`) are **not available** — only user-space/time probes (`tick`)
work. So DTrace cannot provide system-wide kernel telemetry with SIP on
either.

**Conclusion:** both the kext and DTrace paths require SIP disabled, which
cannot be done on this VM. The Endpoint Security framework is the correct
Plan B: it provides the same kernel-level telemetry (process, file, network)
with SIP enabled, and has Rust bindings.

## AMFI findings (why the native ES client cannot run, 2026-11-21)

The native `endpoint-sec` client requires the
`com.apple.developer.endpoint-security.client` entitlement, which Apple
documents as *"must be requested from Apple"* — it is a **restricted**
entitlement. On this VM:

- Ad-hoc `codesign` with `scripts/macos/endpoint-security.entitlements`
  succeeds, but the kernel kills the binary **at launch**:
  `AMFI: ... is adhoc signed`, `Adhoc signed app with restricted
  entitlements detected`, `Code=-424 "The file is adhoc signed but
  contains restricted entitlements"`, `ASP: Security policy would not
  allow process` (exit 137).
- Self-signed-certificate signing also fails headless:
  `security add-trusted-cert` is denied
  (`SecTrustSettingsSetTrustSettings: The authorization was denied since
  no user interaction was possible`), `find-identity` lists 0 valid
  identities, and `codesign` returns `errSecInternalComponent`.

**Conclusion:** a generic, locally built sigmacatch binary cannot create
its own ES client on a stock machine. The entitlement is only obtainable
from Apple (as for Fleet, Santa, etc.). The working path is Apple's own
entitled ES client, `/usr/bin/eslogger`, which runs as root with SIP on
and emits one NDJSON object per notification — the `eslogger` backend in
`inputs/macos_es.rs`. The native client path stays in the code for
vendor builds that do hold the entitlement (`Backend::Native`).

## Telemetry plan

### Plan A — User-mode telemetry (removed 2026-11-21)

The first approach read os_log (structured JSON) plus plain-text system
logs, producing events with fields that match macOS Sigma rules:

| Source | Command / Path | Format | Purpose |
|--------|----------------|--------|---------|
| os_log | `/usr/bin/log show --style ndjson` | ndjson | Primary structured source (equivalent of auditd/ETW) |
| system.log | `/var/log/system.log` | plain text | Syslog events |
| secure.log | `/var/log/secure` | plain text | Authentication events |
| airportd, etc. | `/var/log/` | plain text | Additional daemons |

It was validated in the VM and produced **0 matches** against the 69 macOS
Sigma rules — the os_log stream is flooded with generic daemon events whose
values do not match rule patterns. It has been **removed** (2026-11-21): the
Endpoint Security framework (Plan B) supersedes it as the sole macOS
telemetry source, so `inputs/macos.rs` and the `--macos-path` /
`--macos-source` CLI flags were deleted.

### Plan B — Endpoint Security framework (the sole macOS mode)

After the kext path was blocked by SIP (see "SIP findings" below) and DTrace's
kernel probes proved SIP-gated, research on how real macOS EDRs capture
telemetry (Fleet, Santa, Crescendo, mac-monitor, NuwaStone, santamon) shows
they all use Apple's **Endpoint Security framework** (`ESClient`) — not a
kext, not DTrace, and **without disabling SIP**. The ES framework is Apple's
official API for security telemetry and is designed to run with SIP enabled.

The `endpoint-sec` Rust crate (HarfangLab) provides safe bindings: a `Client`
created with `Client::new(handler)`, subscribed via `Client::subscribe(&[...])`
to the event types of interest. Each event is delivered to the handler as a
`Message` carrying structured data:

- **`EventExec`** — process execution (pid, ppid, image path, args, env) —
  the primary `process_creation` Sigma target.
- **`EventFork`**, **`EventExit`** — process creation/termination.
- **`EventOpen`**, **`EventCreate`**, **`EventWrite`**, **`EventUnlink`**,
  **`EventRename`** — file operations.
- **`EventSudo`**, **`EventSetuid`/`Seteuid`/`Setgid`** — privilege changes.
- **`EventOpensshLogin`**, **`EventLoginLogin`** — logins.
- **`EventKextLoad`/`EventKextUnload`**, **`EventTrace`** — kext loads,
  process attach.
- Network connect, authentication, and other events.

Each event exposes `Process` (pid/ppid/path), `ExecArgs`, `ExecEnvs`, and
`File` (path/stat) — everything needed to match `product: macos` Sigma rules
(`Image`, `CommandLine`, `ParentImage`, `User`).

**Requirements for an ES client:**

1. The process holds the `com.apple.developer.endpoint-security.client`
   entitlement — Apple-granted only (restricted; a locally signed binary
   is killed by AMFI, see "AMFI findings").
2. The user approves the client (a TCC dialog on first run).
3. The process runs as root.

Requirement 1 cannot be satisfied by a locally built binary, so Plan B
uses **two backends** in `inputs/macos_es.rs`:

1. **Native** (`Backend::Native`): sigmacatch's own `endpoint-sec` client.
   For vendor builds that hold the entitlement. `Client::new` runs on a
   dedicated `std` thread (the `Client` is `!Send`/`!Sync`); the handler
   converts each `Message` into a `RawNotification` and pushes the
   resulting `Event` into the runner channel via `try_send` (never blocks
   the ES thread).
2. **Eslogger** (`Backend::Eslogger`): Apple's first-party
   `/usr/bin/eslogger`, already entitled, run as root. It emits one
   NDJSON object per notification; the pure, cross-platform
   `RawNotification::from_eslogger_json` maps it to the same
   `RawNotification` (exec: `event.exec.target.executable.path` →
   `Image`, joined `event.exec.args` → `CommandLine`,
   `process.executable.path` → `ParentImage`, audit tokens →
   `ProcessId`/`ParentProcessId`/`UserId`, `time` → `UtcTime`; create:
   `event.create.destination` existing_file/new_path →
   `TargetFilename`; rename: source + destination; unlink: target;
   setuid/sudo: uid/username/command).
3. **Auto** (`Backend::Auto`, default): try native first; on
   `NewClientError::NotEntitled|NotPermitted|NotPrivileged` fall back to
   eslogger with a warning. Any other native failure is fatal.

Field mapping keeps the Sigma field names the `product: macos` rules use
(`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `User`,
`UserId`, `ProcessId`, `ParentProcessId`), injects `category` per kind
(`process_creation`, `file_event`, `file_rename`, `driver_load`;
setuid/sudo/login stay category-less so the engine fails open), and
writes regression data as **JSON** (`DataFormat::Json`, provider
`sigmacatch-endpoint-security`).

**Plan B implementation (done 2026-11-21):**

1. `endpoint-sec` crate v0.6.2 added (macOS-gated, optional, feature
   `macos`).
2. `inputs/macos_es.rs`: `MacosEsCollector` implementing `CollectorKind`
   and `EventProducer`, with the two backends above and the pure
   `RawNotification` model testable on any platform.
3. Selected by the `macos` cargo feature; the backend defaults to `Auto`
   (native client first, `eslogger` fallback).
4. Verified live in the VM: eslogger NDJSON parsed, events pushed,
   `product: macos` rules loaded.

### Test VM strategy

- **VM 1 (Tahoe 26.7.3, SIP on):** both plans validated in one VM.
  Already provisioned (`frack113`/`azerty`, SSH key, clean-install
  snapshot). Plan B (Endpoint Security) works with SIP enabled, so the
  second SIP-off VM is no longer needed.
