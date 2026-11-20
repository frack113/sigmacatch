# macOS support

Progress on adding macOS as a third platform: a macOS VM under QEMU/KVM on
the Linux host, a data-source survey to decide how regression data is
produced, and a prototype collector.

Status (2026-11-20): **Phases 1–2 done, Phase 3 committed + native build.**
Commit `b7125eda4` lands the collector skeleton: `inputs/macos.rs`
(`MacosCollector`, one-shot system.log reader, `CollectorKind` +
`EventProducer` impls), `--macos-path` CLI flag, `main.rs` dispatch arm,
`macos` cargo feature + tokio `fs`/`io-util`, module gate in `inputs/mod.rs`,
`Product::Macos` reserved in `types.rs`. All lints green (fmt, clippy, 366
tests, markdownlint, typos, zensical). Native in-VM build verified on
macOS Tahoe 26.7.3 (rustup + Xcode CLI tools installed). The collector
reads `/var/log/system.log` (392 events/run) but no rules match yet because
syslog lines lack the structured fields (`Image`, `CommandLine`, ...) that
macOS Sigma rules expect — next step is switching to os_log
(`log show --style ndjson`) for structured events, or adding `product: macos`
rules that match syslog-formatted events. Validate with
`regressiondata-check` once events match.

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
for an open-source collector. Meanwhile audit(4) is re-enablable on
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
  `User`, `ParentImage`): a **proc poller** using the public sysctl
  interface — `KERN_PROC_ALL` snapshot diff for new PIDs, then
  `proc_pidpath` (→ `Image`), `KERN_PROCARGS2` (→ `CommandLine`, root
  only, the same data `ps` shows), parent-PID map (→ `ParentImage`),
  uid (→ `User`). No audit(4), no EndpointSecurity entitlement, no SIP
  changes. Caveat: processes shorter than the poll interval are missed —
  acceptable for regression-data generation (scenarios are replayed).
  Event-driven V2 option: `dtrace proc:::exec` with SIP disabled in the
  controlled VM.
- Everything else from os_log: store NDJSON captures as `ndjson`
  regression data directly (`/usr/bin/log` full path, root).
- Upstream SigmaHQ has **no** `regression_data/rules/macos/` yet — our
  sets would create it (format machinery in `sigmacatch/src/regression/`
  already supports `logtype: json|ndjson|log`).

## Phase 3 — Collector prototype (next)

Wiring (all existing extension points):

- New cargo feature, gated `target_os = "macos"` in `sigmacatch/src/inputs/mod.rs`.
  The Linux features are gated `target_os = "linux"` and therefore silently
  inert elsewhere — macOS gets its own gates, it cannot borrow them.
- Orchestrator `sigmacatch/src/inputs/macos.rs` + an arm in
  `main.rs::dispatch_collector()` (currently exactly one platform arm is
  live per build).
- A `CollectorKind` returning `channels() -> None`,
  `rule_product() -> "macos"`, and `regression_format()` per Phase 2;
  an `EventProducer` (single async method pushing `Event`s, honouring the
  `stop` watch, dropping the sender when done). Reference patterns:
  `inputs/evtx.rs` (one-shot) and `inputs/linux.rs` (multi-source live).

V1 is **one-shot**: replay stored captures (proc-poller JSON lines or
os_log ndjson) through a file-based producer, `live_capture() = false`,
like the evtx path. Live capture (`log stream --style ndjson` + the proc
poller) is V2. The poller itself — `KERN_PROC_ALL` diff + `proc_pidpath` +
`KERN_PROCARGS2` — runs as root, no audit(4), no entitlement, consistent
with the project's self-capture principle (the Linux eBPF/builtin path,
not the auditd one).

Toolchain constraint: cross-compiling Rust to darwin from Linux needs
osxcross plus an Apple SDK (fragile and legally grey). Instead, compile
natively in the dev-variant macOS VM (`rustup` stable, target
`x86_64-apple-darwin` — the QEMU guest is x86_64 on this host). The host
build gate (`cargo xwin build` for Windows) has no macOS equivalent in CI;
for now the native in-VM build is the gate.

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
  matters for the plan — the collector does not depend on audit(4); the
  audit(4) survey above is recorded as measured context only.
- macOS auto-update is fully disabled on this VM (system and user plists:
  check/download/install/critical all false — verified on disk). A Sequoia
  VM got force-upgraded to Tahoe on 2026-11-16 despite the locks; the clean
  Tahoe install is the reaction (fresh BaseSystem, snapshot
  `clean-install`). Re-verify the locks after any update attempt.
- Tahoe is now the baseline OS for macOS work. The Sequoia-era audit(4)
  survey was measured on the previous disk (kept as
  `macos-old-sequoia.qcow2`); on the clean Tahoe VM the `KERN_PROC_ALL` +
  `KERN_PROCARGS2` path (the actual Phase 3 mechanism) is verified: `ps`
  exposes image paths and full argv, root sees everything.
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
