# Windows dev VM (`sigmacatch-dev`)

A QEMU VM dedicated to building and testing the KMDF kernel driver
(`sensor/windows/`) without pushing to GitHub. The CI (`Driver` workflow)
stays the green gate; this VM gives a ~2 min local build loop.

## What it is

- Clone (disk + domain) of the Windows 11 test VM — same provisioning: WinRM
  on port 5985, test-signing already on, MinGit, and an account in the admin
  group (its WinRM token is still filtered; use stored-credential scheduled
  tasks to run elevated — see pitfalls).
- Domain `sigmacatch-dev`, DHCP on virbr0; 8 vCPU in a single socket / 8 GiB,
  128 GiB disk. The guest hostname is inherited from the test VM — see the
  hostname pitfall below.
- Disk is a clone of the test VM's overlay; the underlying `win11.qcow2`
  base is shared read-only between both VMs — never modify it directly.

## Installed toolchain (parity with CI's `driver.yml`)

| Component | Version | Source of truth |
|---|---|---|
| Windows SDK | 10.0.22621 | `winget install -s winget Microsoft.WindowsSDK.10.0.22621` |
| WDK | 10.0.22621 | `winget install -s winget Microsoft.WindowsWDK.10.0.22621` |
| LLVM (libclang) | 17.0.6 | `winget install -s winget LLVM.LLVM --version 17.0.6` |
| VS Build Tools (MSVC linker) | preinstalled on the base image | `vswhere` finds it with the `VCTools` workload |
| Rust (user install) | stable (`cargo 1.100`) | `rustup-init -y --default-toolchain stable --target x86_64-pc-windows-msvc` |

The build uses the same environment pins as the CI cache-hit path
(`WDKContentRoot` + `Version_Number`, which `wdk-build` honours before its
registry discovery and latest-SDK-version scan), plus
`LIBCLANG_PATH` and the CI `RUSTFLAGS` (`-D warnings -C target-feature=+crt-static`).

## Build box optimization

The VM is build-only; the guest was stripped accordingly (snapshot
`toolchain-optimized` holds this state — `virsh snapshot-revert sigmacatch-dev
toolchain-optimized` restores it):

- vCPUs: 8 in one socket (`<topology sockets='1' cores='8' threads='1'/>`) —
  Windows 11 client caps online CPUs at **2 sockets**, so QEMU's default
  `socket-per-vCPU` layout silently halves the guest; keep the topology
  explicit after any vCPU change.
- Services disabled: SysMain, WSearch, Spooler, PcaSvc, MapsBroker, WerSvc,
  wisvc, RetailDemo, Xbl/Wpc/SEMgr/Phone/SCard/SCPolicy (pass 1), then
  audio, AppX/store helpers, SMB client+server, BITS/UsoSvc/edgeupdate,
  CDPSvc/WpnService, Device Inventory/DPS/Dusm, geolocation/radio, autoplay,
  IP-helper/WPAD/SSDP, TokenBroker/wlidsvc, VirtioFs/WinFsp/balloon,
  IpOverUsbSvc, NcbService, camsvc, TrkWks, BDESVC + the per-user service
  templates (Start=4 in registry: cbdhsvc, CDPUserSvc, UdkUserSvc,
  WpnUserService, webthreatdefusersvc) — the instances only die at reboot.
  Protected services that refuse `sc config` and were left as-is: AppXSvc,
  ClipSVC, NgcSvc/NgcCtnrSvc, wscsvc, WinHttpAutoProxySvc. ~45
  auto+running services before, 35 core ones after (plus 0 per-user).
- Search: the WSearch indexing service is disabled, and the taskbar search UI
  (`SearchHost.exe`, ~120 MB, owned by the CBS shell package, NOT by WSearch)
  is kept from starting via the account's HKCU
  (`SearchboxTaskbarMode=0`, `DisableSearchBoxSuggestions=1`); verified absent
  after reboot. It only comes back on demand if someone searches from the
  Start menu on the console. The old index data (ProgramData\Microsoft\Search)
  was deleted.
- Store bloat removed (Teams, Xbox suite, YourPhone, Bing suite, Zune, Todos,
  Solitaire, Clipchamp, DevHome, Widgets, Outlook, PowerAutomate, Feedback…);
  kept: Store, winget/DesktopAppInstaller, Terminal, Notepad, Calculator,
  Paint, Snipping, Photos, the fr-FR language pack, codecs, framework packages.
- Scheduled tasks disabled: EdgeUpdate x2, Application Experience (incl. the
  Compatibility Appraiser), CEIP (Consolidator/UsbCeip), WER QueueReporting,
  Maps, Device Information, Feedback/Siuf, and the Windows Defender ones.
- Defender: build-tree exclusions `.cargo`, `.rustup`, LLVM, Windows Kits,
  VS 2022, `C:\sigmacatch-dev` + the toolchain processes; real-time
  protection is off; the scheduled Defender scan tasks are disabled.
  Windows Update policy = NoAutoUpdate=1.
- Power: High-performance scheme, hibernation off, ReTrim done (host-side
  sparse image stays ~32 GiB thanks to `discard=unmap`).

## Build loop

The loop is driven by a maintainer-local script, kept with the agent tooling
rather than in this repository. It:

- syncs local `sensor/windows/` + `sensor/windows/protocol/` to
  `C:\sigmacatch-dev\sigmacatch\driver\`;
- runs `C:\sigmacatch-dev-build.ps1` (scheduled task, no elevation needed);
- fetches `sigmacatch_driver.dll` to `target/sigmacatch-dev/` (rename to `.sys`
  for the service).

Logs live on the VM at `C:\sigmacatch-dev-build.log`.

Loading and testing the driver against a live VM session is the test VM's
job; the dev VM can also load local builds the
same way (`sc create` + test-signing), but keep the two boxes separate so the
validation VM stays clean-room.

## CI parity

The dev VM must stay in sync with `.github/workflows/driver.yml`:
`WDK_VERSION` / `LLVM_VERSION` there (and the winget installs in this doc)
must change together. If the CI gains a new install step, the dev VM needs it
too — drift shows up as "compiles locally, fails in CI".

## Pitfalls already paid

- The VM's `msstore` winget source is broken (`0x8a15000f`); always pass
  `-s winget` to `winget install`.
- `schtasks` created without `/ru`/`/rp` becomes "Interactive uniquement" and
  silently never runs headless — always create with stored credentials.
- `WinRM` sessions run with a filtered token even for admin-group members;
  machine-scope installs need a scheduled task with `/rl highest` (plus
  `/ru`/`/rp`).
- Both VMs report the same guest hostname; renaming the dev VM
  (`Rename-Computer` + reboot) is pending, not blocking builds.
