# Windows dev VM (`sigmacatch-dev`)

A QEMU VM dedicated to building and testing the KMDF kernel driver
(`sigmacatch/driver/`) without pushing to GitHub. The CI (`Driver` workflow)
stays the green gate; this VM gives a ~2 min local build loop.

## What it is

- Clone (disk + domain) of the Windows 11 test VM — same provisioning: WinRM
  on port 5985, test-signing already on, MinGit, `frack113`/`azerty`
  (admin-group member with a non-elevated WinRM token; use stored-credential
  scheduled tasks to run elevated — see pitfalls).
- Domain `sigmacatch-dev`, MAC `52:54:00:ea:59:6b`, DHCP IP on virbr0
  (e.g. `192.168.122.158`), 6 vCPU / 8 GiB, 128 GiB disk.
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

## Build loop

```sh
scripts/dev_win_build.sh
```

Syncs `driver/` + `src/windows/` to `C:\sigmacatch-dev\sigmacatch\`, runs
`C:\sigmacatch-dev-build.ps1` (scheduled task, no elevation needed), and
fetches `sigmacatch_driver.dll` to `target/sigmacatch-dev/` (rename to `.sys`
for the service). Logs live on the VM at `C:\sigmacatch-dev-build.log`.

Loading and testing the driver against a live VM session is the test VM's
job (`heiter-test-vms-qemu` skill); the dev VM can also load local builds the
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
- Both VMs currently report the same hostname (`SIGMACATCHVM`); renaming the
  dev VM (`Rename-Computer` + reboot) is pending, not blocking builds.
