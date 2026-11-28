# macOS dev VM

The QEMU/KVM macOS VM used to validate the macOS collector: a Tahoe guest
under OpenCore on the Linux host, launched directly by a boot script (not a
libvirt domain). It is the test box for the `macos` feature, the macOS
analogue of the [Windows dev VM](../windows/vm.md).

## What is on it

- **macOS Tahoe 26.7.3** (25G342), installed fresh from its own BaseSystem
  (OSX-KVM `fetch-macOS-v2.py --shortname tahoe` + `dmg2img`). Installer
  language French, keyboard AZERTY — set the layout at install time; with a
  QWERTY guest the keys send different characters.
- Disk: a 128 GiB `macos.qcow2` outside the project tree, with a qcow2 internal
  snapshot **`clean-install`** taken after provisioning (VM stopped,
  `qemu-img snapshot -c`).
- Boot script `sigmacatch-macos-boot.sh` (8 GiB RAM, 8 vCPU, monitor on
  `unix:/tmp/opencode/macos-monitor.sock`, SSH forward `tcp/2222 → 22`).
- A local guest account with an SSH key in `authorized_keys`.
- **A Rust toolchain inside the guest**: `rustc`/`cargo` 1.100.0 on
  `stable-x86_64-apple-darwin`, Xcode CommandLineTools (Apple clang 21). The
  guest builds, lints and tests the `macos` feature itself — `cargo build
  --locked --target x86_64-apple-darwin -p sigmacatch --no-default-features
  --features macos --all-targets`, `cargo clippy --all-targets
  --no-default-features --features macos -- -W warnings`, `cargo test --locked
  -p sigmacatch --no-default-features --features macos`. The guest is x86_64
  and keeps the explicit `--target`; the GitHub `macos-latest` runner is arm64
  and builds natively. `clippy` and `rustfmt` are separate components:
  `rustup component add clippy rustfmt`. A macOS binary cannot be produced from
  a Linux host — no Apple SDK, no linker — so this guest is the local x86_64
  alternative to the macOS CI jobs; both the x86_64 and arm64 releases are
  covered by CI. The Endpoint Security *runtime* still needs root and an
  interactive TCC approval (see [Build](../build.md)).
- Auto-updates fully locked (system and user plists: check/download/install/
  critical all false). Re-verify the locks after any update attempt — a
  Sequoia VM got force-upgraded to Tahoe despite the locks.

### arm64 is CI-only

There is no usable arm64 macOS QEMU guest on this x86_64 host:

- QEMU's [`vmapple`](https://www.qemu.org/docs/master/system/arm/vmapple.html)
  machine needs an Apple Silicon host and a macOS 12 Virtualization.framework
  guest; newer guests are unsupported, and the QEMU build here does not include
  the machine.
- [`cylance/macos-arm64-emulation`](https://github.com/cylance/macos-arm64-emulation)
  boots an arm64e kernel/ramdisk on x86_64 (QEMU 5.1.0), not a full macOS
  userland or a toolchain.
- UTM, Tart, VirtualBuddy and Anka need Apple Silicon for macOS guests;
  [UTM](https://getutm.app/) and [Tart](https://github.com/openai/tart) use
  Virtualization.framework. OSX-KVM and Docker-OSX are x86_64-only.

The `macos-latest` CI job builds, lints and tests the arm64 target natively;
this x86_64 guest remains the local x86_64 test box.

## The settings that are load-bearing

### SMC device must stay disabled

QEMU's `isa-applesmc` only implements `APPLESMC_READ_CMD`; macOS ≥ 15.4
enumerates SMC keys by index, which panics on Tahoe (`kSMCBadCommand 0x82`).
Do **not** add `-device isa-applesmc`: the `VirtualSMC.kext` already enabled
in OSX-KVM's OpenCore supplies the OSK keys. The fallback symptom of a
re-added device is boot stuck at `AppleKeyStore operation failed`.

### CPU model

The working model on an AMD Ryzen host is **`Skylake-Client,-hle,-rtm`**
(the trailing flags matter on hosts without those features). `Haswell-noTSX`
panics or hangs. Keep `boot-args = keepsyms=1 -v debug=0x100` in
`OpenCore/config.plist` so panic text stays on screen instead of
auto-rebooting — that is deliberate for a dev VM.

### Unattended boot

Three things are needed for the VM to boot macOS on its own; the first two
look like the same symptom, which is why all three are written down:

1. **Installer media detached** from the boot script (`BaseSystem.img` was
   still attached on `sata.3`, so a second bootable volume showed up). The
   two lines are commented out in `sigmacatch-macos-boot.sh`; re-attach them
   to reinstall.
2. **`Misc/Boot/ShowPicker=false`** in `OpenCore/config.plist` — necessary
   but not sufficient.
3. **Matching OVMF varstore size** — the real root cause. OSX-KVM's own boot
   scripts pair `OVMF_CODE_4M.fd` (3 653 632 bytes) with a 128 KiB
   `OVMF_VARS-*.fd`; a 4 MiB firmware needs a **540 672-byte** varstore
   (3 653 632 + 540 672 = 4 MiB). With a mismatch the firmware rejects the
   store and reinitialises NVRAM on **every** boot, so OpenCore can never
   keep its default entry and every cold start falls back to the picker.

   The varstore is kept **outside** the git clone so QEMU's writes never
   dirty OSX-KVM:

   ```sh
   qemu-img convert -O raw /usr/share/edk2/ovmf/OVMF_VARS_4M.qcow2 \
     ovmf-vars-4m.fd     # 540672 bytes, outside the git clone
   # boot script: -drive if=pflash,format=raw,file="$OVMF_VARS"
   ```

   Then select **MacOS** once in the picker and press **Ctrl+Enter** (with
   `Misc/Security/AllowSetDefault=true`) to store it as the default. After
   that, cold starts go straight to the Apple logo.

   Rollback to a virgin NVRAM: delete `ovmf-vars-4m.fd`, re-run the
   `qemu-img convert` above; the next boot needs one manual selection again.
   On the guest side, `sudo nvram -d <var>` removes a variable.

## Rebuilding the EFI image

Edit `OpenCore/config.plist` (python `plistlib`), then rebuild without sudo:

```sh
cd OpenCore && ./opencore-image-ng.sh --cfg config.plist --img OpenCore.qcow2.new
```

The libguestfs direct backend works as a user; only the script's trailing
`sudo rm` cleanup fails (cosmetic).

## Resetting

The VM is not a libvirt domain, so there is no `virsh` snapshot/reset.
Clean-room rollback is the qcow2 internal snapshot: stop QEMU, then
`qemu-img snapshot -a clean-install`.
