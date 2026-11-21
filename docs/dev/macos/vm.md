# macOS dev VM

The QEMU/KVM macOS VM used to validate the macOS collector: a Tahoe guest
under OpenCore on the Linux host, launched directly by a boot script (not a
libvirt domain). It is the test box for the `macos` feature, the macOS
analogue of the [Windows dev VM](../windows/vm.md).

## What is on it

- **macOS Tahoe 26.7.3** (25G342), installed fresh from its own BaseSystem
  (OSX-KVM `fetch-macOS-v2.py --shortname tahoe` + `dmg2img`). Installer
  language French, keyboard AZERTY — set the layout at install time, a
  QWERTY guest turns a typed `azerty` password into `qwerty`.
- Disk: `~/Games/Qemu/qcow2/macos.qcow2` (128 GiB), with a qcow2 internal
  snapshot **`clean-install`** taken after provisioning (VM stopped,
  `qemu-img snapshot -c`).
- Boot script: `~/Games/Qemu/OSX-KVM/sigmacatch-macos-boot.sh` (8 GiB RAM,
  8 vCPU, monitor on `unix:/tmp/opencode/macos-monitor.sock`, SSH forward
  `tcp/2222 → 22`).
- Guest account `frack113` / `azerty`, SSH key `~/.ssh/id_sigmacatch`
  installed in `authorized_keys`.
- Auto-updates fully locked (system and user plists: check/download/install/
  critical all false). Re-verify the locks after any update attempt — a
  Sequoia VM got force-upgraded to Tahoe despite the locks.

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
     ~/Games/Qemu/ovmf-vars-4m.fd     # 540672 bytes
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
