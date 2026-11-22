# Linux dev VM (AlmaLinux 10)

The QEMU/KVM AlmaLinux 10 VM used to validate the Linux collectors: a libvirt
domain named `almalinux10` (DHCP hostname `sigmacatch-linux`) on the Linux
host. It is the test box for the `auditd`, `builtin`, `sysmon` and `ebpf`
features, the Linux analogue of the [Windows dev VM](../windows/vm.md).

## What is on it

- **AlmaLinux 10**, reached over SSH. Its DHCP address can change between
  boots; resolve it from the lease table rather than hard-coding it.
- `/usr/local/bin/sigmacatch-linux` — the deployed collector binary, plus
  `/usr/local/bin/sc_start.sh` and `sc_stop.sh` to run and stop it.
- `~/sigma` — a full SigmaHQ clone (not shallow: the collector fetches with
  complete history and builds its pushes on top), `~/config.yaml`,
  `~/AtomicRedTeam` and `~/logs`.
- `git` and an SSH key for git auth to the `frack113/sigma` fork.

The VM has **no Rust toolchain**: no `cargo`, `rustc`, `rustfmt` or `clippy`.
Build and lint on the host, upload the binaries, and use the VM only to check
runtime behaviour. `cargo fmt` / `clippy` / `test` and the `xwin` build stay on
the host; the VM answers the question the host cannot — do real auditd events
actually match?

## Discovering and reaching it

The helper scripts for this lab are local to the test environment, **not** in
this repository; a fresh clone does not have them. The underlying steps are:

```sh
# start the VM if needed, then read the real IP from libvirt
virsh -c qemu:///system list --all
virsh -c qemu:///system net-dhcp-leases default
virsh -c qemu:///system domiflist almalinux10   # match its MAC to the lease
```

The libvirt domain name and the DHCP hostname differ, and `virsh` without
`-c qemu:///system` lists nothing (the user session URI is `qemu:///session`).
`virsh domstate` is localised — check `virsh list --name` instead. Over SSH,
`sudo` asks for the password: supply it interactively or through your own
secret manager, and never store it in the repository. An exported `SSHPASS`
is empty in the remote shell.

## Clean-room reset

Reusing `~/sigma` accumulates `sigmacatch/*` branches, untracked upstream files
from earlier fetches and locally generated regression data. Reset from scratch
instead of repairing: stop the collector, wipe `~/sigma`, re-clone with full
history, push a known `config.yaml` and verify with a read-only
`sigmacatch --dry-run --offline -v`. There is then nothing to restore after a
run.

For a validation run, force `contrib: false` in the pushed config: the log then
reads `No-contrib mode: push disabled — commits will be local only`, so nothing
reaches the remote fork. Do **not** force `offline: true` as well — offline
skips the `fetch` that makes the run representative. Local commits and the
`sigmacatch/<date>` branch are harmless on a fresh clone; the next reset wipes
them.

## A validation run

A validation run goes like this:

1. Record the baseline in `~/sigma` (`git log --oneline -1`, current branch,
   `git status`), so any side effect can be undone.
2. Build on the host:
   `cargo build --release -p sigmacatch --no-default-features --features auditd,builtin --bin sigmacatch --bin regressiondata-check`.
3. Upload both binaries to the VM as `sigmacatch-new` and
   `regressiondata-check-new`.
4. Validate regression data against the VM's **own** clone:
   `./regressiondata-check-new --path ~/sigma` — this differs from the host's
   clone. To attribute a mismatch to a dependency change, build the same tool
   against the older revision and compare the two outputs.
5. Check rule loading read-only: `./sigmacatch-new --dry-run --offline -v`.
   Watch the `Loaded ...` line for `rules_parse_failed` and
   `rules_timeframe_ignored`.
6. Install the binary as `/usr/local/bin/sigmacatch-linux`, start a live
   capture with `sc_start.sh`, wait, then read `~/logs/sc_run.log` for the same
   counters. Stop with `sc_stop.sh`.
7. Restore: reset `~/sigma` to the baseline commit, force `master` back onto it
   and move `HEAD` with `git symbolic-ref HEAD refs/heads/master` (a plain
   `git checkout master` fails when untracked files block it). Confirm with
   `git ls-remote --heads origin 'sigmacatch/*'` that no push escaped.

Never run `git clean -fd` on this clone: the untracked Windows `.evtx`
regression entries are pre-existing data, not collector output.

## Regenerating the committed auditd fixture

The `passwd -S` sample in `sigmacatch/tests/fixtures/sigma/` was captured on
this VM. To reproduce it, run
`sigmacatch --no-default-features --features auditd,builtin` with a filter
config pointing at the rule, execute `passwd -S`, then stop gracefully with
`touch .sigmacatch.stop`. Full details are in that directory's `README.md`.

## Operational pitfalls

- Before any `lvremove` on the VM, check `/proc/cmdline` for `rd.lvm.lv=VG/LV`:
  deleting a boot-referenced logical volume drops the guest into a dracut
  emergency shell, whose shell has no `lvcreate` to repair it. Resize the disk
  with `qemu-img resize` or recreate the LV under the **same name** instead.
- Do not disable a feature to dodge an environment constraint. Install what is
  missing rather than neutralising the code under test.
- If a step fails, stop and report rather than working around it.
