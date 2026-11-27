#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 sigmacatch contributors
#
# Dev-loop for the Windows kernel driver on the local QEMU dev VM
# (`sigmacatch-dev`, clone of the test VM): sync the driver sources,
# build with the exact CI settings, pull the artifact back.
#
# Usage: scripts/dev_win_build.sh
# Requires: virsh (qemu:///system), python3 + pywinrm (skill scripts).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="$HOME/.config/opencode/skills/heiter-test-vms-qemu/scripts"
WINRM="$SKILL/winrm_vm.py"
DEV_MAC="52:54:00:ea:59:6b"
REMOTE_BASE='C:\sigmacatch-dev\sigmacatch'

# The driver and protocol sources, relative to driver/windows/.
SRC_DIR="$REPO_ROOT/driver/windows"
FILES="Cargo.toml build.rs src/lib.rs src/flt.rs protocol/Cargo.toml protocol/src/lib.rs protocol/src/protocol.rs"

vm_ip="${SIGMACATCH_DEV_IP:-}"
if [ -z "$vm_ip" ]; then
  vm_ip=$(virsh -c qemu:///system net-dhcp-leases default | grep -F "$DEV_MAC" | head -1 | awk '{print $5}' | cut -d/ -f1)
fi
if [ -z "$vm_ip" ]; then
  echo "dev VM has no DHCP lease (MAC $DEV_MAC) — start it: virsh -c qemu:///system start sigmacatch-dev" >&2
  exit 1
fi
export WINRM_URL="http://${vm_ip}:5985/wsman"
echo "dev VM: ${vm_ip}"

# Fresh markers make the poll deterministic even after a previous run.
python3 "$WINRM" run "cmd /c del /q C:\sigmacatch-dev-build.done C:\sigmacatch-dev-build.log 2>nul" >/dev/null

# The directories must exist before the streamed puts.
python3 "$WINRM" run "cmd /c if not exist ${REMOTE_BASE}\\driver\\src mkdir ${REMOTE_BASE}\\driver\\src & if not exist ${REMOTE_BASE}\\driver\\protocol\\src mkdir ${REMOTE_BASE}\\driver\\protocol\\src" >/dev/null

for f in $FILES; do
  python3 "$WINRM" put "$SRC_DIR/$f" "${REMOTE_BASE}\\driver\\${f//\//\\}" >/dev/null
done
echo "sources synced"

# Recreate + run the build task (stored credentials, no interactive session).
python3 "$WINRM" run "cmd /c schtasks /create /tn sigmacatch-dev-build /tr \"powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\sigmacatch-dev-build.ps1\" /sc once /st 00:00 /ru frack113 /rp azerty /f & schtasks /run /tn sigmacatch-dev-build" >/dev/null

done_found=""
for _ in $(seq 1 90); do
  sleep 10
  if python3 "$WINRM" run "cmd /c if exist C:\sigmacatch-dev-build.done echo DONE" 2>/dev/null | grep -q DONE; then
    done_found=1
    break
  fi
done
if [ -z "$done_found" ]; then
  echo "build did not finish in 15 min — check C:\\sigmacatch-dev-build.log on the VM" >&2
  exit 2
fi

python3 "$WINRM" run "cmd /c type C:\sigmacatch-dev-build.log" | grep -E 'cargo|rustc|Compiling sigmacatch|Finished|artifact' | tail -n 6
python3 "$WINRM" run "cmd /c type C:\sigmacatch-dev-build.log" | grep -q 'cargo exit=0' || {
  echo "build FAILED — full log: C:\\sigmacatch-dev-build.log on ${vm_ip}" >&2
  exit 3
}

python3 "$WINRM" get 'C:\sigmacatch-dev\sigmacatch\driver\target\x86_64-pc-windows-msvc\release\sigmacatch_driver.dll' \
  "$REPO_ROOT/target/sigmacatch-dev/sigmacatch_driver.dll" >/dev/null
echo "OK -> target/sigmacatch-dev/sigmacatch_driver.dll (rename to .sys for the service)"
