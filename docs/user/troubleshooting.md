# Troubleshooting

Symptom → cause → fix, for the failures a run actually hits. The binary
reports each of these itself — the log line quotes the exact cause.

## First run exits 1

**Symptom:** the run stops right after writing `config.yaml`.

**Cause:** the generated file carries the placeholder `git.author:
sigmacatch` and an empty `email` — both are rejected.

**Fix:** set a real `git.author` and a non-empty `git.email` (any value
containing `@`), then re-run. Or run
[offline](config.md#git) — no author/email is required.

## `https://` URL rejected

**Symptom:** startup aborts because `sigma_repo_url` or `fork_repo_url` is
an `https://` value.

**Cause:** transport is SSH only — there is no HTTP support and no GitHub
token.

**Fix:** use the SSH form `git@github.com:<owner>/<repo>.git`.

## SSH failure

**Symptom:** the run aborts with the exact cause; there is no fallback
transport.

- The `ssh` binary is missing (Windows without OpenSSH / Git for Windows).
- The key is not accepted by GitHub (wrong `git.ssh_key_path`, key not
  registered for the account, file permissions).

**Fix:** install OpenSSH / Git for Windows; point `git.ssh_key_path` at an
ed25519 key with `chmod 600`, or leave it empty to use the SSH agent.

## No capture source (Linux)

**Symptom:** startup bail when no compiled input has a source available.

**Cause:** each Linux collector is guarded by its source — the auditd
collector needs `/var/log/audit/audit.log`, the builtin syslog collector
needs one of the central/authpriv/cron files, the Sysmon tail needs
`sysmon`-tagged lines in central syslog.

**Fix:** start the source (auditd, syslog) or compile a feature whose
source exists. The eBPF collector additionally needs root or
`CAP_BPF`+`CAP_PERFMON` and a kernel with BTF — it refuses to start
otherwise. A build with both `ebpf` and `sysmon` falls back to the
Sysmon-for-Linux syslog tail when the probe fails to load; a build without
`sysmon` then runs auditd/syslog with no sysmon source.

## Slow first run

**Cause:** the initial clone.

**Check:** the clone logs its phase timings (`connect`, `Fetch done`,
`Checkout done`, `Clone finished`) — a slow run is diagnosable from the log.
The default clone is shallow (`depth=1`) and sparse; only set
`git.shallow_clone: false` / `git.sparse_checkout: false` if you need the
full history / worktree.

## Pull failure

**Symptom:** a clear error naming the repo path and the exact cause. The
repo is left **as-is** — no delete, no re-clone.

**Fix:** resolve the network/credential cause and re-run. The message
suggests offline mode when it applies.

## A rule is never captured

**Cause:** it is in the **skip set** — its `info.yml` plus valid data already
exist in the worktree, or its id is on a pending remote `sigmacatch/*`
branch (a still-open PR).

**Fix:** `--all-rules` disables the skip set for the run.

## A rule stops being re-captured after failures

**Cause:** after `regression.max_failed_cycles` (default 3) consecutive
failed capture cycles, the rule is blocked for the rest of the run —
retired from the engine so the cycle loop does not retry it.

**Next run:** if the committed data is still invalid (or absent), the rule
is back in scope and gets re-captured.

## Config is rejected or ignored

- **Unknown fields** are rejected at load — remove them.
- **`product: windows` on Linux** is an explicit value and is *not*
  overridden automatically — set `product: linux` or remove the key so the
  collector default applies.
- **Very restrictive filters** (`min_status: stable`, `min_level: high` or
  `critical`) load, but log a warning at startup.

## Windows: channel not found

**Symptom:** one `error!` per missing channel, then collection continues on
the remaining channels.

**Cause:** the channel does not exist on this machine (for example no
Sysmon channel without Sysmon installed). Expected on partial installs —
nothing to fix.

## Events dropped at render/parse

**Symptom:** `warn!` lines while events are being fetched.

**Cause:** the event was fetched from the channel but could not be rendered
or parsed — typically rotated out between query and render. The event is
dropped; the run continues.
