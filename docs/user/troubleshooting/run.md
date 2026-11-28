# Run and git failures

Startup, clone/push and config problems — the failures shared by every platform. Windows and Linux capture sources have their own pages: [Windows](windows.md), [Linux](linux.md).

## First run exits 1

**Symptom:** the run stops right after writing `config.yaml`.

**Cause:** the generated file carries the placeholder `git.author:
sigmacatch` and an empty `email` — both are rejected.

**Fix:** set a real `git.author` and a non-empty `git.email` (any value
containing `@`), then re-run. Or run
[offline](../config.md#git) — no author/email is required.

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

## A rule is skipped for an unresolved `|expand` placeholder

**Symptom:** startup logs `Skipping rule '<title>' (<path>): unresolved
|expand placeholder, and sigmacatch ships no placeholder variables`.

**Cause:** the rule matches on a Sigma placeholder (`%name%` with the
`|expand` modifier) and no pipeline defines that variable. Left to
rsigma-eval, the placeholder would be filled from the event at match time —
a missing field becomes `""`, `contains ""` matches every value, and a `not
filter` then hides every hit. The Sigma specification requires a tool that
cannot resolve a placeholder to reject the rule, so the rule is skipped
instead of silently mis-matching; the rest of the rule set loads normally.

**Fix:** nothing on the sigmacatch side. SigmaHQ's `rules-placeholder`
bucket is written this way on purpose: those rules need a pipeline that
defines their variables (`vars:` on a `value_placeholders` transformation).

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
