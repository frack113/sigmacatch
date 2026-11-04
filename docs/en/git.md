# Git Workflow

All git operations go through **grit-lib** (pure Rust) via the `repo` module of the `sigmacatch` package — never a `git` binary on PATH. The invariants below are non-negotiable.

## Invariants

### Shallow clone by default, with deferred unshallow (configurable)

`fetch_options_for_branches()` (`plumbing/fetch.rs`) uses per-branch refspecs (never `+refs/heads/*`, except the namespace glob `+refs/heads/sigmacatch/*`).

By default (`git.shallow_clone: true`), the initial clone uses `depth=1` (only the tip commit) for a fast first run. Before any push, the repository is automatically unshallowed (full history fetched) in the background. This avoids the push ancestry issue while keeping first-run fast.

Set `git.shallow_clone: false` in `config.yaml` to disable shallow clone and fetch full history immediately.

### SSH-only transport

Every clone, fetch and push runs over SSH through the system `ssh` binary. There
is no HTTP transport and no GitHub token: authentication comes from the SSH
agent, or from `git.ssh_key_path` wired into `~/.ssh/config`. grit-lib negotiates
protocol v2 over SSH, so the narrow refspecs become `ref-prefix` lines and only
the requested branches are advertised.

### Retry with exponential backoff

All network operations (clone, fetch, pull) retry on transient failures with exponential backoff (5s → 10s → 20s → 40s → 60s max). Configurable via `git.max_retries` (default 3) and the timeout fields (`clone_timeout_secs`, `fetch_timeout_secs`).

### Sparse checkout (cone mode)

When `git.sparse_checkout: true` (default), a cone-mode sparse checkout is configured after clone, materializing only `rules/`, `rules-emerging-threats/`, `regression_data/`. This avoids writing the full Sigma repo (~500MB+ docs/tools/tests) to disk.

### Working branch

The working branch name is configurable via `git.working_branch` in `config.yaml` or the
`--branch` CLI flag. When absent or empty, the default `sigmacatch/<YYYYMMDD>` (today's date)
is used.

Based on the remote ref if present (else HEAD) to keep fast-forward. The narrow pull does not update `refs/remotes/origin/sigmacatch/<date>` → fetch of the `sigmacatch/*` namespace (glob, single fetch, best-effort: network failure = `warn!` — SSH key or `ssh` binary unavailable — and continue with the worktree only) before `create_branch`. Branch missing from the fork → no-op.

**Working branch outside `sigmacatch/*` (fixes #95)**: If the working branch name doesn't match the `sigmacatch/*` pattern (e.g., `feature/my-test`), it is now explicitly fetched from the fork before `create_branch`, so the local branch is based on the fork's tip instead of local `HEAD`/`master`. This ensures same-day re-runs or custom branch names stay in sync with the remote.

**Master-switch skip (same-day re-run)**: `is_head_on_working_branch()` inspects the HEAD target (`symbolic_ref_target`) before `switch_to_tracking_branch()`. If HEAD is already on `refs/heads/sigmacatch/<date>`, the master → working-branch round-trip is skipped (avoids a needless round-trip, fixes Windows without ssh). A same-day re-run therefore stays on the working branch directly.

### Multi-branch skip set (pending PRs)

`pending_regression_rule_ids()` (`SigmaRepo`) scans the trees of ALL remote `sigmacatch/*` branches (never a checkout — `list_refs` + in-RAM walk of `regression_data/`, ids extracted from `<uuid>.<ext>` filenames). Union with the worktree → a fresh VM does not re-capture data from a still-open PR of another day; the new PR diff stays based on main (previous PR data never included). `.evtx` blobs are validated at scan time (size ≤ 64 MiB then a full `parse_evtx_bytes` re-parse); other extensions (`.log`) are accepted without structural validation at scan time — deep validation is repeated at write time. An unreadable, empty or corrupt `.evtx` blob excludes the rule from the skip set (self-healing, bounded RAM). Offline mode: the scan is skipped entirely (no local refs read) — the skip set is built from the on-disk worktree only.

### Remote working-branch guard

`check_remote_working_branch()` (startup) validates the same-day branch (readable commit, ≥ 1 parent, tree with `rules/`) else actionable bail. Absent → `Ok` (fresh day).

### Worktree = exact mirror of the commit

`checkout_main_branch` (`plumbing/checkout.rs`) deletes any file absent from the tree (`.git` never touched) → deterministic skip set at startup (leftovers from a failed push do not pollute). **Offline mode**: all git operations are no-ops (`init`, working branch, checkout, commit, push) — on-disk files are left untouched, a `.git` is not even required (extracted sigma zip), and local edits/deletions made for testing survive the restart.

### Complete repo = resolvable HEAD

`is_repo_complete` accepts a repo as soon as HEAD resolves to a readable commit in the ODB (no `objects/pack`/`packed-refs` required); unreadable repo → deleted + re-cloned (online only — offline uses the repo as-is without any check).

### Non-destructive pull failure

`pull()` (`plumbing/fetch.rs`) now returns a clear `Err` with context (`with_context`) if `.git/config` reading or the SSH fetch fails — the repo is left **as-is** (no `remove_dir_all`, no re-clone). The error includes the repo path, the exact cause (e.g. missing config, invalid SSH key), and suggests offline mode as an alternative. At startup, `is_repo_complete` keeps its existing behavior (unreadable repo → deleted + re-cloned).

### Pack after each clone/fetch

`pack_loose_objects()` (`plumbing/pack.rs`) consolidates the loose objects written by local commits into a V2 pack (zlib, no delta, rayon). Remote fetches produce none: grit-lib installs the received pack directly under `objects/pack/` (V2 index + reverse index `.rev`) — the function targets objects from commits between runs and returns quickly when there are none.

### Clone phase timings

`git_clone`/`git_clone_shallow` log phase timings (`connect`, `Fetch done`, `Checkout done`, `Clone finished`): a slow first run is diagnosable from the log, no re-instrumentation needed.

## Git configuration

`git.contrib` is opt-in: `true` (or `--contrib`) enables pushing to the fork; `false` (default) = local commits only, no push. `needs_network()` = `!offline || contrib` — SSH is used only when a network operation (pull or push) is active. **`offline: true` neutralizes `contrib`** (forced to `false`, `warn!`): no push will ever be attempted in offline mode.

**SSH only**: clone/fetch read `git.sigma_repo_url` (default `git@github.com:SigmaHQ/sigma.git`); push and the pending-`sigmacatch/*` fetch use `git.fork_repo_url` (default `git@github.com:<author>/sigma.git`). Both must be SSH URLs — an `https://` value is rejected at startup with an actionable error. `ensure_ssh_host_config()` writes the `IdentityFile`/`UserKnownHostsFile` directives into `~/.ssh/config` before transport ops (idempotent, **atomic write** tmp + rename to avoid a partial file; skipped in offline mode); on Windows, `ssh` is resolved via Windows OpenSSH / Git for Windows and executed directly (`SshMode::Program`). When `ssh_key_path` is set, every regression commit is signed with pure-Rust ed25519 (`ssh-key`) — the `gpgsig` header reproduces `git commit -S` (the SSH signature format is enabled via the git config `gpg.format = ssh`) → GitHub shows "Verified". **SSH pull failure = abort** (no fallback): when the `ssh` binary is missing (Windows without OpenSSH) or the key is not accepted by GitHub, the run stops with the exact cause.

The full key reference lives in the Quick start section of the [README](https://github.com/frack113/sigmacatch/blob/main/README.md#quick-start).
