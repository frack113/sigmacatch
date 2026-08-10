# Git Workflow

All git operations go through **grit-lib** (pure Rust) via the `sigmacatch-repo` crate — never a `git` binary on PATH. The invariants below are non-negotiable.

## Invariants

### Full-history, never shallow

`fetch_options_for_branches()` (`plumbing/fetch.rs`) never sets `depth`, and uses per-branch refspecs (never `+refs/heads/*`, except the namespace glob `+refs/heads/sigmacatch/*`).

A `depth=1` would leave the ODB without the ancestors of the tips → broken push after the remote advances (`object not found: <parent oid>`).

### HTTP fetch protocol v2

`AuthHttpClient` (`transport.rs`) sends `version=2` → capability-only advertisement + `ls-refs` scoped to the ref-prefixes derived from the narrow refspecs (in v0/v1 GitHub serves ALL remote refs, huge on the big Sigma repo). The `sigmacatch/*` glob yields the ref-prefix `refs/heads/sigmacatch/` (truncated at the first `*`). SSH already uses v2.

### Working branch `sigmacatch/<date>`

Based on the remote ref if present (else HEAD) to keep fast-forward. The narrow pull does not update `refs/remotes/origin/sigmacatch/<date>` → fetch of the `sigmacatch/*` namespace (glob, single fetch, best-effort: network failure = `warn!` with a categorized cause — SSH key/ssh binary vs missing token vs network — and continue with the worktree only) before `create_branch`. Branch missing from the fork → no-op.

**Master-switch skip (same-day re-run)**: `is_head_on_working_branch()` inspects the HEAD target (`symbolic_ref_target`) before `switch_to_tracking_branch()`. If HEAD is already on `refs/heads/sigmacatch/<date>`, the master → working-branch round-trip is skipped (avoids a needless round-trip, fixes Windows without ssh). A same-day re-run therefore stays on the working branch directly.

### Multi-branch skip set (pending PRs)

`pending_regression_rule_ids()` (`SigmaRepo`) scans the trees of ALL remote `sigmacatch/*` branches (never a checkout — `list_refs` + in-RAM walk of `regression_data/`, ids extracted from `<uuid>.<ext>` filenames). Union with the worktree → a fresh VM does not re-capture data from a still-open PR of another day; the new PR diff stays based on main (previous PR data never included). `<uuid>.evtx` blobs are validated (parse ≥ 1 record): an empty/corrupt EVTX — **or one > 64 MiB** (`MAX_EVTX_BLOB_SIZE`) — excludes the rule from the skip set (self-healing of empty commits, bounded RAM). Offline = best-effort (already-fetched refs only).

### Remote working-branch guard

`check_remote_working_branch()` (startup) validates the same-day branch (readable commit, ≥ 1 parent, tree with `rules/`) else actionable bail. Absent → `Ok` (fresh day).

### Worktree = exact mirror of the commit

`checkout_main_branch` (`plumbing/checkout.rs`) deletes any file absent from the tree (`.git` never touched) → deterministic skip set at startup (leftovers from a failed push do not pollute).

### Complete grit clone = loose objects

`is_repo_complete` accepts a repo as soon as HEAD resolves to a readable commit in the ODB (no `objects/pack`/`packed-refs` required); unreadable repo → deleted + re-cloned.

### Pack after each clone/fetch

`pack_loose_objects()` (`plumbing/pack.rs`) consolidates the ~131K loose files (~650 MB) into a V2 pack (zlib, no delta, rayon) → `.git/` ~218 MB (3x), clean `fsck`, ODB readable loose or pack.

## Git configuration

`git.contrib` is opt-in: `true` (or `--contrib`) enables pushing to the fork; `false` (default) = local commits only, no push. `needs_network()` = `!offline || contrib` — a GitHub token is required only when a network operation (pull or push) is active.

**SSH transport**: `git.transport: ssh` + `ssh_key_path` (ed25519 key). `ensure_ssh_host_config()` writes the `IdentityFile`/`UserKnownHostsFile` directives into `~/.ssh/config` before transport ops (idempotent, **atomic write** tmp + rename to avoid a partial file); on Windows, `ssh` is resolved via Windows OpenSSH / Git for Windows and executed directly (`SshCommand::Program`). When `ssh_key_path` is set, every regression commit is signed with pure-Rust ed25519 (`ssh-key`, `gpgsig` header like `git commit -S` + `gpg.format = ssh`) → GitHub shows "Verified". **SSH pull failure = abort** (no HTTPS fallback): if the `ssh` binary is missing (Windows without Git for Windows) or the key is invalid, the error message says so explicitly and points to `transport: http` — retry is HTTP-only when the config uses HTTP.

See `config.yaml` and the general invariants in [`architecture-reference.md`](architecture-reference.md) for the full configuration.
