# SigmaHQ Workflow

How sigmacatch interacts with the SigmaHQ repository: clone, working branch,
per-rule commits, push to your fork, and the skip set that keeps a fresh VM
from re-capturing data that is already on a pending PR. All git operations
run through **grit-lib** (pure Rust) in the `repo` module — never a `git`
binary on PATH. The configuration keys for every step live in
[config.md](config.md#git).

## Transport: SSH only

Every clone, fetch and push runs over SSH through the system `ssh` binary.
There is no HTTP transport and no GitHub token: authentication comes from
the SSH agent, or from `git.ssh_key_path` wired into `~/.ssh/config`
(`IdentityFile`/`UserKnownHostsFile` directives are written there
idempotently, atomic tmp + rename, before any transport op; skipped in
offline mode). On Windows, `ssh` is resolved via Windows OpenSSH / Git for
Windows and executed directly.

- Clone/fetch read `git.sigma_repo_url` (default
  `git@github.com:SigmaHQ/sigma.git`).
- Push and the pending-`sigmacatch/*` fetch use `git.fork_repo_url` (default
  `git@github.com:<author>/sigma.git`).
- Both must be SSH URLs — an `https://` value is rejected at startup with an
  actionable error.
- A missing `ssh` binary (Windows without OpenSSH) or a key not accepted by
  GitHub **aborts the run** with the exact cause — there is no fallback.

When `git.ssh_key_path` is set, every regression commit is signed with
pure-Rust ed25519 (`ssh-key`); the `gpgsig` header reproduces
`git commit -S` (the SSH signature format is enabled via the git config
`gpg.format = ssh`), so GitHub shows "Verified".

## Clone

- **Shallow by default** (`git.shallow_clone: true`): the initial clone uses
  `depth=1` for a fast first run. Before any push, the repository is
  unshallowed (full history) in the background, so the push has the
  ancestors it needs.
- **Sparse checkout** (`git.sparse_checkout: true`): cone mode materializes
  only `rules/`, `rules-emerging-threats/`, `regression_data/` — the rest of
  the Sigma repo (docs/tools/tests, ~500 MB+) is never written to disk.
- **Retries with exponential backoff**: clone, fetch and pull retry on
  transient failures (5s → 10s → 20s → 40s → 60s max), bounded by
  `git.max_retries` and the `clone_timeout_secs` / `fetch_timeout_secs`
  fields.
- **Pack after local commits**: loose objects written by local commits are
  consolidated into a V2 pack (zlib, no delta, rayon). Remote fetches need
  none — grit-lib installs the received packs directly.
- **Diagnosable timings**: clone logs phase timings (`connect`,
  `Fetch done`, `Checkout done`, `Clone finished`), so a slow first run is
  diagnosable from the log.
- **Non-destructive pull failure**: a failed pull returns a clear error
  (repo path, exact cause, offline mode suggested) and leaves the repo
  **as-is** — no delete, no re-clone.
- A repo is accepted as complete as soon as HEAD resolves to a readable
  commit; an unreadable repo is deleted and re-cloned (online only —
  offline uses the repo as-is without any check).

## Working branch

The working branch name comes from `git.working_branch` in `config.yaml` or
the `--branch` CLI flag; when absent, the default `sigmacatch/<YYYYMMDD>`
(today's date) is used.

- The branch is based on the remote ref when present (else HEAD) to keep
  fast-forward.
- A branch outside the `sigmacatch/*` namespace (e.g. `feature/my-test`) is
  explicitly fetched from the fork before creation, so same-day re-runs and
  custom names stay in sync with the remote.
- A same-day re-run that is already on `sigmacatch/<date>` skips the
  master → working-branch round-trip and stays on the branch directly.
- At startup, the same-day remote branch is validated (readable commit,
  ≥ 1 parent, tree with `rules/`); a missing branch is fine (fresh day).

The worktree is an **exact mirror of the commit**: files absent from the
tree are deleted at checkout (`.git` never touched), so leftovers from a
failed push do not pollute the skip set at startup.

## Commits and push

- **One commit per captured rule**: `🧪 test: add regression data for rule
  {rule_id}` — the data files plus the rule YAML annotated with its
  `regression_tests_path` (see
  [regression-data.md](regression-data.md#source-rule-annotation)).
- **Push is opt-in** (`git.contrib: true` or `--contrib`): without it,
  commits stay local. `offline: true` neutralizes `contrib` (forced to
  `false`) — no push is ever attempted offline.
- A commit/push failure rolls the local branch back to the pre-batch tip.

## Skip set: pending PRs

The skip set (see [architecture.md](architecture.md#design-notes)) is built
from the worktree **plus** the trees of all remote `sigmacatch/*` branches —
read via `list_refs` + an in-RAM walk of `regression_data/`, never a
checkout. Ids are extracted from `<uuid>.<ext>` filenames. Consequences:

- A fresh VM does not re-capture data that is already on a still-open PR of
  another day.
- The new PR diff stays based on main — previous PR data is never included.
- `.evtx` blobs are validated at scan time (size ≤ 64 MiB then a full
  re-parse); `.log` files are accepted without structural validation at scan
  time (deep validation repeats at write time). An unreadable, empty or
  corrupt `.evtx` blob excludes the rule from the skip set (self-healing,
  bounded RAM).
- Offline mode: the scan is skipped entirely — the skip set is built from
  the on-disk worktree only.

## Offline mode

`git.offline: true` makes every git operation a no-op (`init`, working
branch, checkout, commit, push): on-disk files are used as-is, a `.git` is
not even required (an extracted sigma zip works), and local edits made for
testing survive a restart. `contrib` is neutralized and no network is
touched.
