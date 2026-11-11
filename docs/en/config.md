# Configuration

`sigmacatch` reads its settings from a single `config.yaml` in the working
directory (CWD). On the first run a file is created with placeholder defaults
and the run stops (`exit 1`) until you edit it. Every section and field is
optional in the file — a missing section or field falls back to its default.
Unknown fields are rejected.

## Full reference

```yaml
git:
  author: "sigmacatch"          # PLACEHOLDER — set your GitHub username before the next run
  email: ""                     # required (any non-empty value containing @)
  fork_repo_url: ""             # SSH URL of your fork; default git@github.com:<author>/sigma.git
  ssh_key_path: ""              # absolute path to an SSH private key (empty = SSH agent)
  sigma_repo_url: "git@github.com:SigmaHQ/sigma.git"   # SSH only
  sigma_repo_path: "sigma"      # local clone path; relative paths resolve against the config dir
  offline: false                # true = zero git operations (no pull/clone/commit/push)
  contrib: false                # true = push commits to your remote fork
  working_branch: ""            # optional working branch; default sigmacatch/<YYYYMMDD>
  shallow_clone: true           # depth=1 initial clone, unshallow before push (default true)
  sparse_checkout: true         # cone-mode sparse checkout: rules/, rules-emerging-threats/, regression_data/ (default true)
  clone_timeout_secs: 600       # overall clone timeout (seconds)
  fetch_timeout_secs: 300       # fetch/pull timeout (seconds)
  max_retries: 3                # max retry attempts for transient failures
log:
  level_file: debug             # debug | info | warn | error
filter:
  product: windows              # explicit choice; omit for the collector default (empty = no filter)
  # min_status: stable          # keep only rules with status >= this (values below)
  # min_level: critical         # keep only rules with level >= this (values below)
  author: ""                    # keep only rules authored by this author (empty = no filter)
  max_rule_size: 1048576        # bytes; range 1024..10MB
regression:
  max_failed_cycles: 3          # block a rule after N consecutive failure cycles
  add_json_output: false        # also write an auxiliary <rule_id>.json for EVTX/log data
engine:
  cross_rule_ac: false          # rsigma-eval cross-rule Aho-Corasick prefilter (off: slower on the SigmaHQ ruleset)
  bloom_prefilter: false        # rsigma-eval bloom prefilter for substring matchers (off: slower on the SigmaHQ ruleset)
hir_cache: ""                   # path to persistent HIR cache file (warm-start engine; empty = compile every run)
stop_file: ".sigmacatch.stop"   # create this file to gracefully stop a continuous (-r 0) run
```

## git

| Key | Default | Description |
|---|---|---|
| `author` | `sigmacatch` | GitHub username. The placeholder `sigmacatch` is rejected; must be alphanumeric + hyphens. Required unless `offline: true`. |
| `email` | `""` | Commit email. Must contain `@`. Required unless `offline: true`. |
| `fork_repo_url` | `git@github.com:<author>/sigma.git` | SSH URL of your fork: push target and source of pending `sigmacatch/*` branches. Must be an SSH URL. |
| `ssh_key_path` | *(unset)* | Absolute path to an SSH private key (ed25519). Empty = use the SSH agent. Must exist and be a file when a network op is active. `chmod 600` recommended. |
| `sigma_repo_url` | `git@github.com:SigmaHQ/sigma.git` | SigmaHQ repository to clone/fetch. SSH only — an `https://` URL is rejected at startup. |
| `sigma_repo_path` | `sigma` | Local clone path. Relative paths resolve against the config file's directory; must not be empty or contain `..`. |
| `offline` | `false` | Skip all git operations (no pull/clone/commit/push). On-disk files are used as-is (`.git` optional). **Neutralizes `contrib`** (forced to `false`). |
| `contrib` | `false` | Push commits to your remote fork. Neutralized by `offline: true`. |
| `working_branch` | *(unset)* | Working branch name. When empty, the default `sigmacatch/<YYYYMMDD>` branch is used. |
| `shallow_clone` | `true` | Initial clone uses depth=1 (fast); unshallow runs before push. Set `false` for full history. |
| `sparse_checkout` | `true` | Cone-mode sparse checkout: only `rules/`, `rules-emerging-threats/`, `regression_data/` materialize. Set `false` for full worktree. |
| `clone_timeout_secs` | `600` | Overall clone timeout in seconds. Must be >0 and ≤3600. |
| `fetch_timeout_secs` | `300` | Fetch/pull timeout in seconds. Must be >0 and ≤1800. |
| `max_retries` | `3` | Max retry attempts for transient network failures. Must be ≤10. |

## log

| Key | Default | Description |
|---|---|---|
| `level_file` | `debug` | File log level: `debug`, `info`, `warn`, `error`. |

## filter

All filters are optional; unset means no filtering.

| Key | Default | Description |
|---|---|---|
| `product` | collector product | SigmaHQ product to keep: `windows`, `linux`, or `macos` (reserved, no collector today). An explicit value always wins; when the key is absent, the collector chooses `windows` or `linux`. Empty = no product filter. |
| `min_status` | *(unset)* | Keep only rules whose status ranks at or above this: `unsupported` < `deprecated` < `experimental` < `test` < `stable`. |
| `min_level` | *(unset)* | Keep only rules whose level ranks at or above this: `informational` < `low` < `medium` < `high` < `critical`. |
| `author` | *(unset)* | Keep only rules authored by this author (normalized). |
| `max_rule_size` | `1048576` | Reject rules whose YAML exceeds this many bytes. Range 1024..10485760 (10MB). |

> On Linux, set `product: linux` or omit the key so the collector default applies. A
> generated `config.yaml` containing `product: windows` is an explicit value and is not
> overridden automatically.
>
> Setting `min_status` to `stable` or `min_level` to `high`/`critical` is very
> restrictive and logs a warning at startup.

## regression

| Key | Default | Description |
|---|---|---|
| `max_failed_cycles` | `3` | After N consecutive failed capture cycles a rule is blocked (logged, removed from the skip set, no more re-capture). Min 1. |
| `add_json_output` | `false` | For EVTX/log data, also write the auxiliary `<rule_id>.json` (raw event). eBPF already writes JSON/NDJSON as its primary data file. See [Output Format](output-format.md). |

## engine

| Key | Default | Description |
|---|---|---|
| `cross_rule_ac` | `false` | Enable rsigma-eval's cross-rule Aho-Corasick prefilter. |
| `bloom_prefilter` | `false` | Enable rsigma-eval's bloom (trigram) prefilter for substring matchers. |

Both prefilters are optional and never change which rules match, only how fast the engine builds and evaluates. They are off by default: on the SigmaHQ Windows ruleset they cost more engine build and evaluation time than they save. Turn them on to compare on your own workload.

## hir_cache

| Key | Default | Description |
|---|---|---|
| `hir_cache` | `""` | Path to a persistent HIR cache file. When set, the compiled detection engine is persisted after each rule change and warm-started on the next run, skipping rule recompilation. Empty = compile every run. Can also be set via `--hir-cache <PATH>` CLI flag. |

## stop_file

`stop_file` names a control file (default `.sigmacatch.stop`, relative to the
working directory). While the file exists, a continuous run (`-r 0`) performs a
graceful shutdown — drain, flush, commit — on the next poll, so a live run can
be ended without a hard kill. Remove the file to keep running.
