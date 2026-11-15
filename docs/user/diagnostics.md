# Diagnostic subcommands

`check-filter` and `list-rules` are subcommands of `sigmacatch`, **always
compiled** — no feature is required. An unknown or absent subcommand starts
the normal collection loop (or, with `--evtx`, the one-shot EVTX pass).

> **Prerequisite:** every subcommand loads `config.yaml` through
> `Config::load`, which runs **full** validation (including
> `git.author`/`email`/SSH key) — not just the `filter` section. On a fresh
> machine with the default `config.yaml`, a diagnostic subcommand can
> therefore fail on a git error before reaching its own work.

An explicit `filter.product` from the config wins; when the key is absent, the
collector chooses `windows` or `linux`.

## check-filter

**Usage:** `sigmacatch check-filter [--json]`

**Purpose:** validates `SigmaFilterConfig` (product / status / level /
author) against the real Sigma rule set. No CLI args beyond `--json` — runs
every filter combination automatically.

**Pipeline:**

1. Loads all rules from `./sigma` once (`SigmahqRules::new()`)
2. For each filter combination: applies the filter and reads `LoadStats`
3. Independently recomputes ground-truth counts per dimension (`count_ground_truth`)
4. Compares each bucket: `loaded`, `product`, `status`, `level`, `author`, `total`
5. Reports per-test pass/fail + summary (exit 1 if any mismatch)

This is **not circular**: the stats come from `filter()`, the ground truth
is counted directly from the raw rules — so a self-consistent but wrong
`stats()` would still fail.

## list-rules

**Usage:** `sigmacatch list-rules [--json] [--coverage]`

**Purpose:** lists the loaded rules with their path. With `--coverage`, also
shows the ratio of rules that have local regression data (`with_data /
total`, not a percentage); the ids on pending remote `sigmacatch/*` branches
are counted in the skip set without being listed separately. The
missing-technique list produced by `list-rules --json --coverage` is the
working view of what still needs captured data.

**Pipeline:**

1. `Config::load("config.yaml")` (filter section)
2. Loads Sigma rules from `./sigma` + filter config
3. Per rule: id, title, status, level, techniques (`attack.*` tags), path, ART link (first
   sub-technique)

```bash
sigmacatch list-rules
sigmacatch list-rules --json --coverage
```
