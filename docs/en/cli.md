# CLI — Diagnostic and tooling

## `sigmacatch-check` — regression validation (cross-platform)

`check` is no longer a subcommand of the collector binaries: it is a standalone
**`sigmacatch-check`** binary, built for Linux and Windows, without a collector. It
loads the Sigma rules and regression data, replays each stored event
through the detection engine, and verifies that the expected rule still matches.

**Usage:**

```text
sigmacatch-check [--json] [--ignore]
```

- `--json` — outputs JSON instead of human-readable text.
- `--ignore` — skip invalid entries (missing entry/raw data, empty events) without counting
  them as failures.
- `--help`, `-h` — print usage and exit.

**Purpose:** deep validation of all regression data in `./sigma/regression_data`. Entries are
parsed according to their `LogType`: `.evtx` via `input_windows_evtx::parse_evtx_bytes`,
`.log` via the auditd parser, straight JSON lines. The `Raw` logtype is skipped.

### Pipeline

1. Loads all Sigma rules from `./sigma`
2. Builds the `DetectionEngine` once
3. Loads regression entries from `./sigma/regression_data`
4. Bidirectional `regression_tests_path` validation between rules and entries:
   every entry's rule must declare a matching `regression_tests_path`, and every declared
   path must point to an existing entry (missing / mismatched paths are counted).
5. For each `info.yml` entry:
   - Validates file existence + non-empty (no deep structure check at this stage)
   - Loads the raw `.evtx` / `.log`, parses events
   - Evaluates events against the rule
   - Validates: the rule MUST match (positive detection test)
   - When a `.json` auxiliary is present, validates the declared `match_count` against the
     real hit count (match count mismatch is a failure)
6. Reports pass/fail per rule + summary (exit 1 on any detection or path failure)

### Output

```text
[PASS] 1 alert(s), rule matched
[PASS] 1 alert(s), rule matched
...
[FAIL] EMPTY — no events produced from raw data
[PASS] 1 alert(s), rule matched
...
[FAIL] RULE NOT MATCHED — expected '460479f3-80b7-42da-9c43-2cc1d54dbccd' (0 alert(s), matched: )

============================================================
  VALIDATION SUMMARY
============================================================
  Total entries:   202
  Passed:          200
  Failed:          2
  Pass rate:       99.0%
============================================================
```

The summary also reports, when non-zero: `Missing paths`, `Mismatched`, `Ignored`,
`Skipped` and `Dropped lines`. A failing summary exits 1 (detection failures **or** any
missing/mismatched path).

**Example:**

```bash
sigmacatch-check
sigmacatch-check --json --ignore
```

### JSON output

`--json` produces:

```json
{
  "total": 202,
  "passed": 200,
  "skipped": 0,
  "ignored": 0,
  "missing_path": 0,
  "mismatched_path": 0,
  "failed_count": 2,
  "pass_rate": 99.0,
  "failed": [
    {
      "rule_name": "registry_event_add_local_hidden_user",
      "error": "RULE NOT MATCHED — expected '460479f3-...' (0 alert(s), matched: )"
    },
    {
      "rule_name": "cisco_cli_dot1x_disabled",
      "error": "EMPTY — no events produced from raw data"
    }
  ]
}
```

---

## Diagnostic subcommands of the collector binaries

The commands below are subcommands of the binaries, **always compiled** (the `tools`
feature has been removed):

| Binary | Subcommands |
|---|---|
| `sigmacatch-channel` (Windows) | `check-filter`, `list-rules` |
| `sigmacatch-linux` (Linux) | `check-filter`, `list-rules` |

An unknown or absent subcommand → the binary starts its normal collection loop.
The Linux equivalents share the same logic with the `linux` product filter.

> **Common prerequisite:** every subcommand loads `config.yaml` through `Config::load`,
> which runs **full** validation (including git.author/email/token) — not just the
> `filter` section. On a fresh machine with the default `config.yaml`, a diagnostic
> subcommand can therefore fail on a git error before reaching its own work.

## check-filter

**Usage:** `sigmacatch-channel check-filter [--json]`

**Purpose:** validates `SigmaFilterConfig` (product / status / level / author) against the real
Sigma rule set. No CLI args — runs every filter combination automatically.

### Pipeline

1. Loads all rules from `./sigma` once (`SigmahqRules::new()`)
2. For each filter combination: applies the filter and reads `LoadStats`
3. Independently recomputes ground-truth counts per dimension (`count_ground_truth`)
4. Compares each bucket: `loaded`, `product`, `status`, `level`, `author`, `total`
5. Reports per-test pass/fail + summary (exit 1 if any mismatch)

This is **not circular**: the stats come from `filter()`, the ground truth is counted
directly from the raw rules — so a self-consistent but wrong `stats()` would still fail.

### Example

```bash
sigmacatch-channel check-filter
```

## list-rules

**Usage:** `sigmacatch-channel list-rules [--json] [--coverage]`

**Purpose:** lists the loaded rules with their path. With `--coverage`, also shows the ratio
of rules that have local regression data (`with_data / total`, not a percentage); the ids on
pending remote `sigmacatch/*` branches are counted in the skip set without being listed
separately.

### Pipeline

1. `Config::load("config.yaml")` (filter section)
2. Loads Sigma rules from `./sigma` + filter config
3. Per rule: id, title, status, level, techniques (`attack.*` tags), path, ART link (first
   sub-technique)

### Example

```bash
sigmacatch-channel list-rules
sigmacatch-channel list-rules --json --coverage
```

The `get-atomic` and `check-channels` subcommands have been removed. `get-atomic` is
replaced by the list of missing techniques produced by `list-rules --json --coverage` and
the generation of regression data; Atomic Red Team tests are now orchestrated directly on
the VM (module `Invoke-AtomicRedTeam` in `C:\AtomicRedTeam`) targeting the rules without
data. `check` is replaced by the standalone `sigmacatch-check` binary (see above).
