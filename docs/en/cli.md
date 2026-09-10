# CLI — Diagnostic and tooling

## `regressiondata-check` — regression validation (cross-platform)

`check` is no longer a subcommand of the collector: it is a standalone
**`regressiondata-check`** binary, built for Linux and Windows, without a collector. It
loads the Sigma rules and regression data, replays each stored event
through the detection engine, and verifies that the expected rule still matches.

**Usage:**

```text
regressiondata-check [--json] [--ignore] [--fix] [--path <DIR>]
```

- `--json` — outputs JSON instead of human-readable text.
- `--ignore` — skip invalid entries (missing entry/raw data, empty events) without counting
  them as failures.
- `--fix` — normalize JSON trailing newlines and `info.yml` indentation.
- `--path <DIR>` — root of the sigma repository (default: `./sigma`).
- `--help`, `-h` — print usage and exit.

**Purpose:** deep validation of all regression data in the sigma root's
`regression_data/` (`./sigma/regression_data` by default). Entries are
parsed according to their `LogType`: `.evtx` via `evtx_reader::parse_evtx_bytes`,
`.log` via the auditd parser, straight JSON lines. The `Raw` logtype is skipped.

### Pipeline

1. Loads all Sigma rules from the sigma root (`./sigma` by default, `--path <DIR>` to override)
2. Builds the `DetectionEngine` once in **lenient** mode (`new_lenient`): rules that fail
   to compile are skipped with a warning, never a failure
3. Loads regression entries from `<DIR>/regression_data`
4. Bidirectional `regression_tests_path` validation between rules and entries:
   every entry's rule must declare a matching `regression_tests_path`, and every declared
   path must point to an existing entry (missing / mismatched paths are counted).
5. Non-blocking warnings: rule ids that are not UUID v4 (upstream SigmaHQ ships some;
   warned, never failed) and rules that failed to compile (lenient mode)
6. For each `info.yml` entry:
   - Validates the `info.yml`: non-empty `rule_metadata` (always a failure), SigmaHQ
     4-space indentation, non-empty `regression_tests_info` (empty → failure, or ignored
     with `--ignore`)
   - Validates the auxiliary `.json` if present: valid **JSON or JSONL** (one object per
     line), exactly one trailing newline
   - Loads the raw data according to the `logtype` (`.evtx`, `.log`, JSON lines), parses events
   - Evaluates events against the rule
   - Validates: the rule MUST match (positive detection test)
   - When a `.json` auxiliary is present, validates the declared `match_count` against the
     real hit count (match count mismatch is a failure)
7. Reports pass/fail per rule + summary (exit 1 on any detection or path failure)

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
`Skipped`, `Dropped lines` and `Warnings`, followed by the `Failed rules` list
(`FAIL <rule_name> — <error>`) when any entry failed. A failing summary exits 1
(detection failures **or** missing/mismatched paths).

**Example:**

```bash
regressiondata-check
regressiondata-check --json --ignore
# from the root of a sigma repository checkout (e.g. CI/CD on SigmaHQ/sigma):
regressiondata-check --path .
regressiondata-check --fix --path .
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
  ],
  "warning_count": 1,
  "warnings": [
    "1 rule(s) failed to compile (lenient mode): [7]"
  ]
}
```

`warnings` collects non-v4 rule ids and rules that failed to compile (lenient mode);
they never trigger exit 1.

---

## `--evtx` — one-shot EVTX input (single run)

Feature `evtx`: a `CollectorKind` with `live_capture() = false` that runs
through the **same** `run()` pipeline as the continuous collectors. It recursively scans a
directory for `.evtx` files, parses each event in pure Rust, pushes them through the
detection engine, writes SigmaHQ regression data for every matched rule (pure-Rust EVTX
writer — never `EvtExportLog`, since static events are not in the live Event Log), then
commits and pushes per rule to `sigmacatch/<date>` on the configured fork. Because
`EventProducer::run()` returns once every file is drained, the sender drops and the shared
loop exits — one pass: read → detect → generate → commit/push, no collection loop. A failed
final upload exits with a non-zero status.

**Usage:**

```text
sigmacatch --evtx <EVTX_PATH> [OPTIONS]

      --evtx <EVTX_PATH>  Directory of .evtx files, scanned recursively
                       (default: C:\Windows\System32\winevt\Logs)
  -v, --verbose        Info-level logging on stderr
  -h, --help           Print help and exit
```

`--evtx` is parsed by the shared CLI but used only by the `evtx` input. Like always the
config file is read from the working directory (`config.yaml` in the CWD — there is no
`--config` flag). It supports the common flags below (`-a`, `-c`, `-o`, `-v`, `-n`,
`--author`); `-r/--max-runs` is accepted but ignored (self-terminating), and `-n/--dry-run`
keeps its read-only semantics.

The sigma repository and the regression output are taken from the config
(`git.sigma_repo_path`, relative paths resolved against the config file's directory);
regression data is written under `<sigma_repo_path>/regression_data`.

---

## Flags of the collector binary

The single `sigmacatch` binary (whatever the compiled inputs) shares these flags:

```text
sigmacatch [OPTIONS]

  -a, --all-rules    Load all rules (ignore existing regression data)
  -c, --contrib      Enable push to the remote fork (neutralized by --offline)
  -o, --offline      No git operations at all (on-disk files as-is, no commit/push)
  -r, --max-runs <N> Exit after N collection cycles (0 = unlimited)
  -v, --verbose      Info-level logging on stderr
  -n, --dry-run      Read-only check: load the ./sigma rules and build the engine —
                     no data written, no git/network operation
      --author <NAME> Override the git author from config.yaml for this run
      --evtx <PATH>   Directory of EVTX files to process (one-shot evtx input;
                      requests the `evtx` feature when not compiled in)
  --help, -h         Print help and exit
```

`--dry-run` runs **before** logger init: it creates neither `config.yaml` nor `logs/`,
skips git validation (author/email/token) and only loads the rules from `./sigma` +
builds the detection engine.

---

## Diagnostic subcommands of the collector binary

The commands below are subcommands of `sigmacatch`, **always compiled** (the `tools`
feature has been removed):

| Binary | Subcommands |
|---|---|
| `sigmacatch` (any platform) | `check-filter`, `list-rules` |

An unknown or absent subcommand → `sigmacatch` starts its normal collection loop (or, with
`--evtx`, the one-shot EVTX pass). The `filter.product` value is taken from the config.

> **Common prerequisite:** every subcommand loads `config.yaml` through `Config::load`,
> which runs **full** validation (including git.author/email/token) — not just the
> `filter` section. On a fresh machine with the default `config.yaml`, a diagnostic
> subcommand can therefore fail on a git error before reaching its own work.

## check-filter

**Usage:** `sigmacatch check-filter [--json]`

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
sigmacatch check-filter
```

## list-rules

**Usage:** `sigmacatch list-rules [--json] [--coverage]`

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
sigmacatch list-rules
sigmacatch list-rules --json --coverage
```

The `get-atomic` and `check-channels` subcommands have been removed. `get-atomic` is
replaced by the list of missing techniques produced by `list-rules --json --coverage` and
the generation of regression data; Atomic Red Team tests are now orchestrated directly on
the VM (module `Invoke-AtomicRedTeam` in `C:\AtomicRedTeam`) targeting the rules without
data. `check` is replaced by the standalone `regressiondata-check` binary (see above).
