# regressiondata-check

A standalone binary — no collector, Linux and Windows — that validates
regression data. It loads the Sigma rules and every regression entry, replays
each stored event through the detection engine, and verifies that the expected
rule still matches.

It shares `config.yaml` with `sigmacatch` (no `--config` flag); see
[Configuration](config.md).

## Build

```bash
# Linux
cargo build --release -p sigmacatch --bin regressiondata-check
# Windows
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --bin regressiondata-check
```

## Usage

```text
regressiondata-check [--json] [--ignore] [--fix] [--path <DIR>]
```

- `--json` — outputs JSON instead of human-readable text.
- `--ignore` — skip invalid entries (missing entry/raw data, empty events)
  without counting them as failures.
- `--fix` — normalize JSON trailing newlines and `info.yml` indentation.
- `--path <DIR>` — root of the sigma repository (default: `./sigma`).
- `--help`, `-h` — print usage and exit.

## What it validates

Deep validation of all regression data in the sigma root's `regression_data/`
(`./sigma/regression_data` by default). Entries are parsed according to their
`LogType`: `.evtx` via `evtx_reader::parse_evtx_bytes`, `.log` via the auditd
parser, JSON/NDJSON via a stream deserializer. JSON events re-inject the Linux
logsource (`auditd` or `sysmon`) instead of the Windows default. The `Raw`
logtype is skipped.

### Pipeline

1. Loads all Sigma rules from the sigma root (`./sigma` by default, `--path <DIR>` to override)
2. Builds the `DetectionEngine` once in **lenient** mode (`new_lenient`): rules that fail
   to compile are skipped with a warning, never a failure
3. Loads regression entries from `<DIR>/regression_data`
4. Bidirectional `regression_tests_path` validation between rules and entries:
   every entry's rule must declare a matching `regression_tests_path`, and every declared
   path must point to an existing entry (missing / mismatched paths are counted)
5. Non-blocking warnings: rule ids that are not UUID v4 (upstream SigmaHQ ships some;
   warned, never failed) and rules that failed to compile (lenient mode)
6. For each `info.yml` entry:
   - Validates the `info.yml`: non-empty `rule_metadata` (always a failure), SigmaHQ
     4-space indentation, non-empty `regression_tests_info` (empty → failure, or ignored
     with `--ignore`)
   - Validates the auxiliary `.json` if present: valid **JSON or NDJSON** (one object per
     line), exactly one trailing newline
   - Loads the raw data according to the `logtype` (`.evtx`, `.log`, JSON/NDJSON), parses events
   - Evaluates events against the rule
   - Validates: the rule MUST match (positive detection test)
   - When a `.json` auxiliary is present, validates the declared `match_count` against the
     real hit count (match count mismatch is a failure)
7. Reports pass/fail per rule + summary (exit 1 on any detection or path failure)

## Output

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

The summary also reports, when non-zero: `Missing paths`, `Mismatched`,
`Ignored`, `Skipped`, `Dropped lines` and `Warnings`, followed by the
`Failed rules` list (`FAIL <rule_name> — <error>`) when any entry failed. A
failing summary exits 1 (detection failures **or** missing/mismatched
paths).

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

`warnings` collects non-v4 rule ids and rules that failed to compile
(lenient mode); they never trigger exit 1.
