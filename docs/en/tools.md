# Tools

Dev tools in the `tools` crate, each with its own purpose. They stay out of the
main `sigmacatch-channel` binary so its dependency tree stays lean.

## check_evtx

**File:** `tools/src/check_evtx.rs`

**Usage:** `cargo run --release --bin check_evtx [--json]`

**Purpose:** Batch validation of the Sigma detection engine against SigmaHQ regression data.

### Pipeline

1. Loads all Sigma rules from `./sigma`, filters to Windows
2. Builds the `DetectionEngine` once
3. Loads regression entries from `./sigma/regression_data`
4. For each `info.yml` entry: loads the raw `.evtx`, parses it → events
5. Evaluates the events against the rule
6. Validates: the rule MUST match (positive detection test)
7. **JSON conformance check**: when a committed `<rule_id>.json` exists, verifies that
   `parse_winevt_xml_raw` reproduces it exactly (SigmaHQ format compatibility) — a mismatch
   is reported separately and does not fail the detection check
8. Reports pass/fail per rule + summary (exit 1 if any detection failure)

### Output

```text
Found 3777 total rules
  → 2872 windows rules after filtering

Found 202 regression entry(ies)

Engine ready — 2872 rule(s) loaded.

Running validation...

  [   1/202 ] win_security_explicit_credential_local_logon       ...     [JSON OK] parse_winevt_xml_raw reproduces committed JSON
[PASS] 1 alert(s), rule matched
  [   2/202 ] win_security_susp_scheduled_task_delete_or_disable ...     [JSON MISMATCH] no EVTX record reproduces committed JSON first diff: Event.EventData.TaskContent ...
[PASS] 1 alert(s), rule matched
  ...
  [ 165/202 ] registry_event_add_local_hidden_user               ...     [JSON OK] parse_winevt_xml_raw reproduces committed JSON
[FAIL] RULE NOT MATCHED — expected '460479f3-80b7-42da-9c43-2cc1d54dbccd' (0 alert(s), matched: )
  --- explain_rule trace ---
  ...
  [ 201/202 ] win_defender_exploit_redsun_tiering_engine_detected_as_eicar ... [JSON MISMATCH] ...
[PASS] 1 alert(s), rule matched
  [ 202/202 ] image_load_win_werfaultsecure_dbgcore_dbghelp_load ...     [JSON OK] parse_winevt_xml_raw reproduces committed JSON
[PASS] 1 alert(s), rule matched

============================================================
  VALIDATION SUMMARY
============================================================
  Total entries:   202
  Passed:          201
  Skipped:         0
  Failed:          1
  Pass rate:       99.5%

  JSON FORMAT CHECKS (parse_winevt_xml_raw vs committed JSON):
  Checked:         189
  Matched:         186
  Mismatch:        3
============================================================

Failed rules:
  FAIL registry_event_add_local_hidden_user — RULE NOT MATCHED — expected '460479f3-...'

JSON format mismatches:
  MISMATCH win_security_susp_scheduled_task_delete_or_disable — no EVTX record reproduces committed JSON first diff: Event.EventData.TaskContent ... (CRLF vs LF in embedded XML)
  MISMATCH proc_creation_win_susp_right_to_left_override — no EVTX record reproduces committed JSON first diff: Event.System.TimeCreated.#attributes.SystemTime ... (fractional-second precision)
  MISMATCH win_defender_exploit_redsun_tiering_engine_detected_as_eicar — no EVTX record reproduces committed JSON first diff: Event.EventData.Threat ID (number vs string)
```

The `check_evtx` run described above matches the current `sigma/regression_data` state
(202 entries, 201 PASS / 1 FAIL — the failure `registry_event_add_local_hidden_user` is the
known registry issue pending a rsigma update; 3 cosmetic JSON format mismatches remain).

### Example

```bash
cargo run --release --bin check_evtx
```

---

## check_filter

**File:** `tools/src/check_filter.rs`

**Usage:** `cargo run --release --bin check_filter [--json]`

**Purpose:** Validates `SigmaFilterConfig` (product / status / level / author) against the real
Sigma rule set. No CLI args — runs every filter combination automatically.

### Pipeline

1. Loads all rules from `./sigma` once (`SigmahqRules::new()`)
2. For each filter combination: applies the filter and reads `LoadStats`
3. Independently recomputes ground-truth counts per dimension (`count_ground_truth`)
4. Compares each bucket: `loaded`, `product`, `status`, `level`, `author`, `total`
5. Reports per-test pass/fail + summary (exit 1 if any mismatch)

This is **not circular**: the stats come from `filter()`, the ground truth is counted
directly from the raw rules — so a self-consistent but wrong `stats()` would still fail.

### Output

```text
Loaded 3777 total rules from ./sigma

============================================================
  TEST: empty filter (no filtering)
============================================================
  product=windows status=None level=None author=None  →  2872 loaded / 3777 total
    GT: loaded=2872 prod=905 stat=0 lvl=0 auth=0 total=3777  sum=3777
    filter: loaded=2872 prod=905 stat=0 lvl=0 auth=0 total=3777  sum=3777
    ✅ all dimensions match ground truth
  ✅ PASS

============================================================
  TEST: product filter
============================================================
  product=linux status=None level=None author=None  →  248 loaded / 3777 total
    GT: loaded=248 prod=3529 stat=0 lvl=0 auth=0 total=3777  sum=3777
    filter: loaded=248 prod=3529 stat=0 lvl=0 auth=0 total=3777  sum=3777
    ✅ all dimensions match ground truth
  product=macos status=None level=None author=None  →  75 loaded / 3777 total
    GT: loaded=75 prod=3702 stat=0 lvl=0 auth=0 total=3777  sum=3777
    filter: loaded=75 prod=3702 stat=0 lvl=0 auth=0 total=3777  sum=3777
    ✅ all dimensions match ground truth
  ✅ PASS

============================================================
  TEST: author filter
============================================================
  product=windows status=None level=None author=Some("FRACK113")  →  461 loaded / 3777 total
    GT: loaded=461 prod=905 stat=0 lvl=0 auth=2411 total=3777  sum=3777
    filter: loaded=461 prod=905 stat=0 lvl=0 auth=2411 total=3777  sum=3777
    ✅ all dimensions match ground truth
  ✅ PASS

============================================================
  TEST: combined: with author
============================================================
  product=windows status=None level=None author=Some("Elastic")  →  5 loaded / 3777 total
    GT: loaded=5 prod=905 stat=0 lvl=0 auth=2867 total=3777  sum=3777
    filter: loaded=5 prod=905 stat=0 lvl=0 auth=2867 total=3777  sum=3777
    ✅ all dimensions match ground truth
  ✅ PASS

============================================================
  SUMMARY
============================================================
  Passed: 7
  Failed: 0
============================================================
```

(7 tests: empty filter, product, status, level, author, combined product+status+level, combined
with author — all pass at the time of writing, 3777 total rules.)

### Example

```bash
cargo run --release --bin check_filter
```

---

## check_dry_run

**File:** `tools/src/check_dry_run.rs`

**Usage:** `cargo run --release --bin check_dry_run [--json]`

**Purpose:** git diagnostics of the former `--dry-run` sigmacatch-channel flag (moved here to keep the
main binary lean). Reuses `Config::load_with_cli` + `dry_run_git` from `sigmacatch-config`.
Accepts the same flags as the main binary (`--author`, `-o`/`--offline`,
`-c`/`--contrib`, `--help`).

### Pipeline

1. `parse_args()` + `Config::load_with_cli("config.yaml", cli)`
2. `dry_run_git(&config)` → token resolution (config + env), fork detection (HTTP HEAD),
   API `/user` check, git smart HTTP info/refs endpoint, local `sigma/` repo state
3. Detailed report of each step → identify the failure point

---

## check_channels

**File:** `tools/src/check_channels.rs`

**Usage:** `cargo run --release --bin check_channels [--json]`

**Purpose:** resolves and lists the Windows channels the engine would collect (former
`--channels-only` sigmacatch-channel flag, moved here).

### Pipeline

1. `Config::load("config.yaml")` (filter section)
2. Loads Sigma rules from `./sigma` + filter config
3. `DetectionEngine::new(&rules)` → `resolve_channels(&custom_map)` (incl. custom_channels.yaml)
4. Prints the channel list (exit 1 if none)

---

## list_rules

**File:** `tools/src/list_rules.rs`

**Usage:** `cargo run --release --bin list_rules [--json]`

**Purpose:** lists the loaded rules with their path (former `--list-rules` sigmacatch-channel flag,
moved here).

### Pipeline

1. `Config::load("config.yaml")` (filter section)
2. Loads Sigma rules from `./sigma` + filter config
3. Per rule: id, title, status, level, techniques (`attack.*` tags), path, ART link (first
   sub-technique)

---

## get_atomic

**File:** `tools/src/get_atomic.rs`

**Usage:** `cargo run --release --bin get_atomic [--output run_atomic.ps] [--getprereqs] [--json]`

**Purpose:** generates a `run_atomic.ps1` script chaining `Invoke-AtomicTest
T1xxx.xxx` commands for the ATT&CK techniques of rules **without regression
data** according to the config filter. The script is copied to the Windows VM
and run manually; sigmacatch-channel (continuous loop) captures the generated events
and produces the regression data.

### Pipeline

1. `Config::load("config.yaml")` (filter section + `git.sigma_repo_path`)
2. Loads Sigma rules from `./sigma` + filter config
3. Skip set = rules with valid regression data (local `regression_data/`)
   ∪ ids on pending remote `sigmacatch/*` branches
4. For each remaining rule: `rule.attack_techniques()` (`SigmaRuleExt`
   extension trait from `sigmacatch-rule`)
5. Dedupe + sort techniques (BTreeSet) — one `Invoke-AtomicTest` per technique
6. Writes `run_atomic.ps1` (or `--output <path>`) + report

### Generated script

```powershell
$ErrorActionPreference = "Continue"
Import-Module Invoke-AtomicRedTeam
# 12 rule(s) without regression data — 7 technique(s)
Start-Sleep -Seconds 5
Invoke-AtomicTest T1055.001 -TimeoutSeconds 120
Start-Sleep -Seconds 30
Invoke-AtomicTest T1547.001 -TimeoutSeconds 120
...
```

- `Start-Sleep 30` between tests → lets sigmacatch-channel collect the events
- `-TimeoutSeconds 120` → prevents a blocking test from freezing the chain
- Rules without an `attack.*` tag are counted and listed in the report (no
  `Invoke-AtomicTest` generated for them)

### Limitations

No coverage guarantee: a rule with a specific condition may not match the event
produced by the ART test. Rules that still have no data are re-listed on the
next run (the skip set only excludes what is already generated).

---

## coverage

**File:** `tools/src/coverage.rs`

**Usage:** `cargo run --release --bin coverage [--json]`

**Purpose:** big-picture coverage stats for the current filter config. JSON output:
total rules, rules with local regression, rules pending on remote branches,
coverage percentage.

### Pipeline

1. `Config::load("config.yaml")` (filter section)
2. Loads all Sigma rules from `./sigma` + filter config
3. Scan local `regression_data/` → skip set
4. `SigmaRepo::pending_regression_rule_ids()` → skip set remote branches
5. Compute coverage % → JSON

---

## How to add a tool

1. Create `tools/src/<name>.rs` with a docstring at the top
2. Add the entry to `tools/Cargo.toml`:

```toml
[[bin]]
name = "<name>"
path = "src/<name>.rs"
```

1. Add only the dependencies the tool needs to `tools/Cargo.toml`
2. Document here with usage and pipeline
