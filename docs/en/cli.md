# CLI — Diagnostic Subcommands

Diagnostic commands are subcommands of the binaries, behind the `tools` feature (off by default):

| Binary | Subcommands |
|---|---|
| `sigmacatch-channel` (Windows) | `check`, `check-filter`, `check-channels`, `list-rules`, `get-atomic` |
| `sigmacatch-linux` (Linux) | `check`, `check-filter`, `list-rules` |

An unknown or absent subcommand → the binary starts its normal collection loop.
The sections below document the Windows subcommands; the Linux equivalents
(`check`, `check-filter`, `list-rules`) share the same logic with the `linux`
product filter and `.log` data validation. The Linux `check` auto-detects the
data format of each regression entry from its first non-empty line —
Sysmon-for-Linux XML (`sysmon`), RFC3164 syslog (`syslog`) or auditd records
(`auditd`) — and parses events accordingly before evaluation.

## check

**Usage:** `sigmacatch-channel check [--json]` / `sigmacatch-linux check [--json]`

**Purpose:** deep validation of all regression data in `./sigma/regression_data`.

### Pipeline

1. Loads all Sigma rules from `./sigma`, filters to Windows
2. Builds the `DetectionEngine` once
3. Loads regression entries from `./sigma/regression_data`
4. For each `info.yml` entry:
   - Validates file existence + non-empty (no deep structure check at this stage)
   - Loads the raw `.evtx` / `.log`, parses events
   - Evaluates events against the rule
   - Validates: the rule MUST match (positive detection test)
5. Reports pass/fail per rule + summary (exit 1 if any detection failure)
6. Exit 0 on success (all rules pass or are skipped)

### Output

```text
Found 3777 total rules
  → 2872 windows rules after filtering

Found 202 regression entry(ies)

Engine ready — 2872 rule(s) loaded.

Running validation...

  [   1/202 ] win_security_explicit_credential_local_logon       ... [PASS] 1 alert(s), rule matched
  [   2/202 ] win_security_susp_scheduled_task_delete_or_disable ... [PASS] 1 alert(s), rule matched
  ...
  [ 165/202 ] registry_event_add_local_hidden_user               ... [FAIL] RULE NOT MATCHED — expected '460479f3-...'
  ...

============================================================
  VALIDATION SUMMARY
============================================================
  Total entries:   202
  Passed:          201
  Skipped:         0
  Failed:          1
  Pass rate:       99.5%
============================================================
```

### JSON output

`--json` produces:

```json
{
  "total": 202,
  "passed": 201,
  "skipped": 0,
  "failed_count": 1,
  "pass_rate": 99.5,
  "failed": [
    {
      "rule_name": "registry_event_add_local_hidden_user",
      "rule_id": "460479f3-80b7-42da-9c43-2cc1d54dbccd",
      "error": "RULE NOT MATCHED — expected '460479f3-...' (0 alert(s), matched: )"
    }
  ]
}
```

---

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

---

## check-channels

**Usage:** `sigmacatch-channel check-channels [--json]`

**Purpose:** resolves and lists the Windows channels the engine would collect.

### Pipeline

1. `Config::load("config.yaml")` (filter section)
2. Loads Sigma rules from `./sigma` + filter config
3. `DetectionEngine::new(&rules)` → `resolve_channels(&custom_map)` (incl. custom_channels.yaml)
4. Prints the channel list (exit 1 if none)

### Example

```bash
sigmacatch-channel check-channels
```

---

## list-rules

**Usage:** `sigmacatch-channel list-rules [--json] [--coverage]`

**Purpose:** lists the loaded rules with their path. With `--coverage`, also shows
coverage stats (rules with local regression data, pending remote branches, coverage %).

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

---

## get-atomic

**Usage:** `sigmacatch-channel get-atomic [--output run_atomic.ps1] [--getprereqs] [--json]`

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

### Example

```bash
sigmacatch-channel get-atomic
sigmacatch-channel get-atomic --output /tmp/run_atomic.ps1
sigmacatch-channel get-atomic --getprereqs --json
```
