# Tools

Dev tools in the `localcheck` crate, each with its own purpose. They stay out of the
main `sigmacatch` binary so its dependency tree stays lean.

## check_evtx

**File:** `localcheck/src/check_evtx.rs`

**Usage:** `cargo run --release --bin check_evtx`

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

```
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

**File:** `localcheck/src/check_filter.rs`

**Usage:** `cargo run --release --bin check_filter`

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

```
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

## How to add a tool

1. Create `localcheck/src/<name>.rs` with a docstring at the top
2. Add the entry to `localcheck/Cargo.toml`:

```toml
[[bin]]
name = "<name>"
path = "src/<name>.rs"
```

3. Add only the dependencies the tool needs to `localcheck/Cargo.toml`
4. Document here with usage and pipeline
