# Tools

Dev tools in the `localcheck` crate, each with its own purpose. They stay out of the
main `sigmacatch` binary so its dependency tree stays lean.

## check_evtx

**File:** `localcheck/src/check_evtx.rs`

**Usage:** `cargo run --release --bin check_evtx`

**Purpose:** Batch validation of the Sigma detection engine against SigmaHQ regression data.

### Pipeline

1. Loads all rules from `./sigma`, filters to Windows
2. Loads regression entries from `./sigma/regression_data`
3. Builds the `DetectionEngine` once
4. For each `info.yml` entry: loads the raw `.evtx`, parses it → events
5. Evaluates the events against the rule
6. Validates: the rule MUST match (positive detection test)
7. Reports pass/fail per rule + summary (exit 1 if any failure)

### Output

```
  [  1/100] proc_creation_win_bitsadmin_download ... [PASS] 1 alert(s), rule matched
  [  2/100] win_security_foo  ... [FAIL] RULE NOT MATCHED — expected '<uuid>' (0 alert(s), matched: ...)

============================================================
  VALIDATION SUMMARY
============================================================
  Total rules:     100
  Passed:          95
  Failed:          5
  Pass rate:       95.0%
============================================================
```

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
  product=windows status=None level=None author=Some("frack113")  →  461 loaded / 3769 total
    GT: loaded=461 prod=908 stat=0 lvl=0 auth=2400 total=3769
    filter: loaded=461 prod=908 stat=0 lvl=0 auth=2400 total=3769
    ✅ all dimensions match ground truth
```

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
