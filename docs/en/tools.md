# Tools

Binaries outside the main binary (`sigmacatch`), each with its own purpose.

## evtx_check

**File:** `sigmacatch/src/bin/evtx_check.rs`

**Usage:** `cargo run --release --bin evtx_check <sigmahq_dir>`

**Purpose:** Batch validation of the Sigma detection engine against SigmaHQ regression data.

### Pipeline

1. Scans `<sigmahq_dir>/regression_data` for `info.yml` files
2. For each triplet: `rule.yml` + `.evtx` + `info.yml`
3. Parses the EVTX file → nested JSON → flat Winevt-compatible format
4. Evaluates the event against the Sigma rule
5. Validates: the rule MUST match (positive detection test)
6. Reports pass/fail per rule + summary

### Output

```
  [1/100] proc_creation_win_bitsadmin_download ... [PASS] 1 match(es)
  [2/100] win_security_foo  ... [FAIL] FALSE NEGATIVE — no matches (EventID=4624, Channel=Security, provider=None)

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
cargo run --release --bin evtx_check ./sigma
```

---

## How to add a tool

1. Create `sigmacatch/src/bin/<name>.rs` with a docstring at the top
2. Add the entry to `sigmacatch/Cargo.toml`:

```toml
[[bin]]
name = "<name>"
path = "src/bin/<name>.rs"
```

3. Document here with usage and pipeline
