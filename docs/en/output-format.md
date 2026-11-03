# Output Format

The tool produces regression data compatible with the [SigmaHQ](https://github.com/SigmaHQ/sigma)
repo format, ready for a PR submission. This page documents **what the pipeline writes** ; the
full schema (`info.yml`, naming conventions, validation) is specified in
[regression-data-format.md](regression-data-format.md).

## Directory structure

The output always lives in the sigma repo, under `regression_data/` :

```text
<sigma_repo_path>/regression_data/
└── <rule_rel_path>/         # mirror of the rule path under sigma/rules/
    ├── info.yml
    ├── <rule_id>.json       # optional (regression.add_json_output)
    └── <rule_id>.evtx       # or <rule_id>.log on Linux
```

The directory mirrors the rule path under `rules/`. For example :

```text
sigma/rules/windows/builtin/security/win_security_foo.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/
```

## What the pipeline writes

| File | Content | Condition |
|---|---|---|
| `info.yml` | Test metadata (always written) | — |
| `<rule_id>.evtx` | Valid EVTX binary (Windows) | default |
| `<rule_id>.log` | Original lines (Linux) | default |
| `<rule_id>.json` | Serialized raw event | `regression.add_json_output: true` |

### EVTX (Windows)

`<rule_id>.evtx` is produced by `EvtExportLog` (re-query of the event by RecordID from the live
log, short backoff retries) or, for events without a record id, by the pure-Rust EVTX writer
(`evtx_writer` in `sigmacatch::regression`, deterministic, no retries). The exported file is
**validated** (re-parse ≥ 1 record) ; an empty/corrupt export (event purged between collection
and export) is an error : the pipeline skips the rule that cycle (no commit) and recaptures later.

### Auxiliary JSON

The `.json` carries the real data for Sigma matching (`event_json_raw`). Its shape depends on
the producer: nested and faithful mirror of the Winevt XML for Windows events, flat
(`{message, program, host?}`, `host` optional) for syslog and structured
(`{stamp, type, node?, fields}`) for auditd on Linux. The pipeline writes a single JSON object
terminated by exactly one newline ; the validator (`regressiondata-check`) also accepts JSONL
(one object per line). See [regression-data-format.md](regression-data-format.md) for examples.

## Source YAML annotation

The source Sigma rule is also annotated with :

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```
