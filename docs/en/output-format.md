# Output Format

The tool produces regression data compatible with the [SigmaHQ](https://github.com/SigmaHQ/sigma) repository format, ready for PR submission. This page documents **what the pipeline writes**; the full schema (`info.yml`, naming conventions, validation) is specified in [regression-data-format.md](regression-data-format.md).

## Directory structure

The output always lives inside the sigma repo, under `regression_data/`:

```text
<sigma_repo_path>/regression_data/
└── <rule_rel_path>/         # mirrors the rule path under sigma/rules/
    ├── info.yml
    ├── <rule_id>.json       # optional (regression.add_json_output)
    └── <rule_id>.evtx       # or <rule_id>.log on Linux
```

The directory mirrors the rule path under `rules/`. For example:

```text
sigma/rules/windows/builtin/security/win_security_foo.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/
```

## What the pipeline writes

| File | Content | Condition |
|---|---|---|
| `info.yml` | Test metadata (always written) | — |
| `<rule_id>.evtx` | Valid binary EVTX (Windows) | default |
| `<rule_id>.log` | Original lines (Linux) | default |
| `<rule_id>.json` | Serialized raw event | `regression.add_json_output: true` |

### EVTX (Windows)

`<rule_id>.evtx` is produced by `EvtExportLog` (re-queries the event by RecordID from the
live log, short-backoff retries) or, for record-id-less events, by the pure Rust EVTX
writer (`sigmacatch-evtx-writer`, deterministic, no retry). The exported file is
**validated** (re-parse ≥ 1 record); an empty/corrupt export (event rotated out between
collection and export) is an error: the pipeline skips the rule for that cycle (no commit)
and re-captures it later.

### Auxiliary JSON

The `.json` carries the actual data used for Sigma matching (`event_json_raw`). Its shape
depends on the producer: nested and a verbatim mirror of the Winevt XML for Windows events,
flat (`{message, program, host, service}`) for Linux events. See
[regression-data-format.md](regression-data-format.md) for examples.

## Source rule annotation

The source Sigma rule YAML is also annotated with:

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```
