# Output Format

The tool produces regression data compatible with the [SigmaHQ](https://github.com/SigmaHQ/sigma) repository format, ready for PR submission. This page documents **what the pipeline writes**; the full schema (`info.yml`, naming conventions, validation) is specified in [regression-data-format.md](regression-data-format.md).

## Directory structure

The output always lives inside the sigma repo, under `regression_data/`:

```text
<sigma_repo_path>/regression_data/
└── <rule_rel_path>/         # mirrors the rule path under sigma/rules/
    ├── info.yml
    ├── <rule_id>.evtx       # Windows
    ├── <rule_id>.log        # Linux auditd/syslog/Sysmon-tail
    └── <rule_id>.json       # Linux eBPF data, or optional auxiliary export
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
| `<rule_id>.evtx` | Valid binary EVTX (Windows) | Windows collectors |
| `<rule_id>.log` | Original lines (Linux auditd/syslog/Sysmon tail) | Linux line collectors |
| `<rule_id>.json` | JSON/NDJSON event (Linux eBPF), or auxiliary raw event | eBPF collector, or `regression.add_json_output: true` (EVTX/log only) |

### EVTX (Windows)

`<rule_id>.evtx` is produced by `EvtExportLog` (re-queries the event by RecordID from the
live log, short-backoff retries) or, for record-id-less events, by the pure Rust EVTX
writer (`evtx_writer` module of `sigmacatch::regression`, deterministic, no retry). The exported file is
**validated** (re-parse ≥ 1 record); an empty/corrupt export (event rotated out between
collection and export) is an error: the pipeline skips the rule for that cycle (no commit)
and re-captures it later.

### eBPF JSON / NDJSON (Linux)

The eBPF collector writes `<rule_id>.json` as its **primary data file**:

- one event → a pretty-printed JSON document, `type: json`;
- several records → NDJSON, one compact JSON object per line, `type: ndjson`.

Auditd alerts remain `.log` (`type: log`) even when eBPF is active in the same binary. The
`.json` carries the nested `Event.System`/`Event.EventData` view used for matching.

### Auxiliary JSON

When the primary data file is `.evtx` or `.log`, `regression.add_json_output: true` adds an
auxiliary `.json` with the raw event. Its shape depends on the producer: nested and a
verbatim mirror of the Winevt XML for Windows events, flat
(`{message, program, host?}`, `host` optional) for syslog and structured
(`{stamp, type, node?, fields}`) for auditd on Linux. A single record is a pretty-printed
document; several records are NDJSON. The validator (`regressiondata-check`) stream-parses
both layouts. See [regression-data-format.md](regression-data-format.md) for examples.

## Source rule annotation

The source Sigma rule YAML is also annotated with:

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```
