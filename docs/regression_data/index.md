# Regression Data

sigmacatch produces regression data compatible with the
[SigmaHQ](https://github.com/SigmaHQ/sigma) repository format, ready for PR
submission. For every matched rule it writes a **set**: an `info.yml`
(metadata) plus a **data file** that stores the captured event. The
validation tool [`regressiondata-check`](../user/cli.md#regressiondata-check-regression-validation-cross-platform)
replays the stored event through the detection engine and verifies the rule
still matches, so a rule change that breaks a known detection is caught.

| Page | Content |
|---|---|
| [info.yml](info-yml.md) | Metadata schema and examples |
| [Data files](data-files.md) | Formats (`.evtx`, `.log`, `.json`/NDJSON, `.raw`), naming, platforms |
| [Validation](validation.md) | What makes a set valid, and what `regressiondata-check` enforces |

## Directory layout

The output always lives inside the sigma repo, under `regression_data/`, and
mirrors the rule path under `rules/`, `rules-emerging-threats/` and
`rules-threat-hunting/`:

```text
regression_data/
├── rules/windows/process_creation/<slug>/            # main rules
├── rules/linux/auditd/execve/<slug>/
└── rules-emerging-threats/2026/Exploits/CVE-2026-33829/<slug>/
```

```text
sigma/rules/windows/builtin/security/win_security_foo.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/
```

Intermediate directories reflect the SigmaHQ category hierarchy. The last
directory before the files is always a **slug** derived from the rule YAML
name (lowercase with underscores). The slug is **never** compared to the
rule_id UUID.

## Files per set

```text
<slug>/
├── info.yml                    # Metadata + test results
├── <rule_id>.evtx              # Windows (EvtExportLog or pure Rust writer)
├── <rule_id>.log               # Linux auditd/syslog/Sysmon tail
└── <rule_id>.json              # Linux eBPF data, or optional auxiliary raw event
```

| File | Content | Condition |
|---|---|---|
| `info.yml` | Test metadata (always written) | — |
| `<rule_id>.evtx` | Valid binary EVTX (Windows) | Windows collectors |
| `<rule_id>.log` | Original lines (Linux auditd/syslog/Sysmon tail) | Linux line collectors |
| `<rule_id>.json` | JSON/NDJSON event (Linux eBPF), or auxiliary raw event | eBPF collector, or `regression.add_json_output: true` (EVTX/log only) |

The `<rule_id>` is always the **UUID** in `rule_metadata[0].id` of the
`info.yml` file — never the directory name.

The data file + `info.yml` are the mandatory output. Some rules (e.g. cisco)
use `.raw` instead when the EVTX format is not applicable; for EVTX/log
data, a `.json` export is an optional extra (see
[Data files](data-files.md)).

## Source rule annotation

The source Sigma rule YAML is also annotated with:

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```

The path mirrors the rule's own path under `rules*` — the annotation is how a
reader (and `regressiondata-check`) links a rule to its regression set.
