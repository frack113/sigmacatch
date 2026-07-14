# Output Format

The tool produces regression data compatible with the [SigmaHQ](https://github.com/SigmaHQ/sigma) repository format, ready for PR submission.

## Directory structure

```
regression_data/
└── <rule_rel_path>/         # mirrors the rule path under sigma/rules/ (or rules/<rule_id>)
    ├── info.yml
    ├── <rule_id>.json
    └── <rule_id>.evtx
```

The directory mirrors the rule path under `rules/`. For example:

```
sigma/rules/windows/builtin/security/win_security_foo.yml
    → regression_data/rules/windows/builtin/security/win_security_foo/
    → regression_data/rules/windows/builtin/security/win_security_foo/info.yml
    → regression_data/rules/windows/builtin/security/win_security_foo/<rule_id>.json
    → regression_data/rules/windows/builtin/security/win_security_foo/<rule_id>.evtx
```

## File contents

### `<rule_id>.json`

A single event, **flat JSON** with keys named according to Sigma (produced by `XmlParser`).
XML fields are flattened directly into the flat form that Sigma rules expect:

```json
{
  "EventID": "1",
  "SysmonEventID": "1",
  "ProcessId": "3904",
  "ThreadId": "4272",
  "Provider": "Microsoft-Windows-Sysmon",
  "_source": "etw",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"whoami\"",
  "ParentImage": "C:\\Windows\\explorer.exe",
  "User": "SYSTEM"
}
```

### `info.yml`

```yaml
id: <uuid>                                    # UUID v4 unique per info.yml entry
description: N/A
date: 2025-07-09
author: <rule_author_from_yaml>                # extracted from the rule YAML
rule_metadata:
    - id: <rule_id>
      title: <rule_title>
regression_tests_info:
    - name: Positive Detection Test
      type: evtx
      provider: Microsoft-Windows-Sysmon                # dynamically extracted from event's ProviderName
      match_count: 1                           # one event per test entry
      path: "regression_data/<rule_rel_path>/<rule_id>.evtx"  # relative path to the EVTX file
```

> `path` is the relative path to the `.evtx` file under `regression_data/`.

The source rule YAML is also annotated with:

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```

## Constraints

- **One event per rule**: each regression directory contains exactly one JSON event.
  Only the first matching event is captured.
- **Valid binary EVTX**: `<rule_id>.evtx` is written via `EvtExportLog` API (Windows), which re-queries the event by RecordID from the live log.
  If `EvtExportLog` fails (event rotated out of retention) or on non-Windows → fallback `.xml` (raw XML, not invalid binary).
  The companion `.json` file carries the actual data for Sigma matching.
