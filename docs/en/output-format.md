# Output Format

The tool produces regression data compatible with the [SigmaHQ](https://github.com/SigmaHQ/sigma) repository format, ready for PR submission.

## Directory structure

The output always lives inside the sigma repo, under `regression_data/`:

```
<sigma_repo_path>/regression_data/
└── <rule_rel_path>/         # mirrors the rule path under sigma/rules/
    ├── info.yml
    ├── <rule_id>.json
    └── <rule_id>.evtx
```

The directory mirrors the rule path under `rules/`. For example:

```
sigma/rules/windows/builtin/security/win_security_foo.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/info.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/<rule_id>.json
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/<rule_id>.evtx
```

## File contents

### `<rule_id>.json`

A single event, serialized from `event_json_raw` — the JSON form of the Winevt XML event
produced by `sigmacatch-types` (roxmltree). It is **nested**, mirrors the original XML
structure verbatim, and preserves the original `EventData` key names (including spaces):

```json
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "System": {
      "Provider": {
        "#attributes": {
          "Name": "Microsoft-Windows-Sysmon",
          "Guid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9"
        }
      },
      "EventID": 1,
      "Version": 5,
      "Level": 4,
      "Task": 1,
      "Opcode": 0,
      "Keywords": "0x8000000000000000",
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2025-12-10T04:33:20.562782Z"
        }
      },
      "EventRecordID": 18463,
      "Correlation": null,
      "Execution": {
        "#attributes": {
          "ProcessID": 3208,
          "ThreadID": 1724
        }
      },
      "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": "swachchhanda",
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-18"
        }
      }
    },
    "EventData": {
      "RuleName": "-",
      "UtcTime": "2025-12-10 04:33:20.557",
      "ProcessGuid": "0197231E-F810-6938-B710-000000000800",
      "ProcessId": 7732,
      "Image": "C:\\Windows\\System32\\bitsadmin.exe",
      "CommandLine": "bitsadmin  /transfer n https://www.atomicredteam.io/atomic-red-team/atomics/T1218.011 hello.html",
      "User": "swachchhanda\\xodih",
      "Hashes": "MD5=4FCFE1D61E6D962F06CE2B61FC11BC0F,SHA256=6FEB16602A2FD1158C6F7E56E3B05A5E9AC01E88089535978C890EC6954A5AFA,IMPHASH=44794EEDDEB70144ABA2F1483E762F30"
    }
  }
}
```

Notable conventions:
- XML attributes are stored under a `#attributes` key (e.g. `Provider`, `TimeCreated`).
- `EventData` keeps its **original** key names — spaces included (e.g. `"RuleName"`, not `Rule_Name`).
  `event_json` (the detection-engine form) strips those spaces; `event_json_raw` (this file) does not.
- Numeric values keep their native JSON type (e.g. `"EventID": 1`, not `"1"`).

### `info.yml`

```yaml
id: <uuid>                                    # UUID v4 unique per info.yml entry
description: N/A
date: 2025-12-10
author: <config.git.author>                   # from config.git.author (fallback: "Sigma Regression Generator")
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

> `path` is the relative path to the `.evtx` file under `regression_data/` (inside the sigma repo).

The source rule YAML is also annotated with:

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```

### Supported logtypes

The `type` field of `regression_tests_info` (and the reading of existing info.yml files) supports
4 logtypes (`crates/sigmacatch-regression/src/logtype.rs`): `evtx`, `json`, `raw`, `log`
— an unknown/missing value falls back to `json` with a `warn!`. The pipeline always writes
`.json` + `.evtx` (fallback `.xml`); a `.raw` is possible for non-Winevt data
(e.g. `regression_data/rules/cisco/aaa/cisco_cli_dot1x_disabled/ef0ff092-....raw`, `type: raw`,
generated outside the pipeline — its `regression_tests_info` section is commented out).

## Constraints

- **One event per rule**: each regression directory contains exactly one JSON event.
  Only the first matching event is captured.
- **Valid binary EVTX**: `<rule_id>.evtx` is written via `EvtExportLog` API (Windows), which re-queries the event by RecordID from the live log.
  If `EvtExportLog` fails (event rotated out of retention) or on non-Windows → fallback `.xml` (raw XML, not invalid binary).
  The companion `.json` file carries the actual data for Sigma matching.
