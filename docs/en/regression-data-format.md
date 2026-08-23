# Sigma Regression Data Format

Regression data format for Sigma rules, compatible with SigmaHQ.

## Purpose

A regression test set consists per rule of an `info.yml` file (metadata) and a **data file** (`<rule_id>.evtx` for Windows, `<rule_id>.log` for Linux). An auxiliary `.json` (raw event) can be added via the `regression.add_json_output` option (default: `false`). This allows validating that a Sigma engine always produces the same results for a given rule against a known event.

## Directory tree

```text
regression_data/
├── rules/                            # Main SigmaHQ rules
│   ├── cisco/
│   │   └── aaa/
│   │       └── cisco_cli_dot1x_disabled/
│   ├── linux/
│   │   ├── auditd/
│   │   │   ├── execve/               → <slug>/
│   │   │   ├── path/                 → <slug>/
│   │   │   └── syscall/              → <slug>/
│   │   └── builtin/                  → <slug>/
│   └── windows/
│       ├── builtin/
│       │   ├── security/             → <slug>/
│       │   ├── taskscheduler/        → <slug>/
│       │   └── wmi/                  → <slug>/
│       ├── file/
│       │   └── file_event/           → <slug>/
│       ├── image_load/               → <slug>/
│       ├── process_access/           → <slug>/
│       ├── process_creation/         → <slug>/
│       ├── registry/
│       │   ├── registry_delete/      → <slug>/
│       │   ├── registry_event/       → <slug>/
│       │   └── registry_set/         → <slug>/
│       └── sysmon/
│           └── sysmon_config_modification/ → <slug>/
├── rules-emerging-threats/           # Emerging threats
│   ├── 2025/
│   │   ├── Exploits/
│   │   │   └── CVE-2025-55182/      → <slug>/
│   │   └── Malware/
│   │       ├── Grixba/               → <slug>/
│   │       └── Shai-Hulud/           → <slug>/
│   └── 2026/
│       └── Exploits/
│           ├── CVE-2026-33829/       → <slug>/
│           └── RedSun/               → <slug>/
└── rules-threat-hunting/             # Threat hunting
    └── windows/
        └── image_load/               → <slug>/
```

Intermediate directories (`cisco/`, `windows/`, `builtin/`, etc.) reflect the SigmaHQ category hierarchy. The last directory before the files is always a **slug** derived from the rule YAML name.

## Regression directory contents

Each rule with regression contains a directory (slug) with:

```text
<slug>/
├── info.yml                    # Metadata + test results
├── <rule_id>.evtx              # Valid EVTX (EvtExportLog or pure-Rust writer)
└── <rule_id>.json              # Optional (regression.add_json_output) — raw event
```

The `<rule_id>` is always the **UUID** contained in `rule_metadata[0].id` of the `info.yml` file. It is never the directory name.

Variants: some rules (e.g., cisco) use `.raw` when the EVTX format is not applicable. Auditd rules use `.log` (complete original audit event lines). The data file + `info.yml` are the mandatory output; the `.json` is an optional extra.

## `info.yml` schema

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Test instance ID (distinct from the rule's rule_id) |
| `description` | string | Test description (often `"N/A"`) |
| `date` | string (ISO 8601) | Test creation date (`YYYY-MM-DD`) |
| `author` | string | Test author |
| `rule_metadata` | sequence | List of at least one element containing rule metadata |

### Optional fields

| Field | Type | Description |
|-------|------|-------------|
| `regression_tests_info` | sequence | Regression test details |

### `rule_metadata` structure

```yaml
rule_metadata:
  - id: <rule-UUID>           # Canonical SigmaHQ rule ID (UUID v4)
    title: <string>           # Rule title
```

`rule_metadata[0].id` is the **canonical ID**. This UUID uniquely identifies the rule across the entire system. It is used for:

- Naming data files (`.evtx`, `.log`, `.json`)
- Lookup key in Sigma engines
- Indexing in data structures

### `regression_tests_info` structure (optional)

```yaml
regression_tests_info:
  - name: Positive Detection Test
    type: evtx                  # or "raw" for cisco, "log" for Linux (auditd/syslog/sysmon)
    provider: <ProviderName>    # dynamically extracted from event's XML ProviderName (e.g., Microsoft-Windows-Sysmon, or "auditd")
    match_count: <int>          # Number of matches found
    path: regression_data/.../<rule_id>.evtx  # Relative path to the template
```

### Complete example

```yaml
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
description: N/A
date: 2024-01-15
author: sigmacatch
rule_metadata:
  - id: d059842b-6b9d-4ed1-b5c3-5b89143c6ede
    title: Suspicious BitsAdmin Download
regression_tests_info:
  - name: Positive Detection Test
    type: evtx
    provider: Microsoft-Windows-Sysmon
    match_count: 1
    path: regression_data/rules/windows/process_creation/proc_creation_win_bitsadmin_download/d059842b-6b9d-4ed1-b5c3-5b89143c6ede.evtx
```

## Naming conventions

### Directories

- The last directory (slug) is derived from the SigmaHQ rule YAML source file name
- Intermediate directories reflect the category hierarchy (`windows/process_creation/`, `cisco/aaa/`, etc.)
- Slugs are lowercase with underscores (`proc_creation_win_bitsadmin_download`)
- **The slug is never compared to the rule_id UUID**

### Data files

| File | Format | Name | Content |
|------|--------|------|---------|
| `info.yml` | YAML | Always `info.yml` | Metadata + results |
| `<rule_id>.evtx` | Binary | UUID v4 | Valid EVTX (EvtExportLog or pure-Rust writer; validated ≥ 1 record at write time) |
| `<rule_id>.log` | Text | UUID v4 | Complete event (multi-record auditd lines, syslog lines, or Sysmon-for-Linux XML) |
| `<rule_id>.json` | JSON | UUID v4 | Optional (`regression.add_json_output`) — raw event (nested Winevt JSON or flat Linux JSON) |

The `<rule_id>` in file names is always the UUID from `rule_metadata[0].id`.

## Validation rules

### rule_id consistency

The same UUID must appear in `rule_metadata[0].id` of `info.yml` and in the name of every present data file. If these values diverge, the set is inconsistent.

### Completeness

A set is **complete** if:

- `info.yml` exists
- the data file referenced by `regression_tests_info[0].path` exists and is valid (EVTX magic / non-empty text, size ≤ 64 MiB)

The auxiliary `.json` is not part of the validity check.

### info.yml format validation

For an `info.yml` to be valid:

1. The file must be UTF-8 (BOM allowed)
2. The `rule_metadata` field must be a non-empty sequence
3. `rule_metadata[0].id` must be a valid UUID v4 in `8-4-4-4-12` format (lowercase hex)
4. The root `id` in the YAML (instance ID) is ignored for rule_id validation

### Naming validation

- The parent directory name is **never** validated against the rule_id
- Data files must be named exactly `<rule_id>.<ext>`
- Hidden files (starting with `.`) are ignored

## Platforms

### Windows

The majority of rules (process_creation, file_event, registry, etc.) target Windows. The `.json` event files contain Windows-specific Sigma keys (`Image`, `CommandLine`, `ParentImage`, etc.).

### Cisco

Some network rules use native formats (`.raw` instead of `.json` + `.evtx`). The `provider` field in `regression_tests_info` may be absent.

### Linux (auditd / syslog / sysmon)

The `sigmacatch-linux` binary runs three collectors in parallel, each guarded by its source:

- **auditd** if `/var/log/audit/audit.log` exists: tails the file, parses records with `linux-audit-parser`, emits one event per record. Records sharing the same audit event id (`msg=audit(timestamp:sequence)`) are grouped: each event carries `event_raw` = all original lines of the audit event.
- **builtin syslog** tails every existing file among central (`/var/log/messages`, `/var/log/syslog`), authpriv (`/var/log/secure`, `/var/log/auth.log`) and cron (`/var/log/cron`, `/var/log/cron.log`): one RFC3164 line per event, flat `event_json` `{message, program, host, service}` with `service` derived from the program tag (`sshd` → `sshd`, `CRON` → `cron`, …) plus a per-file-group fallback (authpriv → `auth`, cron → `cron`). Lines tagged `sysmon` are excluded — handled by the dedicated collector.
- **Sysmon-for-Linux** keeps the central-syslog lines tagged `sysmon` whose body is winevt XML (`<Event>…</Event>`): the shared winevt parser produces the full nested field set and the Windows pipelines apply unchanged; logsource is resolved from the channel `Linux-Sysmon/Operational` → `product: linux`, `service: sysmon`. Truncated XML lines (rsyslog size limits) are skipped.

On hosts forwarding audit records into syslog (audisp/rsyslog), the same activity is captured twice through distinct pipelines — an auditd-based rule and a syslog-based rule can both produce regression data from it. In every case regression data uses `.log` (complete original lines). The provider written to `info.yml` comes from the event XML provider when present (`Linux-Sysmon` for Sysmon-for-Linux events), falling back to `auditd` for plain-text events.

### Emerging Threats

Rules specific to emerging threats, organized by year and type (Exploits, Malware). Same naming conventions as main rules.

### Threat Hunting

Threat hunting rules. Same naming conventions.
