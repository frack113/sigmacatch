# Sigma Regression Data Format

Regression data format for Sigma rules, compatible with SigmaHQ.

## Purpose

A regression test set consists of a **triplet** per rule: an `info.yml` file (metadata), a `.json` file (raw event), and an `.evtx` file (Windows Event Log template). This triplet allows validating that a Sigma engine always produces the same results for a given rule against a known event.

## Directory tree

```
regression_data/
├── rules/                            # Main SigmaHQ rules
│   ├── cisco/
│   │   └── aaa/
│   │       └── cisco_cli_dot1x_disabled/
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

## Regression triplet

Each rule with regression contains a directory (slug) with exactly three files:

```
<slug>/
├── info.yml                    # Metadata + test results
├── <rule_id>.json              # Raw event (flat JSON)
└── <rule_id>.evtx              # Valid EVTX via EvtExportLog (or .xml fallback)
```

The `<rule_id>` is always the **UUID** contained in `rule_metadata[0].id` of the `info.yml` file. It is never the directory name.

Variant: some rules (e.g., cisco) use `.raw` instead of `.json` + `.evtx` when the EVTX format is not applicable.

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
- Naming `.json` and `.evtx` files
- Lookup key in Sigma engines
- Indexing in data structures

### `regression_tests_info` structure (optional)

```yaml
regression_tests_info:
  - name: Positive Detection Test
    type: evtx                  # or "raw" for some formats
    provider: <ProviderName>    # dynamically extracted from event's XML ProviderName (e.g., Microsoft-Windows-Sysmon)
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
| `<rule_id>.json` | JSON | UUID v4 | Raw event (flat JSON, Sigma keys) |
| `<rule_id>.evtx` | Binary | UUID v4 | Valid EVTX via EvtExportLog (or .xml fallback on failure) |

The `<rule_id>` in file names is always the UUID from `rule_metadata[0].id`.

## Validation rules

### rule_id consistency

The same UUID must appear in three places:
1. `rule_metadata[0].id` in `info.yml`
2. `.json` file name
3. `.evtx` file name

If these three values are not identical, the triplet is inconsistent.

### Triplet completeness

A triplet is **complete** if all three files exist in the same directory:
- `info.yml`
- `<rule_id>.json` (or `<rule_id>.raw`)
- `<rule_id>.evtx`

A triplet is **incomplete** if any file is missing.

### info.yml format validation

For an `info.yml` to be valid:
1. The file must be UTF-8 (BOM allowed)
2. The `rule_metadata` field must be a non-empty sequence
3. `rule_metadata[0].id` must be a valid UUID v4 in `8-4-4-4-12` format (lowercase hex)
4. The root `id` in the YAML (instance ID) is ignored for rule_id validation

### Naming validation

- The parent directory name is **never** validated against the rule_id
- `.json`/`.evtx` files must be named exactly `<rule_id>.<ext>`
- Hidden files (starting with `.`) are ignored

## Platforms

### Windows

The majority of rules (process_creation, file_event, registry, etc.) target Windows. The `.json` event files contain Windows-specific Sigma keys (`Image`, `CommandLine`, `ParentImage`, etc.).

### Cisco

Some network rules use native formats (`.raw` instead of `.json` + `.evtx`). The `provider` field in `regression_tests_info` may be absent.

### Emerging Threats

Rules specific to emerging threats, organized by year and type (Exploits, Malware). Same naming conventions as main rules.

### Threat Hunting

Threat hunting rules. Same naming conventions.
