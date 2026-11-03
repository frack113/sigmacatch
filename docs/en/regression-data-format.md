# Sigma Regression Data Format

Regression data format for Sigma rules, compatible with SigmaHQ.

## Objective

A regression set consists per rule of an `info.yml` file (metadata) and a **data file**
(`<rule_id>.evtx` for Windows, `<rule_id>.log` for Linux). An optional `.json` auxiliary
(raw event) can be added via the `regression.add_json_output` option (default: `false`). This
set allows validating that a Sigma engine always produces the same results for a given rule
against a known event.

## Tree

The output mirrors the SigmaHQ hierarchy under `rules/`, `rules-emerging-threats/` and
`rules-threat-hunting/`:

```text
regression_data/
├── rules/windows/process_creation/<slug>/            # main rules
├── rules/linux/auditd/execve/<slug>/
└── rules-emerging-threats/2026/Exploits/CVE-2026-33829/<slug>/
```

The intermediate directories mirror the SigmaHQ category hierarchy. The last folder before the
files is always a **slug** derived from the source Sigma YAML rule name.

## Content of a regression folder

Each rule with regression contains a folder (slug) with :

```text
<slug>/
├── info.yml                    # Metadata + test results
├── <rule_id>.evtx              # Valid EVTX (EvtExportLog or pure-Rust writer)
└── <rule_id>.json              # Optional (regression.add_json_output) — raw event
```

The `<rule_id>` is always the **UUID** contained in `rule_metadata[0].id` of the `info.yml`
file. It is never the folder name.

Variants: some rules (e.g. cisco) use `.raw` when the EVTX format is not applicable. Linux
rules use `.log` (complete original lines: auditd, syslog, or Sysmon-for-Linux XML). The data
file + `info.yml` constitute the mandatory output ; the `.json` is an optional supplement.

## `info.yml` schema

### Required fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Instance test identifier (distinct from the rule's rule_id) |
| `description` | string | Test description (often `"N/A"`) |
| `date` | string (ISO 8601) | Test creation date (`YYYY-MM-DD`) |
| `author` | string | Test author |
| `rule_metadata` | sequence | List of at least one element containing the rule metadata |

### Optional fields

| Field | Type | Description |
|---|---|---|
| `regression_tests_info` | sequence | Regression test details |

### `rule_metadata` structure

```yaml
rule_metadata:
    - id: <rule-UUID>           # Canonical SigmaHQ rule identifier (UUID v4)
      title: <string>           # Rule title
```

`rule_metadata[0].id` is the **canonical identifier**. It is used to :

- Name data files (`.evtx`, `.log`, `.json`)
- Serve as lookup key in the Sigma engines
- Index into data structures

### `regression_tests_info` structure (optional)

```yaml
regression_tests_info:
    - name: Positive Detection Test
      type: evtx                  # or "raw" for cisco, "log" for Linux (auditd/syslog/sysmon)
      provider: <ProviderName>    # dynamically extracted from the XML ProviderName (e.g. Microsoft-Windows-Sysmon, or "auditd")
      match_count: <int>          # Number of matches found
      path: regression_data/.../<rule_id>.evtx  # Relative path to the data file
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

### `.log` examples (Linux)

**auditd (`type: log`, fallback provider `auditd` — raw text event without XML) :**

```yaml
id: 60ff02c2-a649-436c-972d-7c6fe6af8711
description: N/A
date: 2026-08-20
author: frack113
rule_metadata:
    - id: 1543ae20-cbdf-4ec1-8d12-7664d667a825
      title: Suspicious Commands Linux
regression_tests_info:
    - name: Positive Detection Test
    - type: log
      provider: auditd
      match_count: 1
      path: regression_data/rules/linux/auditd/execve/lnx_auditd_susp_cmds/1543ae20-cbdf-4ec1-8d12-7664d667a825.log
```

**Sysmon-for-Linux (`type: log`, provider extracted from the event XML) :**

```yaml
id: 8f2a5c31-9d64-4b7e-a1c2-3f5d8e90b7aa
description: N/A
date: 2026-08-23
author: frack113
rule_metadata:
    - id: f74107df-b6c6-4e80-bf00-4170b658162b
      title: Sudo Privilege Escalation CVE-2019-14287
regression_tests_info:
    - name: Positive Detection Test
      type: log
      provider: Linux-Sysmon
      match_count: 1
      path: regression_data/rules/linux/builtin/lnx_sudo_privilege_escalation_cve_2019_14287/f74107df-b6c6-4e80-bf00-4170b658162b.log
```

## Naming conventions

### Folders

- The last folder (slug) is derived from the source Sigma YAML rule filename
- The intermediate folders mirror the category hierarchy (`windows/process_creation/`, `cisco/aaa/`, etc.)
- Slugs are lowercase with underscores (`proc_creation_win_bitsadmin_download`)
- **The slug is never compared to the rule_id UUID**

### Data files

| File | Format | Name | Content |
|---------|--------|-----|---------|
| `info.yml` | YAML | Always `info.yml` | Metadata + results |
| `<rule_id>.evtx` | Binary | UUID v4 | Valid EVTX (EvtExportLog or pure-Rust writer; validated ≥ 1 record at write) |
| `<rule_id>.log` | Text | UUID v4 | Full event (original auditd lines multi-record, syslog lines, or Sysmon-for-Linux XML) |
| `<rule_id>.json` | JSON | UUID v4 | Optional (`regression.add_json_output`) — raw event (nested Winevt JSON or flat Linux JSON; single JSON or JSONL, exactly one trailing newline, validated by `regressiondata-check`) |

The `<rule_id>` in the file names is always the UUID from `rule_metadata[0].id`.

## Validation rules

### Rule_id coherence

The same UUID must appear in `rule_metadata[0].id` of `info.yml` and in the name of each data
file present. If these values diverge, the set is inconsistent.

### Completeness

A set is **complete** if :

- `info.yml` exists
- the data file referenced by `regression_tests_info[0].path` exists and is valid (EVTX magic / non-empty text, size ≤ 64 MiB)
- the `.json` auxiliary does not count for validity.

### `type` must describe the data file

`regression_tests_info[0].type` qualifies the file named by
`regression_tests_info[0].path` — and nothing else. The only values accepted
are `evtx`, `log`, `json` and `raw`, matching the data file extension.
(`json` is the auxiliary artifact type, not the data file type — activating
`regression.add_json_output` never changes `type`. `type: ndjson` with an `.evtx`
path is not a valid combination : `ndjson` describes the *auxiliary export form*
(single document per event, JSONL for several), not the data file.)

> **SigmaHQ spec and sigmacatch extensions.** The upstream regression spec defines only
> four `type` values — `evtx`, `json`, `ndjson` and `jsonl` — and its runner ignores any
> other value as an unknown test type. `log` and `raw` are sigmacatch extensions : entries
> declaring them are validated and replayed with `regressiondata-check`, but the upstream
> runner does not know them. `regressiondata-check` flags this drift without failing the
> run, on a single line per distinct type :

> ```text
> [WARN] 12 test(s) declare type 'log', a sigmacatch extension outside the SigmaHQ regression spec (evtx/json/ndjson/jsonl); the upstream runner skips them
> ```

When `type` is unknown, the readers deduce the format from the data file's extension
instead of taking a default value, so that already-validated sets survive a wrong `type`.
A recognized `type` that disagrees with the extension present on disk is reported with a warning.

### `info.yml` format validation

For an `info.yml` to be valid :

1. The file must be UTF-8 (BOM allowed)
2. The `rule_metadata` field must be a non-empty sequence
3. `rule_metadata[0].id` must be a parseable UUID ; a hard error is raised only on unparseable
   values. Non-v4 or non-lowercase-canonical (`8-4-4-4-12`) ids are accepted with a warning —
   upstream SigmaHQ ships some and their regression entries must not be discarded
4. The root `id` in the YAML (instance ID) is ignored for rule_id validation.

### Naming validation

- The parent folder name is **never** validated against the rule_id
- Data files must be named exactly `<rule_id>.<ext>`
- Hidden files (starting with `.`) are ignored.

## Platforms

### Windows

The majority of rules (process_creation, file_event, registry, etc.) target Windows. The
`.json` events contain Windows-specific keys (`Image`, `CommandLine`, `ParentImage`, etc.).

### Cisco

Some rules use native formats (`.raw` instead of `.json` + `.evtx`). The `provider` field in
`regression_tests_info` may be absent.

### Linux (auditd / syslog / sysmon)

Three collectors run in parallel, each kept by its source — the complete specification
(files tailed, guards, parsing) lives in [architecture.md](architecture.md). All of their
regression data uses `.log` (complete original lines: auditd records grouped by
`timestamp:sequence`, syslog lines RFC3164, or Sysmon-for-Linux XML). On hosts that relay
audit records to syslog (audisp/rsyslog), both pipelines capture the same activity: an
auditd-based rule and a syslog-based rule can both produce regression data from it. The
provider written into `info.yml` comes from the event XML when it exists (`Linux-Sysmon` for
Sysmon-for-Linux events), with a fallback to `auditd` for raw-text events.

### Emerging Threats

Rules specific to emerging threats, organized by year and type (Exploits, Malware). Same
naming conventions as the main rules.

### Threat Hunting

Rules for threat hunting. Same naming conventions.
