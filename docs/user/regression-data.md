# Regression Data

sigmacatch produces regression data compatible with the
[SigmaHQ](https://github.com/SigmaHQ/sigma) repository format, ready for PR
submission: per rule, an `info.yml` (metadata) plus a **data file** that stores
the captured event. A validation tool replays the stored event through the
detection engine and verifies the rule still matches, so a rule change that
breaks a known detection is caught.

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
name.

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

Variants: some rules (e.g. cisco) use `.raw` when the EVTX format is not
applicable. The data file + `info.yml` are the mandatory output; for EVTX/log
data, a `.json` export is an optional extra.

## What the pipeline writes

### EVTX (Windows)

`<rule_id>.evtx` is produced by `EvtExportLog` (re-queries the event by
RecordID from the live log, short-backoff retries) or, for record-id-less
events, by the pure Rust EVTX writer (`evtx_writer` module of
`sigmacatch::regression`, deterministic, no retry). The exported file is
**validated** (re-parse ≥ 1 record); an empty/corrupt export (event rotated
out between collection and export) is an error: the pipeline skips the rule
for that cycle (no commit) and re-captures it later.

### eBPF JSON / NDJSON (Linux)

The eBPF collector writes `<rule_id>.json` as its **primary data file**:

- one event → a pretty-printed JSON document, `type: json`;
- several records → NDJSON, one compact JSON object per line, `type: ndjson`.

Auditd alerts remain `.log` (`type: log`) even when eBPF is active in the
same binary — the format is selected per alert, not globally. The `.json`
carries the nested `Event.System`/`Event.EventData` view used for matching.

### Auxiliary JSON

When the primary data file is `.evtx` or `.log`,
`regression.add_json_output: true` adds an auxiliary `.json` with the raw
event. Its shape depends on the producer: nested and a verbatim mirror of the
Winevt XML for Windows events, flat (`{message, program, host?}`, `host`
optional) for syslog and structured (`{stamp, type, node?, fields}`) for
auditd on Linux. A single record is a pretty-printed document; several
records are NDJSON. The validator (`regressiondata-check`) stream-parses both
layouts.

## Source rule annotation

The source Sigma rule YAML is also annotated with:

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```

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

`rule_metadata[0].id` is the **canonical ID**. This UUID uniquely identifies
the rule across the entire system. It is used for:

- Naming data files (`.evtx`, `.log`, `.json`)
- Lookup key in Sigma engines
- Indexing in data structures

### `regression_tests_info` structure (optional)

```yaml
regression_tests_info:
    - name: Positive Detection Test
      type: evtx                  # raw for cisco; log for auditd/syslog/sysmon tail; json/ndjson for eBPF
      provider: <ProviderName>    # dynamically extracted from event's XML ProviderName (e.g., Microsoft-Windows-Sysmon, or "auditd")
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

**auditd (`type: log`, fallback provider `auditd` — plain-text event without
XML):**

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
      type: log
      provider: auditd
      match_count: 1
      path: regression_data/rules/linux/auditd/execve/lnx_auditd_susp_cmds/1543ae20-cbdf-4ec1-8d12-7664d667a825.log
```

**Sysmon-for-Linux (`type: log`, provider extracted from the event XML):**

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

### Directories

- The last directory (slug) is derived from the SigmaHQ rule YAML source file name
- Intermediate directories reflect the category hierarchy (`windows/process_creation/`, `cisco/aaa/`, etc.)
- Slugs are lowercase with underscores (`proc_creation_win_bitsadmin_download`)
- **The slug is never compared to the rule_id UUID**

### Data files

| File | Format | Name | Content |
|------|--------|------|---------|
| `info.yml` | YAML | Always `info.yml` | Metadata + results |
| `<rule_id>.evtx` | Binary | UUID v4 | Valid EVTX (EvtExportLog or pure Rust writer; validated ≥ 1 record at write time) |
| `<rule_id>.log` | Text | UUID v4 | Complete event (multi-record auditd lines, syslog lines, or Sysmon-for-Linux XML) |
| `<rule_id>.json` | JSON/NDJSON | UUID v4 | Linux eBPF primary data (single pretty JSON document, or NDJSON for several records), or optional `regression.add_json_output` raw event (nested Winevt JSON or flat Linux JSON) |

The `<rule_id>` in file names is always the UUID from `rule_metadata[0].id`.

## Validation rules

### rule_id consistency

The same UUID must appear in `rule_metadata[0].id` of `info.yml` and in the
name of every present data file. If these values diverge, the set is
inconsistent.

### Completeness

A set is **complete** if:

- `info.yml` exists
- the data file referenced by `regression_tests_info[0].path` exists and is valid (EVTX magic / non-empty text, size ≤ 64 MiB)

For an EVTX/log data set, an auxiliary `.json` is not part of the validity
check. For eBPF, the `.json` named by `path` is the data file and must be
valid.

### `type` must describe the data file

`regression_tests_info[0].type` qualifies the file named by
`regression_tests_info[0].path` — nothing else. Accepted values are `evtx`,
`log`, `json`, `ndjson` and `raw`. `json` means one JSON document; `ndjson`
means one compact JSON object per line.

For EVTX/log data, enabling `regression.add_json_output` never changes
`type`. `type: ndjson` over an `.evtx` path is not a valid combination and is
resolved from the data-file extension. `type: ndjson` over a `.json` path is
the normal multi-record eBPF layout.

> **SigmaHQ spec vs sigmacatch extensions.** The upstream regression spec
> defines only four `type` values — `evtx`, `json`, `ndjson` and `jsonl` — and
> its runner skips every other value as an unknown test type. `log` and
> `raw` are sigmacatch extensions: entries declaring them validate and replay
> with `regressiondata-check`, but the upstream runner cannot read them.
> `regressiondata-check` reports the gap without failing the run, one line
> per distinct type:
>
> ```text
> [WARN] 12 test(s) declare type 'log', a sigmacatch extension outside the SigmaHQ regression spec (evtx/json/ndjson/jsonl); the upstream runner skips them
> ```

When `type` is unrecognised, readers infer the format from the data file's
extension rather than defaulting, so already-committed sets survive a bad
`type`. A `type` that is recognised but disagrees with the extension on disk
is reported as a warning.

### info.yml format validation

For an `info.yml` to be valid:

1. The file must be UTF-8 (BOM allowed)
2. The `rule_metadata` field must be a non-empty sequence
3. `rule_metadata[0].id` must be a parseable UUID; a hard error is raised only on unparsable values. Non-v4 or non-lowercase-canonical (`8-4-4-4-12`) ids are accepted with a warning — upstream SigmaHQ ships such ids and their regression entries must not be dropped
4. The root `id` in the YAML (instance ID) is ignored for rule_id validation

### Naming validation

- The parent directory name is **never** validated against the rule_id
- Data files must be named exactly `<rule_id>.<ext>`
- Hidden files (starting with `.`) are ignored

Unparsable `info.yml` files are skipped with a warning (never silently) so
they cannot fall out of the skip set unnoticed.

## Platforms

### Windows

The majority of rules (process_creation, file_event, registry, etc.) target
Windows. The `.json` event files contain Windows-specific keys (`Image`,
`CommandLine`, `ParentImage`, etc.).

### Cisco

Some network rules use native formats (`.raw` instead of `.json` + `.evtx`).
The `provider` field in `regression_tests_info` may be absent on read.

### Linux (auditd / syslog / sysmon / eBPF)

The auditd, syslog and Sysmon-tail collectors run in parallel, each guarded
by its source — the full specification (tailed files, guards, parsing) lives
in [architecture.md](../dev/architecture.md). Their regression data uses `.log`
(complete original lines: auditd records grouped by `timestamp:sequence`,
RFC3164 syslog lines, or Sysmon-for-Linux XML).

The eBPF collector uses `.json`: a single pretty-printed Sysmon-shaped event
(`type: json`) or NDJSON (`type: ndjson`) when several records are grouped.
When eBPF and auditd run in the same binary, auditd alerts still produce
`.log`.

On hosts forwarding audit records into syslog (audisp/rsyslog), both
pipelines capture the same activity: an auditd-based rule and a
syslog-based rule can both produce regression data from it. The provider
written to `info.yml` comes from the event XML when present
(`Linux-Sysmon` for Sysmon-for-Linux events), falling back to `auditd` for
plain-text events and `sigmacatch-ebpf` for eBPF events without a provider.

### Emerging Threats

Rules specific to emerging threats, organized by year and type (Exploits,
Malware). Same naming conventions as main rules.

### Threat Hunting

Threat hunting rules. Same naming conventions.
