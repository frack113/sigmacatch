# info.yml

Every set has an `info.yml`: it identifies the rule under test and points at
the data file. It is the entry point of the set — the data files are named
after `rule_metadata[0].id`, and `regression_tests_info[0].path` locates the
stored event.

## Required fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Test instance ID (distinct from the rule's rule_id) |
| `description` | string | Test description (often `"N/A"`) |
| `date` | string (ISO 8601) | Test creation date (`YYYY-MM-DD`) |
| `author` | string | Test author |
| `rule_metadata` | sequence | List of at least one element containing rule metadata |

## Optional fields

| Field | Type | Description |
|-------|------|-------------|
| `regression_tests_info` | sequence | Regression test details |

## `rule_metadata` structure

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

## `regression_tests_info` structure (optional)

```yaml
regression_tests_info:
    - name: Positive Detection Test
      type: evtx                  # raw for cisco; log for auditd/syslog/sysmon tail; json/ndjson for eBPF
      provider: <ProviderName>    # dynamically extracted from event's XML ProviderName (e.g., Microsoft-Windows-Sysmon, or "auditd")
      match_count: <int>          # Number of matches found
      path: regression_data/.../<rule_id>.evtx  # Relative path to the data file
```

`type` qualifies the file named by `path` — the accepted values and the
cross-check with the file extension are specified in
[Validation](validation.md#type-must-describe-the-data-file).

## Examples

### Windows (EVTX)

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

### Linux auditd (`type: log`)

Plain-text event without XML — fallback provider `auditd`:

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

### Linux Sysmon-for-Linux (`type: log`)

Provider extracted from the event XML:

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
