# Data Files

The data file stores the captured event. Its format depends on the collector
that produced it: `.evtx` for Windows, `.log` for the Linux line collectors,
`.json`/NDJSON for eBPF, and `.raw` for a few network rules. The format is
selected **per alert**, not globally — when eBPF and auditd run in the same
binary, auditd alerts still produce `.log`.

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

The `<rule_id>` in file names is always the UUID from `rule_metadata[0].id`
of the set's `info.yml` (see [info.yml](info-yml.md)).

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

The `.json` carries the nested `Event.System`/`Event.EventData` view used for
matching.

### Auxiliary JSON

When the primary data file is `.evtx` or `.log`,
`regression.add_json_output: true` adds an auxiliary `.json` with the raw
event. Its shape depends on the producer: nested and a verbatim mirror of the
Winevt XML for Windows events, flat (`{message, program, host?}`, `host`
optional) for syslog and structured (`{stamp, type, node?, fields}`) for
auditd on Linux. A single record is a pretty-printed document; several
records are NDJSON. The validator (`regressiondata-check`) stream-parses both
layouts.

## Platforms

### Windows

The majority of rules (process_creation, file_event, registry, etc.) target
Windows. The `.json` event files contain Windows-specific keys (`Image`,
`CommandLine`, `ParentImage`, etc.).

### Cisco

Some network rules use native formats (`.raw` instead of `.json` + `.evtx`)
when the EVTX format is not applicable. The `provider` field in
`regression_tests_info` may be absent on read.

### Linux (auditd / syslog / sysmon / eBPF)

The auditd, syslog and Sysmon-tail collectors run in parallel, each guarded
by its source — the full specification (tailed files, guards, parsing) lives
in [collectors.md](../dev/collectors.md). Their regression data uses
`.log` (complete original lines: auditd records grouped by
`timestamp:sequence`, RFC3164 syslog lines, or Sysmon-for-Linux XML).

The eBPF collector uses `.json`: a single pretty-printed Sysmon-shaped event
(`type: json`) or NDJSON (`type: ndjson`) when several records are grouped.

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
