# Architecture Reference

> Complete reference document — no need to read the source code.

---

## 1. Overview

Headless tool that captures real Windows events via **Windows Event Log API** (winevt), matches them against SigmaHQ rules, and outputs structured regression data.

**Complete cycle (sequential):**
1. Acquire SigmaHQ rules (gix clone/pull)
2. Load Sigma engine (rsigma-eval) with logsource filter
3. Collect Event Log events (winevt, configured channels)
4. Evaluate events against all loaded rules
5. Generate regression output (JSON + EVTX template + info.yml)

**Loop:** every 30s continuously.

**Platform:** Windows (winevt + Sysmon required). Linux/macOS: no-op stub.

---

## 2. Source tree

```
src/
├── main.rs              # Pipeline + Stats + AggregatedRule
├── config.rs            # YAML config (serde, Default) + LogConfig
├── logger.rs            # Two-layer tracing (stderr info + rolling file debug)
├── sigma/
│   ├── loader.rs        # SigmaRepo (gix) + find_rules_dirs()
│   └── engine.rs        # SigmaEngine + rule evaluation (resolve_logsource from mapping)
├── collector/
│   ├── mod.rs           # pub mod winevt
│   └── winevt.rs        # WinevtCollector (EvtQueryW, EvtNext, EvtRender)
├── evtx/
│   └── writer.rs        # write_evtx() via EvtExportLog API + .xml fallback
├── parser/
│   └── mod.rs           # XmlParser (Winevt XML → flat JSON)
└── regression/
    ├── mod.rs           # SkipSet, build_skip_set(), validate_rule_id(), triplet validation
    ├── generator.rs     # RegressionData, MatchEvent
    └── info_yml.rs      # InfoYml, RuleMetadata, RegressionTestInfo
```

---

## 3. Configuration

`config.yaml` (auto-created on first run):

```yaml
author: "username"          # whoami::username() by default
offline: false              # true = use existing sigma/ without git
log:
  level_file: "debug"       # tracing file level
```

**CLI flags:** `--create-config`, `--author <name>`, `--offline`

---

## 4. Pipeline detailed

### Stage 0 — Init

```
config.yaml → Config struct
    ↓
create_dir_all("sigma/", "regression_data/", "logs/")
    ↓
logger::init() → tracing subscriber (stderr info + file debug)
```

### Stage 1 — SigmaHQ Acquisition

```
SigmaRepo::new("sigma/")
    ↓
init() [async]
    ├── NO .git → gix clone https://github.com/SigmaHQ/sigma.git
    └── .git EXISTS → gix fetch + reset worktree → origin/master
         └── failure → WARN, continue with existing rules
```

### Stage 2 — Skip Set (existing rules)

```
build_skip_set(dirs, max_depth=64)
    ├── scan regression_data/rules/*/info.yml
    ├── scan sigma/regression_data/**/info.yml
    │     (excludes rules-compliance/ and rules_compliance/)
    ├── for each info.yml:
    │     ├── parse_info_yml() → rule_id (flexible: rule_metadata[0].id or root id)
    │     ├── validate_rule_id() → UUID v4 or [a-z0-9_-]+
    │     ├── validate_parent_folder() → parent folder == rule_id
    │     └── validate_triplet() → info.yml + .json + .evtx
    │           ├── complete → SkipSet::rules
    │           └── incomplete → SkipSet::incomplete (listed, not blocking)
    └── SkipSet { rules, incomplete, duplicates }
```

Rules with existing regression (complete or incomplete) → **excluded from Sigma engine** (sole allowed optimization).

### Stage 3 — Rule loading

```
find_rules_dirs("sigma/")
    → Vec<PathBuf> (rules, rules-*, excludes rules-compliance)
    ↓
For each .yml / .yaml:
    ├── parse_sigma_yaml() → Sigma rules
    ├── post-parse filter: rule.logsource.product == "windows" (or absent)
    ├── skip if rule_id in skip set
    ├── engine.add_collection() → rsigma-eval
    └── track rule_paths HashMap<rule_id, PathBuf>
    ↓
SigmaEngine in-memory (loaded rules + rule_paths)
```

### Cycle — Collection

```
WinevtCollector (channels: Security, System, Sysmon)
    ├── [Windows] EvtQueryW(channel="*") → EvtNext() → EvtRender() → XML
    │     ├── One task per channel (tokio::spawn)
    │     ├── XML → parse_event_xml() → WinevtEvent (carries pre-parsed event_json)
    │     └── mpsc::channel → main loop
    └── [non-Windows] Stub → Ok(vec![])
    ↓
Vec<WinevtEvent> { channel, event_id, raw_xml, event_json }
```

### Cycle — Evaluation

```
For each SensorEvent:
    ├── channel → LogSource { product: "windows", service, category }
    │     (mapping::resolve_logsource + channel/service priority)
    ├── event.event_json → flat serde_json::Value (pre-parsed by collector, XmlParser fallback if None)
    ├── engine.evaluate_event_with_logsource(event_value, logsource)
    │     → Vec<EvaluationResult> (rsigma-eval)
    └── For each match:
         ├── rule_id = match.header.rule_id
         ├── skip if rule_id in retired (already generated this cycle)
         ├── stats.matches_found++
         └── aggregated[rule_id].events.push((event_value, raw_xml, provider))
```

### Cycle — Generation

```
For each AggregatedRule in aggregated:
    ├── RegressionData::new(header, output_path, rule_rel_path, author)
    ├── exists() → skip if info.yml already exists
    ├── For each event: reg.add_event(event_json, raw_xml)
    ├── reg.generate()
    │     ├── Write <rule_id>.json (first event, pretty-printed JSON)
    │     ├── Write <rule_id>.evtx (EvtExportLog API, or .xml fallback)
    │     └── Write info.yml (InfoYml::new + save)
    ├── Append "regression_tests_path: ..." to source rule YAML
    └── retired.insert(rule_id)
```

**Output:**
```
regression_data/<rule_rel_path>/
├── <rule_id>.json      # first matching event (flat JSON)
├── <rule_id>.evtx      # valid EVTX via EvtWriteFile (Winevt XML)
└── info.yml            # SigmaHQ-compatible metadata
```

### Post-cycle

```
Sleep 30s → loop
Ctrl+C → running.store(false) → break
```

**Stats:** `{ events_processed, matches_found, regression_data_generated }`

---

## 5. Key data structures

### WinevtEvent

```rust
WinevtEvent {
    channel: String,            // Event Log channel name
    event_id: u32,              // EventID
    raw_xml: String,            // Full event XML (Winevt format)
    event_json: Option<serde_json::Value>,  // pre-parsed JSON from collector (XmlParser)
}
```

### InfoYml

```yaml
type: evtx
id: <uuid v4>
description: "N/A"
date: YYYY-MM-DD
author: <config.author>
rule_metadata:
  - id: <rule_id>
    title: <rule_title>
regression_tests_info:
  name: "Positive Detection Test"
  test_type: evtx
  channel: "Microsoft-Windows-Sysmon/Operational"
  match_count: 1
  path: <rule_rel_path>/<rule_id>.evtx
```

### RegressionData

```rust
RegressionData {
    header: RuleHeader,       // rule_id, title, etc.
    events: Vec<MatchEvent>,  // (event_json, raw_xml, channel, record_id, provider)
    output_path: PathBuf,
    rule_rel_path: Option<PathBuf>,
    author: Option<String>,
    description: Option<String>,
}

MatchEvent {
    event: Value,             // flat JSON of the event
    raw_xml: String,          // full Winevt XML (for EVTX)
    channel: String,          // Event Log channel name
    record_id: Option<u64>,   // EventRecordID
    provider: String,         // ProviderName extracted from event (e.g., Microsoft-Windows-Sysmon)
}
```

---

## 6. Key modules

### SigmaEngine (`sigma/engine.rs`)

- Loads rules from `rules*` dirs
- Post-parse filter: `rule.logsource.product` filters non-Windows rules after `parse_sigma_yaml`
- Skip-at-load = sole optimization (rules with existing `info.yml`)
- `LogSource` derived from Event Log channel + provider (resolve_logsource)
- `evaluate_event_with_logsource()` → `Vec<EvaluationResult>` via rsigma-eval

### EVTX Writer (`evtx/writer.rs`)

- **Windows**: `EvtExportLog` API (winevt) — re-queries the event by RecordID and exports to valid binary `.evtx`
  - `EvtExportLog(None, channel, query, path, EvtExportLogChannelPath | EvtExportLogOverwrite)`
  - Produces valid binary EVTX readable by hayabusa/chainsaw
  - **Known limitation**: race condition with log retention — if the event has been purged between collection and export, the call fails silently (`ERROR_EVT_QUERY_RESULT_STALE`)
- **Fallback**: writes raw XML as `.xml` (not `.evtx` — avoids producing invalid binary that would break downstream tools)
- **Non-Windows**: fallback raw XML write as `.xml`
- The companion `.json` file carries the actual data for Sigma matching

### Logger (`logger.rs`)

- **stderr layer**: `info` level, ANSI colors, filterable via `RUST_LOG`
- **file layer**: `debug` level (configurable), daily rotation
- `logs/sigmacatch.YYYY-MM-DD.log`

---

## 7. Architectural invariants

| Invariant | Detail |
|---|---|
| 100% sequential pipeline | rules → engine → collect → match → generate |
| All in RAM | in-memory aggregation before writing, no DB |
| One run = complete cycle | no "just collect" or "just generate" mode |
| Collection via Winevt | EvtQueryW → EvtNext → EvtRender, no ETW, no ferrisetw |
| LogSource from channel | Event Log channel via resolve_logsource (channel > provider > default) |
| Skip-at-load sole optimization | rules with `info.yml` excluded from engine |
| One event per test | `match_count: 1`, first event only |
| Output mirrors source | `regression_tests_path` added to source YAML |
| EVTX via EvtExportLog | Re-queries event by RecordID → valid binary EVTX. .xml fallback on failure. |

---

## 8. Dependencies

| Dependency | Usage |
|---|---|
| `gix` | git operations (clone/pull SigmaHQ) |
| `rsigma-eval` + `rsigma-parser` | Sigma rule loading/evaluation |
| `tokio` | async runtime |
| `tracing` + `tracing-subscriber` | logging |
| `serde` / `serde_json` / `serde_yaml` | config + event + regression serialization |
| `anyhow` | error handling |
| `chrono` | dates |
| `uuid` | UUID v4 for info.yml |
| `windows` | Winevt API (cfg-gated: windows only, features: Foundation, Com, Console, EventLog, Threading, Security) |

**Removed:** `ratatui`, `crossterm`, `quick-xml`, `winevt-writer`, `tdh`, `ntapi`

---

## 9. Build & Lint

```bash
cargo build --release
cargo clippy -- -W warnings
cargo xwin build --release --target x86_64-pc-windows-msvc   # cross-compile Windows
```

---

## 10. CLI

```
sigmacatch
    [--create-config]      # create config.yaml with defaults
    [--author <name>]      # override username
    [--offline]            # use existing sigma/ without git
```

---

## 11. Pipeline diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  config.yaml                                                            │
│    author, offline, log.level_file                                       │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 0 — INIT                                                         │
│  create_dir_all("sigma/", "regression_data/", "logs/")                 │
│  logger::init() → tracing (stderr info + file debug)                   │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 1 — SIGMAHQ ACQUISITION                                          │
│  SigmaRepo::new("sigma/")                                               │
│    ├── NO .git → gix clone SigmaHQ                                     │
│    └── .git EXISTS → gix fetch + reset → origin/master                │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 2 — SKIP SET                                                     │
│  build_skip_set(regression_data/rules/, sigma/regression_data/)        │
│    → validate triplet (info.yml + .json + .evtx)                       │
│    → validate rule_id format + parent folder match                     │
│    → SkipSet { rules, incomplete, duplicates }                        │
│  → HashSet<rule_id> (rules with existing regression)                   │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 3 — RULE LOADING                                                 │
│  find_rules_dirs("sigma/") → rules, rules-* (excl. rules-compliance)   │
│  For each .yml:                                                         │
│    ├── parse_sigma_yaml() → Sigma rules                                │
│    ├── post-parse filter: logsource.product == "windows" (or absent)  │
│    ├── skip if rule_id in skip set                                    │
│    └── engine.add_collection() → rsigma-eval                          │
│  → SigmaEngine in-memory + rule_paths HashMap                          │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — COLLECTION (winevt)                                            │
│  WinevtCollector (channels: Security, System, Sysmon)                  │
│    ├── Windows: EvtQueryW → EvtNext → EvtRender → XML                │
│    │     → parse_event_xml() → WinevtEvent                            │
│    └── non-Windows: Stub → Ok(vec![])                                 │
│  → Vec<WinevtEvent> { channel, event_id, raw_xml }                     │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — EVALUATION                                                     │
│  For each WinevtEvent:                                                  │
│    ├── event.event_json → flat JSON (pre-parsed, XmlParser fallback if None)
│    ├── provider → LogSource { product: "windows" }                    │
│    └── engine.evaluate_event_with_logsource()                         │
│         → Vec<EvaluationResult>                                        │
│  For each match:                                                        │
│    └── aggregated[rule_id].events.push((json, raw_xml, provider))     │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — GENERATION                                                     │
│  For each AggregatedRule:                                               │
│    ├── skip if rule_id in retired or existing info.yml                │
│    ├── RegressionData::new()                                           │
│    ├── reg.generate() → triplet:                                     │
│    │     ├── <rule_id>.json (first event, flat JSON)                  │
│    │     ├── <rule_id>.evtx (EvtExportLog, or .xml fallback)          │
│    │     └── info.yml (UUID v4, SigmaHQ metadata)                     │
│    └── append "regression_tests_path" to source YAML                  │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  POST-CYCLE                                                             │
│    sleep 30s → loop                                                     │
│  Ctrl+C → running.store(false) → break                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Final output:**
```
regression_data/<rule_rel_path>/
├── <rule_id>.json      # first matching event (flat JSON, Sigma keys)
├── <rule_id>.evtx      # valid EVTX via EvtExportLog (or .xml fallback)
└── info.yml            # type: evtx, rule_metadata, regression_tests_info
```
