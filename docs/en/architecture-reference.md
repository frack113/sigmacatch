# Architecture Reference

> Complete reference document — no need to read the source code.

---

## 1. Overview

Headless tool that captures real Windows events via **Windows Event Log API** (winevt), matches them against SigmaHQ rules, and outputs structured regression data.

**Complete cycle (sequential):**
1. Acquire SigmaHQ rules (grit-lib clone/pull)
2. Load Sigma engine (rsigma-eval) with bloom pre-filter + LogSourceExtractor
3. Collect Event Log events (winevt, configured channels)
4. Evaluate events against all loaded rules
5. Generate regression output (JSON + EVTX template + info.yml)

**Loop:** every 30s continuously.

**Platform:** Windows (winevt + Sysmon required). Linux/macOS: no-op stub.

---

## 2. Source tree

```
sigmacatch/
├── Cargo.toml                     # Racine workspace (7 crates)
├── sigmacatch/                    # Crate binaire
│   └── src/
│       ├── main.rs                # Pipeline + Stats + AggregatedRule
│       ├── lib.rs                 # Déclarations pub mod
│       ├── config.rs              # Config, SigmaFilterConfig, MinStatus, MinLevel
│       ├── repo.rs                # wrapper grit-lib + SigmaRepo (clone/fetch/push/commit/branch)
│       ├── github/
│       │   ├── commit.rs          # commit_all_rules avec author env + fallback
│       │   └── fork.rs            # ForkConfig, check_fork_exists, detect_fork
│       └── bin/evtx_check.rs      # Outil de validation batch
├── crates/
│   ├── detection-engine/          # Wrapper rsigma-eval + pipelines (windows.yml, flatten_winevt.yml) + bloom/logsource
│   ├── input-evtx/                # Parse EVTX files → Event (inject_logsource_fields at creation)
│   ├── input-windows-channels/    # Multi-channel Winevt collector (EventProducer) + inject_logsource_fields
│   ├── sigma-regression/          # SkipSet, RegressionData, InfoYml, triplet validation
│   └── sigmacatch-types/          # Shared types: Event, Alert, RegressionHeader + XML parsing + logsource mapping tables (phf)
```

---

## 3. Configuration

`config.yaml` (auto-créé au premier run, complété automatiquement si la section `sigma` manque) :

```yaml
git:
  author: "sigmacatch"        # GitHub username for contrib workflow
  email: "you@example.com"    # required for git commits
  github_token: ""            # GitHub token (or GITHUB_TOKEN env var) — required for HTTP transport
  transport: http             # http or ssh
  ssh_key_path: ""            # path to SSH private key (optional, only needed for SSH)
log:
  level_file: "debug"
sigma:
  min_status: "stable"      # minimum rule status (inclusive): unsupported < deprecated < experimental < test < stable
  min_level: "critical"     # minimum rule level (inclusive): informational < low < medium < high < critical
```

**Filtrage des règles :** `min_status` et `min_level` sont appliqués au chargement. Les règles dont `status`/`level` est inférieur au seuil sont exclues du moteur. Les règles sans champ `status` ou `level` sont toujours acceptées.

**CLI flags :** `--author <name>`

---

## 4. Pipeline detailed

### Stage 0 — Init

```
config.yaml → Config struct
    ↓
create_dir_all("sigma/", "regression_data/", "regression_data/rules/", "logs/")
    ↓
logger::init() → tracing subscriber (stderr info + file debug)
```

### Stage 1 — SigmaHQ Acquisition

```
SigmaRepo::new("sigma/")
    ↓
with_remote_url(fork URL)
    ↓
init() [async]
    ├── NO .git → grit-lib clone <remote_url> (fork or SigmaHQ)
    └── .git EXISTS → set remote origin URL (if fork) → grit-lib fetch
         └── failure → WARN, continue with existing rules
    ↓
create_branch("sigmacatch-contrib/YYYYMMDD_<author>")
    └── create_branch() → grit-lib create ref + switch HEAD to branch (or switch if exists)
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
Sequential walk: collect all .yml / .yaml paths (cheap, no parse)
    ↓
Parallel parse + filter (rayon):
    For each file:
    ├── parse_sigma_yaml() → Sigma rules
    ├── post-parse filter: rule.logsource.product == "windows" (or absent)
    ├── status/level filter: rule.status >= min_status AND rule.level >= min_level
    ├── skip if rule_id in skip set
    └── cross-file dedupe (first occurrence, walk order, wins)
    ↓
Sequential merge: accumulate surviving rules into ONE SigmaCollection,
then a SINGLE engine.add_collection() → rsigma-eval (one index rebuild)
    ↓
SigmaEngine in-memory (loaded rules + rule_paths)
```

> **Performance note:** `rsigma-eval`'s `add_collection()` rebuilds the whole
> rule index on every call. The old per-file `add_collection` was O(N²)
> (N rebuilds of an N-rule index). Batching all surviving rules into one
> collection drops rule loading from ~33s to ~0.2s for the full SigmaHQ
> set (~2800 rules). Parsing itself runs in parallel via `rayon`.

> A startup rule table is displayed (rules loaded, rules skipped, active services/categories).

**Status/level filtering:** rules whose `status` < `min_status` or `level` < `min_level` are excluded (only if the field is present). Default `min_status=stable`, `min_level=critical` — very restrictive, loads only stable/critical rules.

### Cycle — Collection

```
EventCollector (channels resolved from rules via resolve_channels_from_rules)
    ├── [Windows] EvtQueryW(channel="*") → EvtNext() → EvtRender() → XML
    │     → parse_winevt_xml() → Event (carries event_json + event_raw)
    │     → event.inject_logsource_fields() (injects product/service/category)
    └── [non-Windows] Stub → Ok(vec![])
    ↓
Vec<Event> { event_json, event_raw }
```

### Cycle — Evaluation

```
For each Event:
    ├── event.event_json contains product/service/category (injected by collector)
    ├── LogSourceExtractor reads these fields → prunes incompatible rules
    ├── bloom pre-filter prunes impossible substring matchers
     ├── engine.put_events(events) → engine.process_events() → engine.get_alerts()
    │     → Vec<EvaluationResult> (rsigma-eval)
    └── For each match:
         ├── rule_id = match.header.rule_id
         ├── skip if rule_id in retired (already generated this cycle)
         ├── stats.matches_found++
         └── aggregated[rule_id].alerts.push(alert)
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
<output_base>/<rule_rel_path>/
    ├── <rule_id>.json      # first matching event (flat JSON)
    ├── <rule_id>.evtx      # valid EVTX via EvtExportLog (or .xml fallback)
    └── info.yml            # SigmaHQ-compatible metadata
```
- Non-contrib: `output_base` = `regression_data/` (project root)
- Contrib: `output_base` = `sigma/regression_data/` (inside sigma repo, committed to fork)

### Post-cycle

```
commit_all_rules() → batch grit-lib commit to sigma repo
Sleep 30s → loop
Ctrl+C → running.store(false) → break
push_branch() → fetch + compare + normal push to fork (skip if diverged)
```

**Stats:** `{ events_processed, matches_found, regression_data_generated }`

---

## 5. Key data structures

### Event

```rust
Event {
    event_json: serde_json::Value,    // parsed event JSON (nested)
    event_raw: Vec<u8>,               // raw source bytes (XML)
}
```

Methods: `channel()`, `event_id()`, `provider()`, `from_xml()`, `inject_logsource_fields()`

The `event_json` field contains logsource fields (`product`, `service`, `category`) injected by `inject_logsource_fields()` called by collectors. The `LogSourceExtractor` from rsigma-eval reads these fields to prune incompatible rules.

### Alert

```rust
Alert {
    rule_id: String,
    rule_title: String,
    severity: String,
    event_json: serde_json::Value,
    event_raw: Vec<u8>,
}
```

### InfoYml

```yaml
id: <uuid v4>
description: "N/A"
date: YYYY-MM-DD
author: <config.author>
rule_metadata:
  - id: <rule_id>
    title: <rule_title>
regression_tests_info:
  - name: "Positive Detection Test"
    type: evtx
    provider: "Microsoft-Windows-Sysmon"
    match_count: 1
    path: <rule_rel_path>/<rule_id>.evtx
```

### RegressionData

```rust
RegressionData {
    header: RegressionHeader,    // rule_id, title, etc.
    alerts: Vec<Alert>,          // matched events
    output_path: PathBuf,
    rule_rel_path: Option<PathBuf>,
    author: Option<String>,
    description: Option<String>,
    is_contrib: bool,
}
```

---

## 6. Key modules

### DetectionEngine (`detection-engine/src/lib.rs`)

- Loads pipelines (flatten_winevt.yml + windows.yml) and rules via rsigma-eval
- Enables bloom pre-filter + LogSourceExtractor in `new()` for evaluation optimization
- `put_events()` / `process_events()` / `get_alerts()` for the FIFO cycle
- `load_collection()` to bulk-load a SigmaCollection
- `from_rules_dir()` / `from_rules_dirs()` for quick setup from filesystem
- Independent: depends only on `sigmacatch-types` + `rsigma-eval` (no input-windows-channels)

### EventCollector (`input-windows-channels/src/collector.rs`)

- Multi-channel Windows Event Log collector, implements `EventProducer`
- `new(channels)` → creates collector for specified channels
- `run(self, tx)` → launches collection and sends events via mpsc
- Windows: EvtQueryW → EvtNext → EvtRender → XML → parse_winevt_xml → Event → inject_logsource_fields
- Non-Windows: stub (no-op)
- Logsource mapping tables (channel → service, provider → service, category) imported from `sigmacatch-types`

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

---

## 7. Dependencies

| Dependency | Usage |
|---|---|---|
| `grit-lib` | all git operations (clone, fetch, push, branch, commit, checkout) via HTTP + SSH, pure Rust |
| `reqwest` (blocking) | HTTP client for fork detection + API calls (not used for git transport) |
| `rsigma-eval` + `rsigma-parser` | Sigma rule loading/evaluation |
| `tokio` | async runtime |
| `tracing` + `tracing-subscriber` | logging |
| `serde` / `serde_json` / `serde_yaml` | config + event + regression serialization |
| `anyhow` | error handling |
| `chrono` | dates |
| `uuid` | UUID v4 for info.yml |
| `rayon` | parallel rule file parsing |
| `phf` | static hash maps for taxonomy tables (in sigmacatch-types) |
| `evtx` | EVTX file parsing (evtx_check binary + input-evtx crate) |
| `roxmltree` | XML parsing for Winevt events (in sigmacatch-types) |
| `windows` | Winevt API (cfg-gated: windows only, features: Foundation, Com, Console, EventLog, Threading, Security) |

**Removed:** `ratatui`, `crossterm`, `quick-xml`, `winevt-writer`, `tdh`, `ntapi`, `ferrisetw`

---

## 8. Build & Lint

```bash
cargo build --release
cargo clippy -- -W warnings
cargo xwin build --release --target x86_64-pc-windows-msvc   # cross-compile Windows
```

---

## 9. CLI

```
sigmacatch
    [--author <name>]      # override username
    [--dry-run]            # git diagnostics only (no collection)
```

Config is auto-created on first run with defaults. Edit `config.yaml` before running.

---

## 10. Pipeline diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│  config.yaml                                                            │
│    author, email, log.level_file                                         │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 0 — INIT                                                         │
│  create_dir_all("sigma/", "regression_data/",                           │
│                "regression_data/rules/", "logs/")                       │
│  logger::init() → tracing (stderr info + file debug)                   │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 1 — SIGMAHQ ACQUISITION                                          │
│  SigmaRepo::new("sigma/")                                               │
│    ├── [contrib] set fork remote URL                                   │
│    ├── NO .git → grit-lib clone (fork or SigmaHQ)                           │
│    └── .git EXISTS → set remote origin → grit-lib fetch                    │
│    ↓                                                                   │
│    [contrib] create_branch("sigmacatch-contrib/...") + switch HEAD      │
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
│    ├── status/level filter: rule.status >= min_status AND ...         │
│    ├── skip if rule_id in skip set                                    │
│    └── engine.add_collection() → rsigma-eval                          │
│  → SigmaEngine in-memory + rule_paths HashMap                          │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — COLLECTION (winevt)                                            │
│  EventCollector (all Windows channels)                                  │
│    ├── Windows: EvtQueryW → EvtNext → EvtRender → XML                │
│    │     → parse_winevt_xml() → Event                                  │
│    │     → event.inject_logsource_fields()                             │
│    └── non-Windows: Stub → Ok(vec![])                                 │
│  → Vec<Event> { event_json, event_raw }                                │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — EVALUATION                                                     │
│  For each Event:                                                        │
│    ├── event.event_json contains product/service/category              │
│    ├── LogSourceExtractor + bloom pre-filter optimize evaluation      │
 │    └── engine.put_events() → process_events() → get_alerts()          │
│         → Vec<EvaluationResult>                                        │
│  For each match:                                                        │
│    └── aggregated[rule_id].alerts.push(alert)                         │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — GENERATION                                                     │
│  For each AggregatedRule:                                               │
│    ├── skip if rule_id in retired or existing info.yml                │
│    ├── RegressionData::new(output_base, ...)                          │
│    │   output_base = regression_data/ or sigma/regression_data/       │
│    ├── reg.generate() → triplet:                                     │
│    │     ├── <rule_id>.json (first event, flat JSON)                  │
│    │     ├── <rule_id>.evtx (EvtExportLog, or .xml fallback)          │
│    │     └── info.yml (UUID v4, SigmaHQ metadata)                     │
│    └── append "regression_tests_path" to source YAML                  │
│  ↓                                                                     │
│  commit_all_rules() → batch grit-lib commit to sigma repo                  │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  POST-CYCLE                                                             │
│    sleep 30s → loop                                                     │
│  Ctrl+C → running.store(false) → break                                  │
│    push_branch() → fetch + compare + normal push to fork                │
└─────────────────────────────────────────────────────────────────────────┘
```

**Final output:**
```
<output_base>/<rule_rel_path>/
├── <rule_id>.json      # first matching event (flat JSON, Sigma keys)
├── <rule_id>.evtx      # valid EVTX via EvtExportLog (or .xml fallback)
└── info.yml            # type: evtx, rule_metadata, regression_tests_info
```
- Non-contrib: `output_base` = `regression_data/` (project root)
- Contrib: `output_base` = `sigma/regression_data/` (inside sigma repo, committed to fork)
