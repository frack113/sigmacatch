# Architecture Reference

> Complete reference document — no need to read the source code.

---

## 1. Overview

Headless tool that captures real Windows events via **Windows Event Log API** (winevt), matches them against SigmaHQ rules, and outputs structured regression data.

**Continuous run (one process until Ctrl+C):**
1. Load config + init logger
2. Acquire SigmaHQ rules (grit-lib clone/fetch) + create branch
3. Build the skip set from existing regression data
4. Load the Sigma engine (rsigma-eval) with bloom pre-filter + LogSourceExtractor
5. Resolve channels from the loaded rules
6. Spawn a continuous collector (winevt, one task per channel)
7. Evaluate every event against all loaded rules (FIFO API)
8. Every 30s: generate regression output for matched rules, commit to the fork
9. On Ctrl+C: final flush → commit → push branch to fork

**Platform:** Windows (winevt + Sysmon required for rich events). Linux/macOS: collector is a no-op stub — the pipeline still runs end-to-end for testing.

---

## 2. Source tree

```
sigmacatch/
├── Cargo.toml                     # Workspace root (10 packages)
├── sigmacatch/                    # Binary crate
│   └── src/
│       ├── main.rs                # Orchestration: continuous loop + process_and_generate + commit/push
│       └── bin/evtx_check.rs      # Batch validation of Sigma engine against .evtx regression data
└── crates/
    ├── sigmacatch-config/         # Config YAML, CLI parsing, custom_channels.yaml, dry-run git diagnostics
    ├── sigmacatch-logger/         # Two-layer tracing subscriber (stderr info + daily rolling file debug)
    ├── sigmacatch-rule/           # SigmahqRules: load (parse_sigma_yaml), filter, dedupe, remove_id, channels()
    ├── sigmacatch-detection/      # DetectionEngine wrapper + embedded pipelines (windows.yml, flatten_winevt.yml)
    ├── input-windows-channels/    # Multi-channel Winevt collector (EventProducer) + logsource resolution
    ├── sigmacatch-regression/     # SigmahqRegression, InfoYml, RegressionData, triplet validation
    ├── sigmacatch-types/          # Shared types: Event, Alert, RegressionHeader, Product + XML parsing + logsource mapping tables
    ├── sigmacatch-repo/           # grit-lib wrapper: SigmaRepo, git operations
    └── input-evtx/                # EVTX file parser → Event (used by evtx_check)
```

---

## 3. Configuration

`config.yaml` (auto-created with defaults on first run; the program exits after creation until you edit it — `serde(default)`):

```yaml
git:
  author: "sigmacatch"        # GitHub username for the contrib workflow (must be set)
  email: "you@example.com"    # required for git commits (must contain '@')
  github_token: ""            # GitHub token (or GITHUB_TOKEN env var) — required for HTTP transport
  transport: http             # http (default) or ssh (ssh not implemented on Windows)
  ssh_key_path: ""            # path to SSH private key (optional, only needed for SSH)
  sigma_repo_url: "https://github.com/SigmaHQ/sigma.git"
  sigma_repo_path: "sigma"    # local path to the sigma repo (relative, no '..' traversal, not absolute)
log:
  level_file: "debug"
sigma:
  product: windows            # windows, linux, or macos
  min_status: "stable"        # minimum rule status (inclusive): unsupported < deprecated < experimental < test < stable
  min_level: "critical"       # minimum rule level (inclusive): informational < low < medium < high < critical
  max_rule_size: 1048576      # bytes (1MB default, min 1024, max 10MB)
```

**Rule filtering:** `product`, `min_status`, `min_level` and `author` are applied by `SigmahqRules::filter()`.
Rules whose `status`/`level` is below the threshold are excluded (only if the field is present);
rules without `status`/`level` are always accepted. If 0 rules remain, the program bails out.

**Validation:** `git.author` must be a valid GitHub username (alphanumeric + hyphens), `git.email`
is required, HTTP transport requires a token (config or env), and `sigma_repo_path` is validated
against traversal/absolute paths.

**CLI flags:** `--author <name>`, `--dry-run`, `--channels-only`, `--all-rules`.

---

## 4. Pipeline detailed

### Step 1 — Init

```
parse_args() → CliArgs
    ↓
Config::load_with_cli("config.yaml", cli)
    ├── missing → write defaults → exit(1) with instructions
    └── --author <name> overrides git.author before validation
    ↓
--dry-run → dry_run_git() (token/fork/API/info-refs diagnostics) → exit
    ↓
[windows] setup_console() (UTF-8 codepage + VT processing)
    ↓
init_logger(&config) → tracing (stderr info + daily rolling file debug)
```

### Step 2 — Repo acquisition

```
ensure_dirs() → create <sigma_repo_path>/ and logs/
    ↓
fork_url = "https://github.com/{author}/sigma"
    ↓
SigmaRepo::new()
    ├── set_info_user(author, email)
    ├── set_info_http(token) | set_info_ssh(key_path)
    ├── set_remote_url(fork_url) → init() [async]
    └── set_working_branch(branch_name) → switch_to_working_branch()
```

### Step 3 — Skip set (existing regression)

```
SigmahqRegression::new()            # loads ./sigma/regression_data
    └── scans all info.yml (walk, depth 64, skips symlinks)
        └── lenient: missing dir → empty, not an error
    ↓
existing_rules: HashSet<Uuid> = regression.get_sigma_id().collect()
    └── empty when --all-rules
    ↓
SigmahqRules::new()                 # loads ./sigma
    ├── find_rules_dirs() → rules, rules-* (excludes rules-compliance, index.yml)
    ├── sequential walk, parse_sigma_yaml() per file
    ├── cross-file dedupe by rule id (first occurrence wins)
    └── for each id in existing_rules → rules.remove_id(&id)
    ↓
rules = rules.filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size })
    ├── stats() → rules_loaded, filtered_product/status/level/author
    └── 0 rules loaded → bail with a clear error message
```

> Rules with existing regression data are excluded from the Sigma engine — this skip-at-load
> is the only load-time optimization. After generation, a rule is removed and the engine is
> reloaded in one batch (see Step 7).

### Step 4 — Channel resolution

```
custom_map = load_custom_channel_mapping("custom_channels.yaml")   # missing/empty → {}
    ↓
cycle_channels = rules.channels(&custom_map)
    ├── resolve_channels(): logsource service:category → channel list (deduped)
    └── 0 channels → warn + return Ok (nothing to collect)
    ↓
DetectionEngine::new(&rules)
    ├── loads embedded pipelines (flatten_winevt.yml, windows.yml) once
    ├── enables bloom pre-filter + LogSourceExtractor
    └── --channels-only → print channels + exit
```

### Step 5 — Continuous collection

```
output_base = <sigma_repo_path>/regression_data
clean_partial_artifacts(&output_base)     # removes dirs with json/evtx but no info.yml
    ↓
let (tx, rx) = mpsc::channel::<Event>(100_000)
    ↓
EventCollector::new(cycle_channels).run(tx, stop)   # tokio task, one task per channel
```

**Per-channel loop (`collect_continuous`, spawned with `spawn_blocking`):**

```
loop (until stop):
    query = "*" if last_record_id == 0
            else "*[System[EventRecordID > {last_record_id}]]"
    EvtQuery(channel, query)
        ├── ERROR_EVT_CHANNEL_NOT_FOUND → error! once → exclude permanently (return)
        └── other error → warn! + sleep 5s → retry
    loop:
        EvtNext(batch of 32, 5s timeout)
            ├── idle timeout / no more items → break (re-query)
            └── error → warn! + sleep 5s → break
        for each handle: EvtRender(EventXml) → Event::from_xml → inject_logsource_fields()
            └── tx.blocking_send(event)
        MAX_EVENTS (100k) reached → stop initial drain
    if 0 sent:
        ├── cycle_fetched > 0 → warn! "fetched N but 0 sent — dropped during render/parse"
        ├── first cycle → info! "initial query OK — 0 events"
        ├── else heartbeat → info! "still alive" (every 60s)
        └── record-id rollover probe (every 30 empty cycles) → reset last_record_id if needed
    else:
        ├── first drain → info! "initial drain collected N events"
        └── else progress → info! (every 10s)
```

The collector stops when `stop` is set (Ctrl+C) or the receiver is dropped. On non-Windows, each
channel task is a no-op stub.

### Step 6 — Continuous event loop

```
generate_interval = 30s (first tick skipped immediately)
    ↓
loop:
    tokio::select! {
        shutdown_rx.changed()            → info "Shutting down" → break
        Some(event) = rx.recv()          → engine.put_events(vec![event])
        _ = generate_interval.tick()     → process_and_generate()
                                               → commit_files() if files created
    }
```

### Step 7 — process_and_generate

```
engine.process_events() → engine.get_alerts()
    ├── alerts empty → return (no "evaluation complete" log)
    ├── log stats: events_processed, matches_found (unique rules), alerts_count
    └── for each alert:
        regression.add(&alert) → Option<Vec<String>>
            ├── None if rule already retired / Uuid::nil() / info.yml exists
            └── Some(files):
                ├── RegressionData::for_rule(header, output_path, rule_rel_path, author, description)
                ├── write <rule_id>.json (first matching event, pretty JSON)
                ├── write <rule_id>.evtx via EvtExportLog (or .xml fallback)
                ├── write info.yml
                ├── append "regression_tests_path" to the source rule YAML
                └── retire the rule (regression.retired + rules.remove_id)
    └── retired rules → engine.reload_rules(rules)   # ONE batch reload
```

**Output:**
```
<sigma_repo_path>/regression_data/<rule_rel_path>/
    ├── <rule_id>.json      # first matching event (flat JSON)
    ├── <rule_id>.evtx      # valid EVTX via EvtExportLog (or .xml fallback)
    └── info.yml            # SigmaHQ-compatible metadata
```

`<rule_rel_path>` mirrors the rule path under `sigma/rules/` (e.g.
`rules/windows/builtin/security/win_security_foo/`). The output always lives inside the sigma
repo and is committed to the fork.

### Step 8 — Shutdown / commit / push

```
Ctrl+C → shutdown_rx.set(true)
    ↓
Final flush:
    await collector task (stops → drops Sender clones)
    drain remaining rx → engine.put_events
    ↓
process_and_generate() → commit_files() if files
    ↓
push(sigma_repo_path, branch_name, transport, token) → fork
    └── success → "Next step: create PR at https://github.com/SigmaHQ/sigma/pulls"
```

---

## 5. Key data structures

### Event (`sigmacatch-types`)

```rust
Event {
    event_json: serde_json::Value,   // parsed event JSON (nested)
    event_raw: Vec<u8>,              // raw source bytes (XML)
}
```

Methods: `from_xml()`, `channel()`, `provider()`, `record_id()`, `inject_logsource_fields()`.
The collector calls `inject_logsource_fields()` which injects `product`, `service`, `category`
into `event_json`; the engine's `LogSourceExtractor` reads these fields to prune incompatible rules.

### Alert (`sigmacatch-types`)

```rust
Alert {
    rule_id: Uuid,               // parsed from the Sigma rule id
    rule_title: String,
    description: Option<String>,
    rule_path: Option<PathBuf>,  // source rule YAML path (relative to sigma repo)
    severity: String,
    event_json: serde_json::Value,
    event_raw: Vec<u8>,
}
```

### SigmahqRegression (`sigmacatch-regression`)

```rust
struct SigmahqRegression {
    entries: Vec<(PathBuf, InfoYml, RegressionEntry)>,
    author: String,
    output_path: Option<PathBuf>,   // default ./sigma/regression_data
    retired: HashSet<Uuid>,
}
```

API: `new()` / `new_from_path()` (lenient), `set_author()` / `author()`, `len()` / `is_empty()`,
`iter()` / `infos()` / `entries()` / `get_entry()`, `get_sigma_id() -> Vec<Uuid>`,
`get_raw_data(index)`, `add(&Alert) -> Option<Vec<String>>`.

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

---

## 6. Key modules

### DetectionEngine (`crates/sigmacatch-detection/src/lib.rs`)

- Loads embedded pipelines (`flatten_winevt.yml` + `windows.yml`) and rules via rsigma-eval
- Enables bloom pre-filter + LogSourceExtractor in `new()` for evaluation optimization
- FIFO cycle: `put_events()` / `process_events()` / `get_alerts()`
- `reload_rules(&SigmahqRules)` — batch reload after retiring rules
- `rule_count()`, `stats()` (EngineStats), `explain_rule(rule_id, event)`, `save_hir` / `load_hir`
- Depends on `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`

### SigmahqRules (`crates/sigmacatch-rule/src/lib.rs`)

- `new()` (hardcoded `./sigma`) / `new_from_path()` — walk + parse + dedupe
- `filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size })` → LoadStats
- `remove_id(&Uuid)`, `get(&Uuid)`, `channels(&custom_map)`, `to_collection()`

### EventCollector (`crates/input-windows-channels/src/collector.rs`)

- Multi-channel Windows Event Log collector, implements `EventProducer`
- `new(channels)` → `run(self, tx, stop)` async; one blocking task per channel
- Windows: EvtQuery → EvtNext → EvtRender → `Event::from_xml` → `inject_logsource_fields`
- Non-Windows: no-op stub
- Observability: permanent exclusion on `ERROR_EVT_CHANNEL_NOT_FOUND` (single `error!`),
  liveness logs ("initial query OK", "still alive" every 60s, progress every 10s),
  `warn!` when events are fetched but dropped at render/parse, record-id rollover detection

### EVTX Writer (`sigmacatch-regression/src/evtx.rs`)

- **Windows**: `EvtExportLog` API (winevt) — re-queries the event by RecordID and exports a valid binary `.evtx`
  - `EvtExportLog(None, channel, query, path, EvtExportLogChannelPath | EvtExportLogOverwrite)`
  - **Known limitation**: race condition with log retention — if the event has been purged between collection and export, the call fails silently (`ERROR_EVT_QUERY_RESULT_STALE`)
- **Fallback**: raw XML written as `.xml` (not `.evtx` — avoids an invalid binary that would break downstream tools)
- **Non-Windows**: raw XML fallback as `.xml`

### Logger (`crates/sigmacatch-logger/src/lib.rs`)

- **stderr layer**: `info` level, ANSI colors, filterable via `RUST_LOG`
- **file layer**: `debug` level (configurable), daily rotation
- `logs/sigmacatch.YYYY-MM-DD.log`

---

## 7. Dependencies

| Dependency | Usage |
|---|---|
| `grit-lib` | all git operations (clone, fetch, push, branch, commit, checkout) via HTTP, pure Rust |
| `reqwest` (blocking + async) | HTTP client for git transport |
| `rsigma-eval` + `rsigma-parser` | Sigma rule loading/evaluation |
| `tokio` | async runtime |
| `tracing` + `tracing-subscriber` | logging |
| `serde` / `serde_json` / `serde_yaml` | config + event + regression serialization |
| `anyhow` | error handling |
| `chrono` | dates |
| `uuid` | UUID v4 for info.yml + rule IDs |
| `rayon` | parallel rule file parsing |
| `phf` | static hash maps for taxonomy tables (in `sigmacatch-types`) |
| `evtx` | EVTX file parsing (evtx_check binary + input-evtx crate) |
| `roxmltree` | XML parsing for Winevt events (in `sigmacatch-types`) |
| `windows` | Winevt API (cfg-gated: windows only, features: Foundation, System, Security, Com, Console, Threading) |
| `tempfile` (dev) | integration tests |

**Removed:** `ratatui`, `crossterm`, `quick-xml`, `winevt-writer`, `tdh`, `ntapi`, `ferrisetw`

---

## 8. Build & Lint

```bash
cargo fmt --check
cargo clippy -- -W warnings
cargo test --workspace
cargo build --release
cargo xwin build --release --target x86_64-pc-windows-msvc   # cross-compile Windows
```

---

## 9. CLI

```
sigmacatch
    [--author <name>]      # override git.author from config
    [--dry-run]            # git diagnostics only (no collection)
    [--channels-only]      # print resolved channels and exit
    [--all-rules]          # disable the skip set (load every rule)
```

Config is auto-created on first run with defaults. Edit `config.yaml` before running.
