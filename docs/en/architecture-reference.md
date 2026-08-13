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
8. Every 30s: generate regression output for matched rules, commit (per rule) + push (if contrib) to the fork
9. On Ctrl+C: final flush → commit → push branch to fork (only when `git.contrib: true`)

**Platform:** Windows (winevt + Sysmon required for rich events). Linux/macOS: collector is a no-op stub — the pipeline still runs end-to-end for testing.

---

## 2. Source tree

```text
sigmacatch/
├── Cargo.toml                     # Workspace root (11 packages)
├── sigmacatch/                    # Binary crate
│   └── src/
│       └── main.rs                # Orchestration: continuous loop + process_and_generate + commit/push
├── tools/                    # Dev tools (check_dry_run, check_channels, list_rules, check_filter, check_evtx, get_atomic, coverage)
└── crates/
    ├── sigmacatch-config/         # Config YAML, CLI parsing, custom_channels.yaml, dry-run git diagnostics (check_dry_run)
    ├── sigmacatch-logger/         # Two-layer tracing subscriber (stderr info + daily rolling file debug)
    ├── sigmacatch-rule/           # SigmahqRules: load (parse_sigma_yaml), filter, dedupe, remove_id
    ├── sigmacatch-detection/      # DetectionEngine wrapper + embedded pipelines (windows.yml, flatten_winevt.yml) + channel_resolver
    ├── input-windows-channels/    # Multi-channel Winevt collector (EventProducer)
    ├── sigmacatch-regression/     # SigmahqRegression, InfoYml, RegressionData, triplet validation
    ├── sigmacatch-types/          # Shared types: Event, Alert, RegressionHeader, Product + XML parsing + logsource mapping tables
    ├── sigmacatch-repo/           # grit-lib wrapper: SigmaRepo, git operations
    └── input-evtx/                # EVTX file parser → Event (used by tools)
```

---

## 3. Configuration

`config.yaml` (auto-created with defaults on first run; the program exits after creation until you edit it — `serde(default)`):

```yaml
git:
  author: "sigmacatch"        # GitHub username for the contrib workflow (must be set)
  email: "you@example.com"    # required for git commits (must contain '@')
  github_token: ""            # GitHub token (or GITHUB_TOKEN env var) — required for HTTP transport
  transport: http             # http (default, token) or ssh (private key)
  ssh_key_path: ""            # path to SSH private key (optional, only needed for SSH)
  sigma_repo_url: "https://github.com/SigmaHQ/sigma.git"
  sigma_repo_path: "sigma"    # local path to the sigma repo (relative, no '..' traversal, not absolute)
  offline: false              # true = skip pull at startup (existing repo required). false (default) = pull
  contrib: false              # true = push to the remote fork. false (default) = local commits only
log:
  level_file: "debug"
filter:
  product: windows            # windows, linux, or macos
  min_status: "stable"        # minimum rule status (inclusive): unsupported < deprecated < experimental < test < stable
  min_level: "critical"       # minimum rule level (inclusive): informational < low < medium < high < critical
  author: ""                  # filter rules by author (optional, empty = no filter)
  max_rule_size: 1048576      # bytes (1MB default, min 1024, max 10MB)
regression:
  max_failed_cycles: 3        # block a rule (no more re-capture) after N consecutive EVTX failure cycles (min 1)
```

**Rule filtering:** `product`, `min_status`, `min_level` and `author` are applied by `SigmahqRules::filter()`.
Rules whose `status`/`level` is below the threshold are excluded (only if the field is present);
rules without `status`/`level` are always accepted. If 0 rules remain, the program bails out.

**Validation:** `git.author` must be a valid GitHub username (alphanumeric + hyphens), `git.email`
is required, HTTP transport requires a token (config or `GITHUB_TOKEN` env) when `needs_network()`
is true — i.e. `offline: false` or `contrib: true`; a fully offline run (`offline: true` +
`contrib: false`) needs no token. `sigma_repo_path` is validated against traversal/absolute paths.

**Offline / contrib:** `offline: true` uses the existing repo as-is (no pull, complete repo required).
`contrib: true` enables the push to the fork at the end; by default (`false`) commits stay local.
The CLI flags `--offline` / `--contrib` force these values to `true`.

**SSH transport:** `git.transport: ssh` clones/fetches/pushes via the `ssh_key_path` private key. At
startup, `ensure_ssh_host_config()` (`transport.rs`) writes the `IdentityFile`/`UserKnownHostsFile`
directives into `~/.ssh/config` (idempotent, **atomic write** tmp + rename); on Windows the `ssh`
executable is resolved via standard paths (Windows OpenSSH, Git for Windows) and used as a direct
exec (`SshCommand::Program`, no shell). A **failed SSH pull is final** (no HTTPS fallback): the error
message categorizes the cause (missing `ssh` binary or invalid key) and points to `transport: http` —
an HTTP retry only happens with the config switched to HTTP.
When `ssh_key_path` is set, every regression commit is **signed** with pure-Rust ed25519
(`ssh-key`): the `gpgsig` header is inserted between the committer line and the message, like
`git commit -S` with `gpg.format = ssh`, so GitHub shows the commit as "Verified".

**CLI flags:** `--author <name>`, `-a`/`--all-rules`, `-o`/`--offline`, `-c`/`--contrib`, `-v`/`--verbose`, `--help` / `-h`. The diagnostics (git dry-run, channels, rule list) are `tools` tools: `check_dry_run`, `check_channels`, `list_rules`.

---

## 4. Pipeline detailed

### Step 1 — Init

```text
parse_args() → CliArgs
    ↓
Config::load_with_cli("config.yaml", cli)
    ├── missing → write defaults → exit(1) with instructions
    └── --author <name> overrides git.author before validation
    ↓
[windows] setup_console() (UTF-8 codepage + VT processing)
    ↓
init_logger(&config) → tracing (stderr info + daily rolling file debug)
```

### Step 2 — Repo acquisition

```text
ensure_dirs() → create <sigma_repo_path>/ and logs/
    ↓
fork_url = "https://github.com/{author}/sigma"
    ↓
SigmaRepo::new()
    ├── set_info_user(author, email)
    ├── set_info_http(token) | set_info_ssh(key_path)
    ├── [ssh] ensure_ssh_host_config(key_path)   # writes IdentityFile into ~/.ssh/config (warn on failure)
    ├── [ssh_key_path set] set_signing_key(key_path)   # signs every commit (ed25519, gpgsig)
    ├── set_git_operations(offline, contrib)   # controls pull at startup + final push
    ├── set_remote_url(fork_url) → init() [async]
    │       ├── incomplete/missing repo + offline → actionable bail
    │       ├── existing repo → narrow pull of current branch (skipped if offline)
    │       │       └── HEAD already on working branch (same-day re-run) → skip the master switch
    │       └── otherwise → full clone (full-history, protocol v2) + pack
    ├── set_working_branch(branch_name)         # fetch target branch (skipped if offline) + create_branch
    │   └── switch_to_working_branch()          # materializes the branch tree (exact commit mirror)
    └── check_remote_working_branch()   # guard: rejects orphan/amputated same-day branch
```

### Post-processing: loose-object pack

The clone/fetch through grit-lib (`http_fetch`) writes every received object as a **loose**
file in `.git/objects/xx/` (~131K files, ~650 MB for the Sigma repo) — grit has no
`git gc --auto` equivalent. After every clone/fetch (HTTP clone, SSH clone, HTTP pull,
SSH pull), `pack_loose_objects()` (`crates/sigmacatch-repo/src/plumbing/pack.rs`)
consolidates:

- collect loose objects (sorted by OID);
- zlib compression (default level, **no delta**) **parallelized** (rayon, 16K chunks),
  then serialize a **V2** pack + index `.idx` (magic `\xfftOc`, fanout, sorted OIDs,
  CRC32 table, offset table, SHA-1 checksums);
- delete loose files + empty `xx/` directories;
- observability: server progress messages (`remote: Enumerating objects…`) are relayed
  to the log during download.

Result: `.git/` drops from ~650 MB to ~218 MB (3x), `git fsck --full --strict` is clean,
objects remain readable through the ODB (loose **or** pack).

**Benchmark vs native `git clone`** (fork `frack113/sigma`, master branch, Linux 24 cores):

| | native `git clone` | sigmacatch (grit + pack) |
|---|---|---|
| Fresh clone time | ~3s | ~70s (fetch ~50s + pack ~17s) |
| `.git/` | 52 MB | 218 MB |
| Pack | 47 MB (deltas) | 215 MB (no delta) |

Why: native git writes the server's delta-compressed pack **directly**; grit unpacks
everything to loose files, then we re-compress **without deltas**. The download itself is
identical (~47 MB). The cost is paid **once** at first clone — subsequent pulls only
transfer deltas (sub-second when nothing changed). On a slow VM the first clone can take
several minutes.

### Step 3 — Skip set (existing regression)

```text
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
> reloaded in one batch (see Step 7). The skip set is built from the worktree ∪ the remote
> `sigmacatch/*` branches (pending PRs, see git.md); `<uuid>.evtx` blobs are validated (parse
> ≥ 1 record, and ≤ 64 MiB) so empty/corrupt/oversized data does not skip the rule (re-captured).

### Step 4 — Channel resolution

```text
custom_map = load_custom_channel_mapping("custom_channels.yaml")   # missing/empty → {}
    ↓
DetectionEngine::new(&rules)
    ├── loads embedded pipelines (flatten_winevt.yml, windows.yml) once
    ├── enables bloom pre-filter + LogSourceExtractor
    ↓
cycle_channels = engine.resolve_channels(&custom_map)
    ├── reads post-pipeline CompiledRule.logsource → service:category → channel list (deduped, sorted)
    └── 0 channels → warn + return Ok (nothing to collect)
```

### Step 5 — Continuous collection

```text
output_base = <sigma_repo_path>/regression_data
clean_partial_artifacts(&output_base)     # removes dirs with json/evtx but no info.yml
    ↓
let (tx, rx) = mpsc::channel::<Event>(100_000)
    ↓
EventCollector::new(cycle_channels).run(tx, stop)   # tokio task, one task per channel
```

**Per-channel loop (`collect_continuous`, spawned with `spawn_blocking`):**

```text
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

```text
generate_interval = 30s (first tick skipped immediately)
    ↓
loop:
    tokio::select! {
        shutdown_rx.changed()            → info "Shutting down" → break
        Some(event) = rx.recv()          → engine.put_events(vec![event])
        _ = generate_interval.tick()     → process_and_generate()
                                               → upload_regression() if files created
    }
```

### Step 7 — process_and_generate

```text
engine.process_events() → engine.get_alerts()
    ├── alerts empty → return (no "evaluation complete" log)
    ├── log stats: events_processed, matches_found (unique rules), alerts_count
    └── for each alert:
        regression.add(&alert) → Option<Vec<String>>
            ├── None if rule already retired / Uuid::nil() / valid info.yml exists
            ├── EVTX export failure → None too: rule stays loaded, re-captured later
            └── Some(files):
                ├── RegressionData::for_rule(header, output_path, rule_rel_path, author, description)
                ├── write <rule_id>.json (event_json_raw of first matching event, pretty JSON)
                ├── write <rule_id>.evtx via EvtExportLog (validated ≥ 1 record + retry)
                ├── write info.yml
                ├── append "regression_tests_path" to the source rule YAML
                └── retire the rule (regression.retired + rules.remove_id)
    └── retired rules → engine.reload_rules(rules)   # ONE batch reload
    ↓
returns batches: Vec<(Uuid, Vec<String>)>   # (rule_id, written files) — empty if no alerts
    ↓
upload_regression() → upload_rule_batches()   # in sigmacatch-repo
     ├── one commit per rule: "🧪 test: add regression data for rule {rule_id}"
    ├── commit/push failure → rollback local branch to pre-batch tip
    └── SINGLE push if git.contrib: true (otherwise local commits only)
        └── success → "Next step: create PR at https://github.com/SigmaHQ/sigma/pulls"
```

**Output:**

```text
<sigma_repo_path>/regression_data/<rule_rel_path>/
    ├── <rule_id>.json      # first matching event (raw Winevt JSON, original EventData key names)
    ├── <rule_id>.evtx      # valid EVTX via EvtExportLog (non-Windows: no data generated)
    └── info.yml            # SigmaHQ-compatible metadata
```

`<rule_rel_path>` mirrors the rule path under `sigma/rules/` (e.g.
`rules/windows/builtin/security/win_security_foo/`). The output always lives inside the sigma
repo and is committed to the fork when `git.contrib: true` (local commits otherwise).

### Step 8 — Shutdown / commit / push

```text
Ctrl+C → shutdown_rx.set(true)
    ↓
Final flush:
    await collector task (30s timeout) → drain remaining rx → engine.put_events
    ↓
process_and_generate() → upload_regression() if files
     ├── per-rule commit ("🧪 test: add regression data for rule {id}")
    └── push() to fork if git.contrib: true
        └── success → "Next step: create PR at https://github.com/SigmaHQ/sigma/pulls"
```

---

## 5. Key data structures

### Event (`sigmacatch-types`)

```rust
Event {
    event_json_raw: serde_json::Value,  // raw Winevt JSON (original EventData key names, spaces kept) — used for regression output
    event_json: serde_json::Value,      // transformed JSON for Sigma detection (EventData spaces stripped)
    event_raw: Vec<u8>,                 // raw source bytes (XML)
}
```

Methods: `from_xml()`, `new()`, `record_id()`, `inject_logsource_fields()` (`channel()`,
`provider()` and `event_id()` are private). The collector calls `inject_logsource_fields()` which
injects `product`, `service`, `category` into `event_json`; the engine's `LogSourceExtractor` reads
these fields to prune incompatible rules.

### Alert (`sigmacatch-types`)

```rust
Alert {
    rule_id: Uuid,               // parsed from the Sigma rule id
    rule_title: String,
    description: Option<String>,
    rule_path: Option<PathBuf>,  // source rule YAML path (relative to sigma repo)
    severity: String,
    event_json_raw: serde_json::Value,  // raw Winevt JSON (original key names) — written to <rule_id>.json
    event_json: serde_json::Value,      // transformed JSON for Sigma detection
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
- `remove_id(&Uuid)`, `get(&Uuid)`, `rules()` / `iter()`, `to_collection()`, `rule_paths()`
- Channel resolution no longer lives here — it moved to `DetectionEngine::resolve_channels` (§10)

### EventCollector (`crates/input-windows-channels/src/lib.rs`)

- Multi-channel Windows Event Log collector, implements `EventProducer` (single module, no more `collector.rs`)
- `new(channels)` → `run(self, tx, stop)` async; one blocking task per channel
- Windows: EvtQuery → EvtNext (batch of 32, 5s timeout) → EvtRender → `Event::from_xml` → `inject_logsource_fields`
- Non-Windows: no-op stub
- Observability: permanent exclusion on `ERROR_EVT_CHANNEL_NOT_FOUND` (single `error!`),
  liveness logs ("initial query OK", "still alive" every 60s, progress every 10s),
  `warn!` when events are fetched but dropped at render/parse, record-id rollover detection

### EVTX Writer (`sigmacatch-regression/src/evtx.rs`)

- **Windows**: `EvtExportLog` API (winevt) — re-queries the event by RecordID and exports a valid binary `.evtx`
  - `EvtExportLog(None, channel, query, path, EvtExportLogChannelPath | EvtExportLogOverwrite)`
  - **Validation**: the exported file is re-parsed (`input_evtx::parse_evtx_file`) and must contain ≥ 1 record.
    `EvtExportLog` reports success even when the query matched 0 events (header-only file) — an empty or
    corrupt file is a failure, not a success.
  - **Retry**: 4 attempts total (1 initial + 3 retries) with short backoff (2s/5s/10s) — the retention race is often transient.
  - **On failure** the partial `.json` is deleted, an error is returned, the rule is skipped this cycle
    (no commit) and re-captured on a later cycle.
  - **Known limitation**: race condition with log retention — if the event has been purged between collection
    and export, the call fails silently (`ERROR_EVT_QUERY_RESULT_STALE`)
- **Self-healing**: rules whose committed data is invalid (empty EVTX) are excluded from the skip set
  (`get_sigma_id` via `data_file_is_valid`, and `pending_regression_rule_ids` via `.evtx` blob validation)
  → regenerated on the next run.
- **Non-Windows**: no data is generated (the Winevt collector is a stub) and `write_evtx` errors.

### Logger (`crates/sigmacatch-logger/src/lib.rs`)

- **stderr layer**: `error` level by default, `info` with `-v`/`--verbose`, ANSI colors, filterable via `RUST_LOG`
- **file layer**: `debug` level (configurable), daily rotation
- `logs/sigmacatch.YYYY-MM-DD.log`

---

## 7. Dependencies

| Dependency | Usage |
|---|---|
| `grit-lib` | all git operations (clone, fetch, push, branch, commit, checkout) via HTTP (token) and SSH (key), pure Rust |
| `reqwest` (blocking + async) | HTTP client for git transport |
| `ssh-key` | ed25519 commit signing (`gpgsig` header, pure Rust) |
| `zeroize` | zeroes secrets in memory (GitHub token) |
| `rsigma-eval` + `rsigma-parser` | Sigma rule loading/evaluation |
| `tokio` | async runtime |
| `tracing` + `tracing-subscriber` | logging |
| `serde` / `serde_json` / `serde_yaml` | config + event + regression serialization |
| `anyhow` | error handling |
| `chrono` | dates |
| `uuid` | UUID v4 for info.yml + rule IDs |
| `phf` | static hash maps for taxonomy tables (in `sigmacatch-types`) + channel resolution (in `sigmacatch-detection/src/channel_resolver.rs`) |
| `evtx` | EVTX file parsing (input-evtx crate, used by tools/check_evtx) |
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

```text
sigmacatch
    [-a], [--all-rules]    # disables the skip set (loads all rules)
    [-c], [--contrib]      # enables push to the remote fork
    [-o], [--offline]      # skips pull at startup (forces offline)
    [-v], [--verbose]      # shows info-level logs on stderr
    [--author <name>]      # overrides git.author from config
    [--help], [-h]         # shows help and exits
```

Diagnostics moved to `tools`:

```text
check_dry_run              # git diagnostics (token, fork, API, info/refs, repo state)
check_channels             # print the resolved channels
list_rules                 # print the loaded rules (id, title, status, level, techniques, path, ART link)
check_filter               # validate SigmaFilterConfig against the rules (ground truth)
check_evtx                 # validate the regression data (evtx + json + engine match)
get_atomic                 # generate run_atomic.ps (Invoke-AtomicTest) for rules without regression data
coverage                   # rule coverage stats (local + pending remote branches)
```

Config is auto-created on first run with defaults. Edit `config.yaml` before running.

---

## 10. Embedded pipelines & channel resolution

### `windows.yml` (`crates/sigmacatch-detection/pipelines/`)

Embedded transformation pipeline (loaded via `include_str!` in `sigmacatch-detection`), applied to every rule before compilation:

- Maps `logsource.category` → Sysmon EventID conditions via `add_condition`, gated by `rule_conditions` (`type: logsource` with `category`, `product`, `service` filters; all conditions combined with AND).
- **rsigma-eval v0.21+** : `add_condition` accepts YAML sequences (`conditions: {EventID: [17, 18]}`) whose values are OR-linked, matching the pySigma `AddConditionTransformation` (breaking API : `AddCondition.conditions` is `HashMap<String, Vec<SigmaValue>>`). A multi-EventID category is a single transformation entry (e.g. `wmi_event` → `[19, 20, 21]`).
- **EventType registry filters** : `registry_add` = EventID 12 + `EventType: CreateKey`, `registry_set` = EventID 13 + `EventType: SetValue`, `registry_rename` = EventID 14 + `EventType: RenameKey`. **`registry_delete` has NO EventType filter** — EventID 12 carries both `DeleteKey` and `DeleteValue` (rsigma-eval constraint), so it matches on EventID 12 alone.
- **`change_logsource` final (post-add_condition)** : one `service: sysmon` block per routed category, same logsource gate `(category, product: windows)` as its `add_condition` → makes the post-pipeline logsource usable by `channel_resolver` (zero duplicated category → service mapping).
- `prepend` : adds the condition before the existing detection (`new AND existing`) for short-circuit optimization.
- **Supported transformations** : `field_name_mapping`, `field_name_prefix_mapping`, `field_name_prefix`, `field_name_suffix`, `drop_detection_item`, `add_condition`, `change_logsource`, `replace_string`, `value_placeholders`, `wildcard_placeholders`, `query_expression_placeholders`, `set_state`, `rule_failure`, `detection_item_failure`, `field_name_transform`, `hashes_fields`, `map_string`, `set_value`, `convert_type`, `regex`, `add_field`, `remove_field`, `set_field`, `set_custom_attribute`, `case_transformation`, `nest`, `include`.

`flatten_winevt.yml` : flattens the nested Winevt XML structure for Sigma evaluation. Pipeline loaded once at engine init, applied to every rule before compilation.

### Channel resolution (`crates/sigmacatch-detection/src/channel_resolver.rs`)

- **Post-pipeline logsource** : `resolve_channels` reads `CompiledRule.logsource` (post-pipeline, publicly exposed by rsigma-eval 0.21) via `DetectionEngine::resolve_channels(&custom_map)` in `main.rs` — resolved at engine creation time, no extra cost (no re-transform).
- `SERVICE_CHANNELS` : static `phf::Map<service, &[channel]>` — service → Windows Event Log channels mapping (runtime, not a generated table).
- `CATEGORY_CHANNELS` : categories the pipeline does NOT route (`ps_classic_*`, `ps_module`, `ps_script`).
- Lookup : `service` present → `SERVICE_CHANNELS[service]` + `custom_map` (from `custom_channels.yaml`, `channel → service`) ; else `category` → `CATEGORY_CHANNELS[category]`.
- Sysmon categories are **not** in the table — the pipeline rewrites them to `service: sysmon` (single source of truth in `windows.yml`).
- Unmapped logsource → `warn!` (per logsource), no channels ; non-Windows rules are ignored. Result : deduped, sorted channel list.
- `sigmacatch-types` remains owner of the inverse mapping tables (`CHANNEL_TO_SERVICE`, `PROVIDER_TO_SERVICE`, `CHANNEL_EVENT_TO_CATEGORY`, `CHANNEL_EVENT_TO_SUBCATEGORY`) used by `inject_logsource_fields()` (channel/provider → logsource enrichment).
