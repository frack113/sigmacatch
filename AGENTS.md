<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# AGENTS.md - Sigmacatch

**What:** Headless tool that captures real Windows events via **Windows Event Log API** (winevt), matches them against SigmaHQ rules, and outputs structured regression data (raw event JSON + valid EVTX via `EvtExportLog` + `info.yml`) compatible with SigmaHQ format.

**Tech:** Rust 2021 edition, async (tokio), grit-lib for git (pure Rust, no externes), rsigma-eval/rsigma-parser for Sigma, `windows` crate for Winevt API (cfg-gated). No TUI. Native Windows x64 target.

**Platform:** Windows (Winevt API via `windows` crate) + **Sysmon** requis pour des events riches. Linux/macOS (stub collector returns empty vec). Compilation Windows via `cargo xwin build --release --target x86_64-pc-windows-msvc` (nécessite `cargo install cargo-xwin` + Windows SDK téléchargé automatiquement).

**Prérequis Windows :** [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) doit être installé et configuré. Sans Sysmon, les events Winevt (Process, File, Registry, Network) sont trop pauvres pour matcher les règles Sigma qui référencent les champs Sysmon spécifiques (ParentImage, CommandLine, hashes, etc.).

## Architecture

```
sigmacatch/                      # Binary + pipeline (orchestration)
└── src/
    ├── main.rs                  # Pipeline loop + CLI + Stats + AggregatedRule
    ├── lib.rs                   # pub mod declarations
    ├── config.rs                # YAML config (Config, SigmaFilterConfig, MinStatus, MinLevel)
    ├── logger.rs                # Two-layer tracing subscriber (stderr info + daily rolling file debug)
    ├── repo.rs                  # grit-lib wrapper: clone/fetch/push/commit/branch (pure Rust, no git CLI)
    ├── detection/mod.rs         # SigmaDetectionEngine (extract channel/provider, resolve logsource)
    ├── collectors/
    │   ├── mod.rs               # pub mod event_log
    │   └── event_log.rs         # WinevtCollector (EvtQueryW, EvtNext, EvtRender)
    ├── evtx/
    │   └── writer.rs            # write_evtx() via EvtExportLog API (→ EVTX valide ou .xml fallback)
    ├── parser/
    │   └── winevt.rs            # re-export from winevt-xml crate
    ├── sigma/
    │   ├── mod.rs               # pub mod engine, loader, mapping
    │   ├── engine.rs            # SigmaEngine: load rules (post-parse filter), evaluate events
    │   ├── loader.rs            # SigmaRepo (grit-lib) + find_rules_dirs()
    │   └── mapping/mod.rs       # re-export from sigma-mapping crate
    ├── regression/mod.rs        # re-export from sigma-regression crate
    ├── github/
    │   ├── mod.rs               # pub mod commit, fork
    │   ├── commit.rs            # commit_all_rules() with author/email env, validate_rule_id, fallback
    │   └── fork.rs              # ForkConfig, check_fork_exists() (rate-limit aware), detect_fork()
    └── bin/
        └── evtx_check.rs        # Batch validation of Sigma engine against .evtx regression data

crates/
├── detection-engine/            # BareEngine wrapper + embedded pipelines (windows.yml, flatten_winevt.yml)
├── sigma-mapping/               # LogSource resolution, taxonomy (phf tables + channel_mapping.yml), custom mappings
├── sigma-regression/            # SkipSet, RegressionData, InfoYml, triplet validation (SigmaHQ format)
├── sigmacatch-types/            # Shared types: Event, Alert, RegressionHeader
└── winevt-xml/                  # WinevtEvent struct + XML/JSON parsing (roxmltree)
```

### Mapping module (`crates/sigma-mapping/src/mapping/`)

- `channel_mapping.rs`: `CHANNEL_TO_SERVICE_MAP` — `LazyLock<HashMap>` parsed from embedded `channel_mapping.yml` (channel name → Sigma service)
- `taxonomy.rs`: 2 static `phf` tables implementing the SigmaHQ Windows taxonomy
  - `CHANNEL_EVENT_TO_CATEGORY`: (channel, event_id) → category (~35 entries)
  - `CHANNEL_EVENT_TO_SUBCATEGORY`: Sysmon registry subcategories (EID 12→registry_add, 13→registry_set, 14→registry_rename)
  - `PROVIDER_TO_SERVICE`: ETW provider → service fallback (~11 entries)
- `custom.rs`: optional `custom_channels.yaml` overrides (v1.1)
- `mod.rs`: `resolve_logsource(channel, provider, event_id, custom_map) → LogSource`
  - Priority: custom channel → CHANNEL_TO_SERVICE_MAP → PROVIDER_TO_SERVICE → default
  - See `# INVARIANT:` comment in `crates/sigma-mapping/src/mapping/mod.rs`
  - Category via `CHANNEL_EVENT_TO_SUBCATEGORY` (priority) → `CHANNEL_EVENT_TO_CATEGORY`
- `build_logsource_to_channels(custom_map) → HashMap<String, Vec<ChannelTarget>>`
  - Generates 1→N map from static tables + custom mappings (runtime, not a static table)
  - Keys: `service` and `service:category` (e.g., `"sysmon"`, `"sysmon:process_creation"`)

### Processing pipeline (`crates/detection-engine/pipelines/`)

- `windows.yml`: embedded Sigma rule transformation pipeline (loaded via `include_str!` in `detection-engine`)
  - Maps Sigma rule `logsource.category` → Sysmon EventID conditions
  - Uses `add_condition` transformation with `rule_conditions` to gate when each condition fires
  - `EventType: CreateKey` / `EventType: DeleteKey` for registry_add / registry_delete sub-categories
  - **rsigma-eval v0.20 constraint**: `conditions` values in `add_condition` are single `SigmaValue` (integer/string/bool/null). **YAML arrays (`[17, 18]`) are NOT supported** — they become `SigmaValue::Null`. Always use separate transformation entries for each EventID (e.g., `[4, 16]` → two entries with `EventID: 4` and `EventID: 16`).
  - `rule_conditions`: `type: logsource` with `category`, `product`, `service` filters. All conditions use AND logic.
  - `field_name_conditions`: `include_fields` / `exclude_fields` with `match_type: plain` or `match_type: regex`
  - `field_name_cond_not`: negate field name conditions (boolean)
  - `detection_item_conditions`: `match_string` (regex), `is_null`
  - `rule_cond_expression`: logical expression over named conditions (`and`, `or`, `not`, `(`, `)`)
  - `prepend`: put added condition before existing detection (`new AND existing`) for short-circuit optimization
  - Supported transformation types: `field_name_mapping`, `field_name_prefix_mapping`, `field_name_prefix`, `field_name_suffix`, `drop_detection_item`, `add_condition`, `change_logsource`, `replace_string`, `value_placeholders`, `wildcard_placeholders`, `query_expression_placeholders`, `set_state`, `rule_failure`, `detection_item_failure`, `field_name_transform`, `hashes_fields`, `map_string`, `set_value`, `convert_type`, `regex`, `add_field`, `remove_field`, `set_field`, `set_custom_attribute`, `case_transformation`, `nest`, `include`
- `flatten_winevt.yml`: flattens nested Winevt XML event structure for Sigma evaluation
- Pipeline loaded once at engine init → applied to every rule before compilation

### Pipeline (rules-driven collection)

```
1. stage_0_init (config + directories)
2. stage_1_update_repo (sigma repo)
   └── (contrib) fork URL → with_remote_url, create_branch() with HEAD switch
3. stage_2_existing_rules (skip set)
4. stage_3_load_rules (load Sigma rules, filter non-Windows)
5. Load custom_channels.yaml → HashMap<String, String>
6. resolve_channels_from_rules(engine, custom_map)
   ├── Log active services + categories
   ├── Log skipped services + categories
   ├── If 0 channels → warn + return Ok
   └── Return Vec<String> channels
7. stage_4_work_winevt(channels, custom_map, ...)
8. Generate regression
   └── (contrib) output → sigma/regression_data/ instead of regression_data/
9. (contrib) commit_all_rules() → batch git commit to sigma repo
```

> Load rules → skip set → extract services/categories → resolve channels → collect → evaluate → generate → (contrib) commit + push

## Pipeline (single run, sequential)

1. Load config (create `config.yaml` with defaults if missing)
2. Create directories: `regression_data/`, `regression_data/rules/`
3. Acquire SigmaHQ rules via `grit-lib` (clone); exit error if no rules found
4. `find_rules_dirs()` scans `sigma/` for `rules` / `rules-*` dirs (excludes `rules-compliance`)
5. Build skip set by scanning `regression_data/rules/` + `sigma/regression_data/` for existing `info.yml` → `HashSet<String>` of rule IDs
6. Load Sigma rules from all `rules*` dirs, **excluding skipped rule IDs**; post-parse filter via `rule.logsource.product` filters non-Windows rules (seule optimisation autorisée)
7. Collect events via `WinevtCollector` (channels from config) → `Vec<WinevtEvent>`:
   - Each event's `LogSource` is derived from the **channel** via `resolve_logsource` (channel → service > provider → service > default)
   - Evaluate against **all loaded rules** via `evaluate_event_with_logsource(event, logsource)` — **aucun event perdu**
   - Aggregate matches by `rule_id` in `HashMap<String, AggregatedRule>`
8. Generate regression for rules without existing `info.yml` (skip at generate time too)
9. Write: `<output>/<rule_rel_path>/<rule_id>.json` (first matched event) + `<rule_id>.evtx` + `info.yml`; append `regression_tests_path` line to the source rule YAML
   - Non-contrib: `regression_data/` at project root
   - Contrib: `sigma/regression_data/` (committed to sigma fork repo)

## Invariants architecturaux (fondations non négociables)

- Pipeline 100% séquentiel : acquérir règles → charger moteur → collecter events → matcher → générer
- Tout en RAM : aggregation en mémoire avant écriture (pas de DB intermédiaire)
- Un run = cycle complet (pas de mode "juste collect" ou "juste generate")
- Collecte Windows via **Winevt API** (`windows` crate, `EvtQueryW`/`EvtNext`/`EvtRender`) — pas d'ETW, pas de ferrisetw
- Output = `regression_data/<rule_rel_path>/` (triplet: `<rule_id>.json` + `<rule_id>.evtx` + `info.yml` format SigmaHQ)
  - Non-contrib: `regression_data/` at project root
  - Contrib: `sigma/regression_data/` (inside the sigma repo, committed to fork)
- **Moteur temps réel** : `rsigma-eval` chargé une fois avec toutes les règles non skipées ; chaque event est évalué contre toutes les règles chargées. Aucun event perdu. Le skip-at-load est l'unique optimisation.
- **LogSource dérivée du channel ETW** (`resolve_logsource`), avec provider comme fallback.
  - Priority: channel → service > provider → service > default
  - See `# INVARIANT:` comment in `crates/sigma-mapping/src/mapping/mod.rs`
- **EVTX via `EvtExportLog`** : re-queries l'event par RecordID depuis le live log. Si succès → `.evtx` binaire valide. Si échec (event purgé) ou non-Windows → fallback `.xml` (raw XML, pas de binaire invalide).
  - **Known limitation** : race condition avec la rétention du log — si l'event a été purgé entre la collecte et l'export, `EvtExportLog` échoue silencieusement (`ERROR_EVT_QUERY_RESULT_STALE`).

> Skip set details, key design decisions, and skip set construction logic are in [`docs/architecture-reference.md`](docs/architecture-reference.md) (Stages 2, 5, 6, 7).

## Configuration

`config.yaml` (auto-created on first run by `stage_0_init`, `serde(default)`):

```yaml
author: "username"
email: "you@example.com"
github_token: ""          # GitHub token (or set GITHUB_TOKEN env var) — required for fork push
log:
  level_file: "debug"
sigma:
  min_status: "stable"    # load rules with status >= this threshold
  min_level: "critical"   # load rules with level >= this threshold
```

Les chemins `sigma/`, `regression_data/`, `logs/` sont hardcodés et créés automatiquement par `stage_0_init`.

CLI flags (in `main.rs`): `--author <name>`, `--dry-run`, `--channels-only`, `--all-rules`.
`Config` porte `author` (username), `email` (requis pour les commits git), `github_token` (requis pour le push fork) et `LogConfig` (niveau fichier).
Contrib est toujours actif — fork detection, branch, commit, push tournent à chaque run.

## Conventions

### Commit messages

Toujours utiliser un emoji UTF-8 en préfixe :

| Emoji | Type | Exemple |
|-------|------|---------|
| ✨ | feat | `✨ feat: add ETW collection` |
| 🐛 | fix | `🐛 fix: handle empty event` |
| 📚 | docs | `📚 docs: update architecture` |
| ♻️ | refactor | `♻️ refactor: extract providers` |
| 🧹 | cleanup | `🧹 cleanup: remove dead code` |
| 💄 | style | `💄 style: fix formatting` |
| ⚡ | perf | `⚡ perf: reduce allocations` |
| 🧪 | test | `🧪 test: add integration test` |
| 🔧 | chore | `🔧 chore: update dependencies` |

Format: `emoji type: description` (conventional commits).

**Séparation des commits :** un commit = un type de changement. Ne jamais mélanger code + docs + refactor dans un seul commit. Exemples :
- 🐛 fix code → commit séparé
- 📚 docs → commit séparé
- ♻️ refactor → commit séparé
- 🧪 test → commit séparé

Un PR peut contenir plusieurs commits tant que chacun est cohérent et logique.

### Pull Requests

Format du body du PR (inspiré des PR #1 et #2) :

```markdown
## Summary

1-2 phrases décrivant l'objectif du PR.

## Changes

### 🐛 Fix / ✨ Feature / ♻️ Refactor / 📚 Docs / 🔧 Chore
- Liste des changements par catégorie avec commits pertinents

## Tests

- Résultats des validations (cargo test, clippy, build)
- Nombre de tests, warnings éventuels

## Files

Liste des fichiers modifiés avec description courte.
```

Règles :
- **Titre** : `emoji type: description` (mêmes emojis que les commits)
- **Summary** : concis, 1-2 lignes max
- **Changes** : groupés par type avec emoji, inclure les hashes de commit si pertinent
- **Tests** : obligatoire — rapporter résultats clippy, fmt, test, build
- **Files** : tableau ou code block avec fichiers modifiés

- All errors use `anyhow::Result` (no custom error types except `LoadError` in engine)
- `tracing` for logging (info/warn/error); `RUST_LOG` env filter supported
- `serde_json::Value` for events; `WinevtEvent.event_json: Option<Value>` carries pre-parsed JSON from collector to eliminate double XML parsing
- Directory creation with `create_dir_all`, validation with `exists()`
- Skip logic uses `SkipSet` (with `HashSet<String>` of rule IDs) — seule optimisation autorisée dans le pipeline
- Async for TUI-free orchestration and Sigma repo git ops; detection/generation are synchronous
- **No dead code** — remove unused imports, fields, methods, and variables. Keep code clean and optimized.
- **Format before commit** — run `cargo fmt --check` before committing and fix any formatting differences.
- **Clippy strict** — run `cargo clippy -- -W warnings` before committing. Fix all warnings.
- **Windows cross-build validation** — run `cargo xwin build --release --target x86_64-pc-windows-msvc` after any code change to ensure Windows compatibility.
- **Security first** — validate paths (`rule_dir()` rejects `..`, `/`, `\`, `\0`), limit sizes, sanitize inputs.
- **Use existing crate APIs** — before writing custom parsers, serialization, or data processing, check what the project's dependencies already provide. Consult `docs.rs/<crate>` for API details. Do not reinvent functionality that crates like `rsigma-parser`, `serde_yaml`, `serde_json`, etc. already handle.
- **No hand-rolled parsers** — never implement custom YAML/JSON/TOML parsing when a crate API can do it. The old `quick_logsource_check()` hand-rolled YAML parser (27 defects) was deleted in Stage 3; `parse_sigma_yaml` is now used for all rule loading.
- **No external git CLI fallback** — use `grit-lib` (already a dependency) for all git operations: clone, fetch, push (HTTP), branch creation, HEAD switch, commit, tree checkout, index management. No `git` binary needed on PATH. Clear error message if missing.

## Build & Lint

```bash
cargo fmt --check
cargo clippy -- -W warnings
```

## Windows Cross-Compile

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

Le `.cargo/config.toml` force `target-feature=+crt-static` pour le target MSVC. Sans cela, le binaire dépend de **VCRUNTIME140.dll** (Microsoft Visual C++ Redistributable) et plante au lancement si le runtime n'est pas installé sur la machine cible. `+crt-static` linke le CRT statiquement → `.exe` standalone, sans DLL externe.

## CI/CD (GitHub Actions)

Workflows séparés par fonction dans `.github/workflows/` :

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `lint.yml` | push/PR → `main` | `fmt` (`cargo fmt --check`) + `clippy` (`cargo clippy -- -W warnings`) |
| `build.yml` | push/PR → `main` | `linux` (`cargo build --release`) + `windows` (MSVC `windows-latest`) |
| `test.yml` | push/PR → `main` | `test` (`cargo test`) |
| `audit.yml` | push/PR → `main` | `cargo-deny` (advisories, sources, licenses) |
| `release.yml` | push tag `v*` | linux build + windows build + git-cliff changelog + GitHub release |
| `documentation.yml` | push/PR → `main` | mkdocs-material build + deploy to GitHub Pages |

- **Pas de workflow monolithique** — un fichier par fonction (lint, build, test, audit, release, docs)
- `actions/checkout@v7`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`
- Dependabot gère les mises à jour automatiques (`github-actions` + `cargo` ecosystems)
- Les 3 checks principaux (lint, build, test) doivent passer avant merge

## Dependency Management

- Les specifiers dans `Cargo.toml` utilisent la version majeure (ex: `"0.85"`, `"0.20"`) pour recevoir les correctifs automatiquement via `cargo update`
- `cargo upgrade` est réservé pour les mises à jour intentionnelles de specifiers
- Les PR Dependabot doivent être reviewées avant merge

## Dependencies

- `grit-lib` — all git operations (clone, fetch, push, branch, commit, checkout) via HTTP, pure Rust
- `reqwest` (blocking) — HTTP client for git transport + fork detection (GitHub API)
- `rsigma-eval` + `rsigma-parser` — Sigma rule loading/evaluation
- `tokio` — async runtime
- `tracing` + `tracing-subscriber` — logging
- `serde` / `serde_json` / `serde_yaml` (`yaml_serde`) — config + event/regression serialization
- `anyhow`, `chrono`, `uuid` — error handling, dates, IDs
- `rayon` — parallel rule file parsing
- `phf` — static hash maps for taxonomy tables (in `sigma-mapping`)
- `evtx` — EVTX file parsing (used by `evtx_check` binary)
- `tempfile` (dev) — integration tests
- `windows` (`cfg(windows)`) — Winevt API (`EvtQueryW`/`EvtNext`/`EvtRender`/`EvtExportLog`)

Removed (no longer used): `ratatui`, `crossterm`, `quick-xml`, `winevt-writer`, `ferrisetw`, `tdh`/`ntapi` raw ETW.
