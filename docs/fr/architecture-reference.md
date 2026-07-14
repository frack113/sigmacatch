# Référence Architecture

> Document de référence complet — ne nécessite pas de relire le code source.

---

## 1. Vue d'ensemble

Outil headless qui capture des événements Windows réels via **Windows Event Log API** (winevt), les matche contre les règles SigmaHQ, et sort des données de régression structurées.

**Cycle complet (séquentiel) :**
1. Acquérir règles SigmaHQ (gix clone/pull)
2. Charger moteur Sigma (rsigma-eval) avec filtre logsource
3. Collecter événements Event Log (winevt, channels configurés)
4. Évaluer events contre toutes les règles chargées
5. Générer sortie regression (JSON + EVTX template + info.yml)

**Boucle :** toutes les 30s par défaut, ou unique (`--once`).

**Plateforme :** Windows (winevt + Sysmon requis). Linux/macOS : stub no-op.

---

## 2. Arborescence

```
src/
├── main.rs              # Pipeline + Stats + AggregatedRule
├── config.rs            # Config YAML (serde, Default) + LogConfig
├── logger.rs            # Two-layer tracing (stderr info + rolling file debug)
├── sigma/
│   ├── loader.rs        # SigmaRepo (gix) + find_rules_dirs()
│   └── engine.rs        # SigmaEngine + évaluation des règles (resolve_logsource depuis mapping)
├── collector/
│   ├── mod.rs           # pub mod winevt
│   └── winevt.rs        # WinevtCollector (EvtQueryW, EvtNext, EvtRender)
├── evtx/
│   └── writer.rs        # write_evtx() via EvtWriteFile API
├── parser/
│   └── mod.rs           # XmlParser (Winevt XML → JSON plat)
└── regression/
    ├── mod.rs           # SkipSet, build_skip_set(), validate_rule_id(), triplet validation
    ├── generator.rs     # RegressionData, MatchEvent
    └── info_yml.rs      # InfoYml, RuleMetadata, RegressionTestInfo
```

---

## 3. Configuration

`config.yaml` (auto-créé au premier run) :

```yaml
author: "username"          # whoami::username() par défaut
once: false                 # true = un seul cycle puis exit
offline: false              # true = utilise sigma/ existant sans git
log:
  level_file: "debug"       # niveau fichier tracing
  clear_on_start: true      # supprime anciens logs
```

**CLI flags :** `--create-config`, `--author <name>`, `--once`, `--offline`

---

## 4. Pipeline détaillé

### Stage 0 — Init

```
config.yaml → Config struct
    ↓
create_dir_all("sigma/", "regression_data/", "logs/")
    ↓
logger::init() → tracing subscriber (stderr info + file debug)
```

### Stage 1 — Acquisition SigmaHQ

```
SigmaRepo::new("sigma/")
    ↓
init() [async]
    ├── NO .git → gix clone https://github.com/SigmaHQ/sigma.git
    └── .git EXISTS → gix fetch + reset worktree → origin/master
         └── échec → WARN, continue avec règles existantes
```

### Stage 2 — Skip Set (règles existantes)

```
build_skip_set(dirs, max_depth=64)
    ├── scan regression_data/rules/*/info.yml
    ├── scan sigma/regression_data/**/info.yml
    │     (exclut rules-compliance/ et rules_compliance/)
    ├── pour chaque info.yml :
    │     ├── parse_info_yml() → rule_id (flexible: rule_metadata[0].id ou root id)
    │     ├── validate_rule_id() → UUID v4 ou [a-z0-9_-]+
    │     ├── validate_parent_folder() → dossier parent == rule_id
    │     └── validate_triplet() → info.yml + .json + .evtx
    │           ├── complet → SkipSet::rules
    │           └── incomplet → SkipSet::incomplete (listé, pas bloquant)
    └── SkipSet { rules, incomplete, duplicates }
```

Règles avec régression existante (complète ou incomplète) → **exclu du moteur Sigma** (seule optimisation autorisée).

### Stage 3 — Chargement des règles

```
find_rules_dirs("sigma/")
    → Vec<PathBuf> (rules, rules-*, exclut rules-compliance)
    ↓
Pour chaque .yml / .yaml :
    ├── parse_sigma_yaml() → règles Sigma
    ├── post-parse filter: rule.logsource.product == "windows" (ou absent)
    ├── skip si rule_id dans skip set
    ├── engine.add_collection() → rsigma-eval
    └── track rule_paths HashMap<rule_id, PathBuf>
    ↓
SigmaEngine in-memory (règles chargées + rule_paths)
```

### Cycle — Collecte

```
WinevtCollector (channels: Security, System, Sysmon)
    ├── [Windows] EvtQueryW(channel="*") → EvtNext() → EvtRender() → XML
    │     ├── Un task par channel (tokio::spawn)
    │     ├── XML → parse_event_xml() → WinevtEvent
    │     └── mpsc::channel → main loop
    └── [non-Windows] Stub → Ok(vec![])
    ↓
Vec<WinevtEvent> { channel, event_id, timestamp, raw_xml }
```

### Cycle — Évaluation

```
Pour chaque SensorEvent :
    ├── channel → LogSource { product: "windows", service, category }
    │     (mapping::resolve_logsource + priorité channel/service)
    ├── event.to_json_value() → serde_json::Value plat (clés Sigma : Image, CommandLine, ...)
    ├── engine.evaluate_event_with_logsource(event_value, logsource)
    │     → Vec<EvaluationResult> (rsigma-eval)
    └── Pour chaque match :
         ├── rule_id = match.header.rule_id
         ├── skip si rule_id dans retired (déjà généré ce cycle)
         ├── stats.matches_found++
         └── aggregated[rule_id].events.push(event_value)
```

### Cycle — Génération

```
Pour chaque AggregatedRule dans aggregated :
    ├── RegressionData::new(header, output_path, rule_rel_path, author)
    ├── exists() → skip si info.yml existe déjà
    ├── Pour chaque event : reg.add_event(event_json, raw_xml)
    ├── reg.generate()
    │     ├── Write <rule_id>.json (premier event, JSON pretty-printed)
    │     ├── Write <rule_id>.evtx (EvtWriteFile API, XML Winevt valide)
    │     └── Write info.yml (InfoYml::new + save)
    ├── Append "regression_tests_path: ..." au YAML source de la règle
    └── retired.insert(rule_id)
```

**Sortie :**
```
regression_data/<rule_rel_path>/
├── <rule_id>.json      # premier event correspondant (JSON plat)
├── <rule_id>.evtx      # EVTX valide via EvtWriteFile (XML Winevt)
└── info.yml            # métadonnées compatible SigmaHQ
```

### Post-cycle

```
Si config.once → print Stats JSON → exit
Sinon → sleep 30s → loop
Ctrl+C → running.store(false) → break
```

**Stats :** `{ rules_loaded, events_processed, matches_found, regression_data_generated, status }`

---

## 5. Structures de données clés

### WinevtEvent

```rust
WinevtEvent {
    channel: String,            // nom du channel Event Log
    event_id: u32,              // EventID
    raw_xml: String,            // XML complet de l'événement (Winevt format)
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
    events: Vec<MatchEvent>,  // (event_json, raw_xml)
    output_path: PathBuf,
    rule_rel_path: Option<PathBuf>,
    author: Option<String>,
}

MatchEvent {
    event: Value,             // JSON plat de l'événement
    raw_xml: String,          // XML Winevt complet (pour EVTX)
}
```

---

## 6. Modules clés

### SigmaEngine (`sigma/engine.rs`)

- Charge règles depuis `rules*` dirs
- Post-parse filter: `rule.logsource.product` filtre les règles non-Windows après `parse_sigma_yaml`
- Skip-at-load = seule optimisation (règles avec `info.yml` existant)
- `LogSource` dérivé du channel Event Log + `EventFields::category()`
- `evaluate_event_with_logsource()` → `Vec<EvaluationResult>` via rsigma-eval

### EVTX Writer (`evtx/writer.rs`)

- **Windows** : `EvtWriteFile` API (winevt) — écrit XML Winevt dans EVTX valide
  - `CoInitializeEx` → `EvtWriteFile(PCWSTR path, 0, PCWSTR xml)` → `EvtClose`
  - Produit un EVTX binaire valide lisible par hayabusa/chainsaw
- **Non-Windows** : fallback écriture XML brut (pas de format EVTX sans API Winevt)
- Le `.json` compagnon porte les données réelles pour le matching Sigma

### Logger (`logger.rs`)

- **couche stderr** : niveau `info`, couleurs ANSI, filterable via `RUST_LOG`
- **couche fichier** : niveau `debug` (configurable), rotation journalière
- `logs/sigmacatch.YYYY-MM-DD.log`

---

## 7. Invariants architecturaux

| Invariant | Détail |
|---|---|
| Pipeline 100% séquentiel | rules → engine → collect → match → generate |
| Tout en RAM | agrégation mémoire avant écriture, pas de DB |
| Un run = cycle complet | pas de mode "juste collect" ou "juste generate" |
| Collecte via Winevt | EvtQueryW → EvtNext → EvtRender, pas ETW, pas ferrisetw |
| LogSource depuis channel | channel Event Log via resolve_logsource (channel > provider > default) |
| Skip-at-load unique optimisation | règles avec `info.yml` exclu du moteur |
| Un event par test | `match_count: 1`, premier event seulement |
| Output miroir source | `regression_tests_path` ajouté au YAML source |
| EVTX via EvtWriteFile | XML Winevt → EVTX binaire valide (API winevt) |

---

## 8. Dépendances

| Dépendance | Usage |
|---|---|
| `gix` | git operations (clone/pull SigmaHQ) |
| `rsigma-eval` + `rsigma-parser` | Sigma rule loading/evaluation |
| `tokio` | async runtime |
| `tracing` + `tracing-subscriber` | logging |
| `serde` / `serde_json` / `serde_yaml` | config + event + regression serialization |
| `anyhow` | error handling |
| `chrono` | dates |
| `uuid` | UUID v4 pour info.yml |
| `windows` | Winevt API (cfg-gated: windows only, features: Foundation, Com, Console, EventLog, Threading, Security) |

**Retirés :** `ratatui`, `crossterm`, `quick-xml`, `winevt-writer`, `tdh`, `ntapi`

---

## 9. Build & Lint

```bash
cargo build --release
cargo clippy -- -W warnings
cargo build --release --target x86_64-pc-windows-gnu   # cross-compile Windows
```

---

## 10. CLI

```
sigmacatch
    [--create-config]      # créer config.yaml avec defaults
    [--author <name>]      # override username
    [--once]               # un seul cycle puis exit
    [--offline]            # utiliser sigma/ existant sans git
```

---

## 11. Diagramme du pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│  config.yaml                                                            │
│    author, once, offline, log.level_file, clear_on_start               │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 0 — INIT                                                         │
│  create_dir_all("sigma/", "regression_data/", "logs/")                 │
│  logger::init() → tracing (stderr info + file debug)                   │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 1 — ACQUISITION SIGMAHQ                                         │
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
│  → HashSet<rule_id> (règles avec régression existante)               │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 3 — CHARGEMENT DES RÈGLES                                        │
│  find_rules_dirs("sigma/") → rules, rules-* (excl. rules-compliance)   │
│  Pour chaque .yml :                                                     │
│    ├── parse_sigma_yaml() → règles Sigma                               │
│    ├── post-parse filter: logsource.product == "windows" (ou absent)  │
│    ├── skip si rule_id dans skip set                                  │
│    └── engine.add_collection() → rsigma-eval                          │
│  → SigmaEngine in-memory + rule_paths HashMap                          │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — COLLECTE (winevt)                                              │
│  WinevtCollector (channels: Security, System, Sysmon)                  │
│    ├── Windows: EvtQueryW → EvtNext → EvtRender → XML                │
│    │     → parse_event_xml() → WinevtEvent                            │
│    └── non-Windows: Stub → Ok(vec![])                                 │
│  → Vec<WinevtEvent> { channel, event_id, raw_xml }                     │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — ÉVALUATION                                                     │
│  Pour chaque WinevtEvent :                                              │
│    ├── parse raw_xml → JSON plat (XmlParser)                          │
│    ├── provider → LogSource { product: "windows" }                    │
│    └── engine.evaluate_event_with_logsource()                         │
│         → Vec<EvaluationResult>                                        │
│  Pour chaque match :                                                    │
│    └── aggregated[rule_id].events.push((json, raw_xml))               │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — GÉNÉRATION                                                     │
│  Pour chaque AggregatedRule :                                           │
│    ├── skip si rule_id dans retired ou info.yml existant              │
│    ├── RegressionData::new()                                           │
│    ├── reg.generate() → triplet :                                     │
│    │     ├── <rule_id>.json (premier event, JSON plat)                │
│    │     ├── <rule_id>.evtx (EvtWriteFile, XML Winevt)                │
│    │     └── info.yml (UUID v4, metadata SigmaHQ)                     │
│    └── append "regression_tests_path" au YAML source                  │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  POST-CYCLE                                                             │
│  Stats JSON → stdout                                                    │
│    ├── config.once → exit                                                │
│    └── sleep 30s → loop                                                  │
│  Ctrl+C → running.store(false) → break                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Sortie finale :**
```
regression_data/<rule_rel_path>/
├── <rule_id>.json      # premier event correspondant (JSON plat, clés Sigma)
├── <rule_id>.evtx      # EVTX valide via EvtWriteFile (XML Winevt)
└── info.yml            # type: evtx, rule_metadata, regression_tests_info
```
