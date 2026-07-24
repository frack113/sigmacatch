# Référence Architecture

> Document de référence complet — ne nécessite pas de relire le code source.

---

## 1. Vue d'ensemble

Outil headless qui capture des événements Windows réels via **Windows Event Log API** (winevt), les matche contre les règles SigmaHQ, et sort des données de régression structurées.

**Cycle complet (séquentiel) :**
1. Acquérir règles SigmaHQ (grit-lib clone/pull)
2. Charger moteur Sigma (rsigma-eval) avec filtre logsource
3. Collecter événements Event Log (winevt, channels configurés)
4. Évaluer events contre toutes les règles chargées
5. Générer sortie regression (JSON + EVTX template + info.yml)

**Boucle :** toutes les 30s en continu.

**Plateforme :** Windows (winevt + Sysmon requis). Linux/macOS : stub no-op.

---

## 2. Arborescence

```
sigmacatch/
├── Cargo.toml                     # Racine workspace (6 crates)
├── sigmacatch/                    # Crate binaire
│   └── src/
│       ├── main.rs                # Pipeline + Stats + AggregatedRule
│       ├── lib.rs                 # Déclarations pub mod
│       ├── config.rs              # Config, SigmaFilterConfig, MinStatus, MinLevel
│       ├── repo.rs                # wrapper grit-lib (clone/fetch/push/commit/branch)
│       ├── detection/mod.rs       # SigmaDetectionEngine
│       ├── collectors/
│       │   └── event_log.rs       # WinevtCollector (EvtQueryW, EvtNext, EvtRender)
│       ├── evtx/writer.rs         # write_evtx() via EvtExportLog API + .xml fallback
│       ├── parser/winevt.rs       # re-export depuis winevt-xml
│       ├── sigma/
│       │   ├── engine.rs          # SigmaEngine + évaluation des règles
│       │   ├── loader.rs          # SigmaRepo (grit-lib) + find_rules_dirs()
│       │   └── mapping/mod.rs     # re-export depuis sigma-mapping
│       ├── regression/mod.rs      # re-export depuis sigma-regression
│       ├── github/
│       │   ├── commit.rs          # commit_all_rules avec author env + fallback
│       │   └── fork.rs            # ForkConfig, check_fork_exists, detect_fork
│       └── bin/evtx_check.rs      # Outil de validation batch
├── crates/
│   ├── detection-engine/          # BareEngine + pipelines embarquées (windows.yml, flatten_winevt.yml)
│   ├── sigma-mapping/             # LogSource, taxonomie (phf + channel_mapping.yml), mappings custom
│   ├── sigma-regression/          # SkipSet, RegressionData, InfoYml, validation triplet
│   ├── sigmacatch-types/          # Types partagés : Event, Alert, RegressionHeader
│   └── winevt-xml/                # WinevtEvent + parsing XML/JSON (roxmltree)
```

---

## 3. Configuration

`config.yaml` (auto-créé au premier run, complété automatiquement si la section `sigma` manque) :

```yaml
author: "sigmacatch"        # nom GitHub pour contrib workflow (doit être changé)
email: "you@example.com"    # requis pour les commits git
github_token: ""            # token GitHub (ou var env GITHUB_TOKEN) — requis pour le push du fork
log:
  level_file: "debug"       # niveau fichier tracing
sigma:
  min_status: "stable"      # seuil de statut minimal (inclus) : unsupported < deprecated < experimental < test < stable
  min_level: "critical"     # seuil de niveau minimal (inclus) : informational < low < medium < high < critical
```

**Filtrage des règles :** `min_status` et `min_level` sont appliqués au chargement. Les règles dont `status`/`level` est inférieur au seuil sont exclues du moteur. Les règles sans champ `status` ou `level` sont toujours acceptées.

**CLI flags :** `--author <name>`

---

## 4. Pipeline détaillé

### Stage 0 — Init

```
config.yaml → Config struct
    ↓
create_dir_all("sigma/", "regression_data/", "regression_data/rules/", "logs/")
    ↓
logger::init() → tracing subscriber (stderr info + file debug)
```

### Stage 1 — Acquisition SigmaHQ

```
SigmaRepo::new("sigma/")
    ↓
with_remote_url(URL du fork)
    ↓
init() [async]
    ├── NO .git → grit-lib clone <remote_url> (fork ou SigmaHQ)
    └── .git EXISTS → mise à jour remote origin (si fork) → grit-lib fetch
         └── échec → WARN, continue avec règles existantes
    ↓
create_branch("sigmacatch-contrib/YYYYMMDD_<author>")
    └── create_branch() → grit-lib create ref + switch HEAD vers la branche (ou switch si existe déjà)
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
Walk séquentiel : collecte tous les chemins .yml / .yaml (rapide, pas de parse)
    ↓
Parse + filter parallèle (rayon::par_iter, pas d'état partagé) :
    Pour chaque fichier :
    ├── parse_sigma_yaml() → règles Sigma
    ├── post-parse filter: rule.logsource.product == "windows" (ou absent)
    ├── filter status/level: rule.status >= min_status ET rule.level >= min_level (config.sigma)
    ├── skip si rule_id dans skip set
    └── dédoublonnage cross-fichier (1re occurrence, ordre du walk, gagne)
    ↓
Merge séquentiel : accumule les règles survivantes dans UNE SigmaCollection,
puis UN SEUL engine.add_collection() → rsigma-eval (un seul rebuild d'index)
    ↓
SigmaEngine in-memory (règles chargées + rule_paths)
```

> **Note perf :** `add_collection()` de `rsigma-eval` rebuild l'index complet
> des règles à chaque appel. L'ancien `add_collection` par fichier était en
> O(N²) (N rebuilds d'un index de N règles). Regrouper toutes les règles
> survivantes dans une seule collection fait passer le chargement de ~33s à
> ~0,2s pour tout SigmaHQ (~2800 règles). Le parse tourne en parallèle via
> `rayon`.

> Affichage d'une table de règles au démarrage (nombre chargé, nombre skipé, services/catégories actifs).

**Filtrage status/level :** les règles dont `status` < `min_status` ou `level` < `min_level` sont exclues (seulement si le champ est présent). Par défaut `min_status=stable`, `min_level=critical` — très restrictif, ne charge que les règles stables/critiques.

### Cycle — Collecte

```
WinevtCollector (channels résolus depuis les règles via resolve_channels_from_rules)
    ├── [Windows] EvtQueryW(channel="*") → EvtNext() → EvtRender() → XML
    │     ├── Un task par channel (tokio::spawn)
    │     ├── XML → parse_winevt_xml() → WinevtEvent (porte event_json pré-parsé)
    │     └── mpsc::channel → main loop
    └── [non-Windows] Stub → Ok(vec![])
    ↓
Vec<WinevtEvent> { channel, event_id, raw_xml, event_json }
```

### Cycle — Évaluation

```
Pour chaque SensorEvent :
    ├── channel → LogSource { product: "windows", service, category }
    │     (mapping::resolve_logsource + priorité channel/service)
    ├── event.event_json → serde_json::Value plat (pré-parsé par collector, fallback XmlParser si None)
    ├── engine.evaluate_event_with_logsource(event_value, logsource)
    │     → Vec<EvaluationResult> (rsigma-eval)
    └── Pour chaque match :
         ├── rule_id = match.header.rule_id
         ├── skip si rule_id dans retired (déjà généré ce cycle)
         ├── stats.matches_found++
         └── aggregated[rule_id].events.push((event_value, raw_xml, provider))
```

### Cycle — Génération

```
Pour chaque AggregatedRule dans aggregated :
    ├── RegressionData::new(header, output_path, rule_rel_path, author)
    ├── exists() → skip si info.yml existe déjà
    ├── Pour chaque event : reg.add_event(event_json, raw_xml)
    ├── reg.generate()
    │     ├── Write <rule_id>.json (premier event, JSON pretty-printed)
    │     ├── Write <rule_id>.evtx (EvtExportLog API, ou .xml fallback)
    │     └── Write info.yml (InfoYml::new + save)
    ├── Append "regression_tests_path: ..." au YAML source de la règle
    └── retired.insert(rule_id)
```

**Sortie :**
```
<output_base>/<rule_rel_path>/
    ├── <rule_id>.json      # premier event correspondant (JSON plat)
    ├── <rule_id>.evtx      # EVTX valide via EvtExportLog (ou .xml fallback)
    └── info.yml            # métadonnées compatible SigmaHQ
```
- Non-contrib : `output_base` = `regression_data/` (racine du projet)
- Contrib : `output_base` = `sigma/regression_data/` (dans le repo sigma, commité sur le fork)

### Post-cycle

```
commit_all_rules() → batch grit-lib commit dans le repo sigma
sleep 30s → loop
Ctrl+C → running.store(false) → break
push_branch() → fetch + comparaison + push normal vers le fork (skip si divergé)
```

**Stats :** `{ events_processed, matches_found, regression_data_generated }`

---

## 5. Structures de données clés

### WinevtEvent

```rust
WinevtEvent {
    channel: String,            // nom du channel Event Log
    event_id: u32,              // EventID
    raw_xml: String,            // XML complet de l'événement (Winevt format)
    event_json: Option<serde_json::Value>,  // JSON pré-parsé par le collector (XmlParser)
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
    alerts: Vec<Alert>,          // events correspondants
    output_path: PathBuf,
    rule_rel_path: Option<PathBuf>,
    author: Option<String>,
    description: Option<String>,
    is_contrib: bool,
}
```

---

## 6. Modules clés

### SigmaEngine (`sigma/engine.rs`)

- Charge règles depuis `rules*` dirs
- Walk séquentiel collecte les chemins ; parse + post-parse filter en parallèle (`rayon::par_iter`)
- Post-parse filter: `rule.logsource.product` filtre les règles non-Windows après `parse_sigma_yaml`
- Filtre status/level appliqué par fichier pendant le parse parallèle
- Skip-at-load = seule optimisation (règles avec `info.yml` existant)
- Toutes les règles survivantes mergées dans une seule `SigmaCollection`, compilées en **un seul** `add_collection()` (évite les rebuilds d'index O(N²))
- `LogSource` dérivé du channel Event Log + provider (resolve_logsource)
- `evaluate_event_with_logsource()` → `Vec<EvaluationResult>` via rsigma-eval

### EVTX Writer (`evtx/writer.rs`)

- **Windows** : `EvtExportLog` API (winevt) — re-queries l'event par RecordID et exporte en `.evtx` binaire valide
  - `EvtExportLog(None, channel, query, path, EvtExportLogChannelPath | EvtExportLogOverwrite)`
  - Produit un EVTX binaire valide lisible par hayabusa/chainsaw
  - **Known limitation** : race condition avec la rétention du log — si l'event a été purgé entre la collecte et l'export, l'appel échoue silencieusement (`ERROR_EVT_QUERY_RESULT_STALE`)
- **Fallback** : écriture XML brut en `.xml` (pas `.evtx` — évite de produire un binaire invalide qui casserait les outils downstream)
- **Non-Windows** : fallback écriture XML brut en `.xml`
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
| EVTX via EvtExportLog | Re-queries event par RecordID → EVTX binaire valide. Fallback .xml si échec. |

---

## 8. Dépendances

| Dépendance | Usage |
|---|---|---|
| `grit-lib` | toutes les ops git (clone, fetch, push, branch, commit, checkout) via HTTP, Rust pur |
| `reqwest` (blocking) | client HTTP pour transport git + détection de fork (API GitHub) |
| `rsigma-eval` + `rsigma-parser` | Sigma rule loading/evaluation |
| `tokio` | async runtime |
| `tracing` + `tracing-subscriber` | logging |
| `serde` / `serde_json` / `serde_yaml` | config + event + regression serialization |
| `anyhow` | error handling |
| `chrono` | dates |
| `uuid` | UUID v4 pour info.yml |
| `rayon` | parse parallèle des fichiers de règles |
| `phf` | tables de hash statiques pour la taxonomie (dans sigma-mapping) |
| `evtx` | parsing de fichiers EVTX (binaire evtx_check) |
| `windows` | Winevt API (cfg-gated: windows only, features: Foundation, Com, Console, EventLog, Threading, Security) |

**Retirés :** `ratatui`, `crossterm`, `quick-xml`, `winevt-writer`, `tdh`, `ntapi`

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
    [--author <name>]      # override username
```

La config est auto-créée au premier run avec les valeurs par défaut. Éditez `config.yaml` avant de lancer.

---

## 11. Diagramme du pipeline

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
│  STAGE 1 — ACQUISITION SIGMAHQ                                         │
│  SigmaRepo::new("sigma/")                                               │
│    ├── [contrib] définir l'URL du remote fork                          │
│    ├── NO .git → grit-lib clone (fork ou SigmaHQ)                           │
│    └── .git EXISTS → mise à jour remote origin → grit-lib fetch            │
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
│  → HashSet<rule_id> (règles avec régression existante)               │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  STAGE 3 — CHARGEMENT DES RÈGLES                                        │
│  find_rules_dirs("sigma/") → rules, rules-* (excl. rules-compliance)   │
│  Pour chaque .yml :                                                     │
│    ├── parse_sigma_yaml() → règles Sigma                               │
│    ├── post-parse filter: logsource.product == "windows" (ou absent)  │
│    ├── filter status/level: rule.status >= min_status ET ...          │
│    ├── skip si rule_id dans skip set                                  │
│    └── engine.add_collection() → rsigma-eval                          │
│  → SigmaEngine in-memory + rule_paths HashMap                          │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — COLLECTE (winevt)                                              │
│  WinevtCollector (channels résolus depuis les règles)                   │
│    ├── Windows: EvtQueryW → EvtNext → EvtRender → XML                │
│    │     → parse_winevt_xml() → WinevtEvent                          │
│    └── non-Windows: Stub → Ok(vec![])                                 │
│  → Vec<WinevtEvent> { channel, event_id, raw_xml }                     │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — ÉVALUATION                                                     │
│  Pour chaque WinevtEvent :                                              │
│    ├── event.event_json → JSON plat (pré-parsé, fallback XmlParser si None)
│    ├── channel → LogSource via resolve_logsource()                   │
│    └── engine.evaluate_event_with_logsource()                         │
│         → Vec<EvaluationResult>                                        │
│  Pour chaque match :                                                    │
│    └── aggregated[rule_id].events.push((json, raw_xml, provider))     │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  CYCLE — GÉNÉRATION                                                     │
│  Pour chaque AggregatedRule :                                           │
│    ├── skip si rule_id dans retired ou info.yml existant              │
│    ├── RegressionData::new(output_base, ...)                          │
│    │   output_base = regression_data/ ou sigma/regression_data/       │
│    ├── reg.generate() → triplet :                                     │
│    │     ├── <rule_id>.json (premier event, JSON plat)                │
│    │     ├── <rule_id>.evtx (EvtExportLog, ou .xml fallback)          │
│    │     └── info.yml (UUID v4, metadata SigmaHQ)                     │
│    └── append "regression_tests_path" au YAML source                  │
│  ↓                                                                     │
│  commit_all_rules() → batch grit-lib commit dans sigma                       │
└──────────────────────┬──────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  POST-CYCLE                                                             │
│    sleep 30s → loop                                                     │
│  Ctrl+C → running.store(false) → break                                  │
│    push_branch() → fetch + comparaison + push normal vers le fork       │
└─────────────────────────────────────────────────────────────────────────┘
```

**Sortie finale :**
```
<output_base>/<rule_rel_path>/
├── <rule_id>.json      # premier event correspondant (JSON plat, clés Sigma)
├── <rule_id>.evtx      # EVTX valide via EvtExportLog (ou .xml fallback)
└── info.yml            # type: evtx, rule_metadata, regression_tests_info
```
- Non-contrib : `output_base` = `regression_data/` (racine du projet)
- Contrib : `output_base` = `sigma/regression_data/` (dans le repo sigma, commité sur le fork)
