# Référence Architecture

> Document de référence complet — ne nécessite pas de relire le code source.

---

## 1. Vue d'ensemble

Outil headless qui capture des événements Windows réels via **Windows Event Log API** (winevt), les matche contre les règles SigmaHQ, et sort des données de régression structurées.

**Exécution continue (un seul processus jusqu'à Ctrl+C) :**

1. Charger la config + init logger
2. Acquérir les règles SigmaHQ (grit-lib clone/fetch) + créer la branche
3. Construire le skip set depuis les données de régression existantes
4. Charger le moteur Sigma (rsigma-eval) avec bloom pre-filter + LogSourceExtractor
5. Résoudre les channels depuis les règles chargées
6. Lancer un collecteur continu (winevt, une task par channel)
7. Évaluer chaque event contre toutes les règles chargées (API FIFO)
8. Toutes les 30s : générer la sortie regression pour les règles matchées, commit (par règle) + push (si contrib) sur le fork
9. Sur Ctrl+C : flush final → commit → push de la branche vers le fork (seulement si `git.contrib: true`)

**Plateforme :** Windows (winevt + Sysmon requis pour des events riches). Linux/macOS : le collecteur est un stub no-op — le pipeline tourne quand même de bout en bout pour les tests.

---

## 2. Arborescence

```text
sigmacatch/
├── Cargo.toml                     # Racine workspace (11 packages)
├── sigmacatch/                    # Crate binaire
│   └── src/
│       └── main.rs                # Orchestration : boucle continue + process_and_generate + commit/push
├── localcheck/                    # Outils de dev (check_filter, check_evtx)
└── crates/
    ├── sigmacatch-config/         # Config YAML, parsing CLI, custom_channels.yaml, diagnostics git dry-run
    ├── sigmacatch-logger/         # Abonnement tracing à deux couches (stderr info + fichier journal rolling debug)
    ├── sigmacatch-rule/           # SigmahqRules : chargement (parse_sigma_yaml), filtre, dédupe, remove_id
    ├── sigmacatch-detection/      # Wrapper DetectionEngine + pipelines embarquées (windows.yml, flatten_winevt.yml) + channel_resolver
    ├── input-windows-channels/    # Collecteur Winevt multi-channel (EventProducer)
    ├── sigmacatch-regression/     # SigmahqRegression, InfoYml, RegressionData, validation triplet
    ├── sigmacatch-types/          # Types partagés : Event, Alert, RegressionHeader, Product + parsing XML + tables de mapping logsource
    ├── sigmacatch-repo/           # wrapper grit-lib : SigmaRepo, opérations git
    └── input-evtx/                # Parser fichiers EVTX → Event (utilisé par localcheck)
```

---

## 3. Configuration

`config.yaml` (auto-créé avec des défauts au premier run ; le programme exit après création jusqu'à ce que vous le modifiiez — `serde(default)`) :

```yaml
git:
  author: "sigmacatch"        # GitHub username pour le contrib workflow (doit être renseigné)
  email: "you@example.com"    # requis pour les commits git (doit contenir '@')
  github_token: ""            # GitHub token (ou variable d'env GITHUB_TOKEN) — requis pour HTTP transport
  transport: http             # http (défaut) ou ssh (ssh pas implémenté sur Windows)
  ssh_key_path: ""            # path to SSH private key (optionnel, seulement pour SSH)
  sigma_repo_url: "https://github.com/SigmaHQ/sigma.git"
  sigma_repo_path: "sigma"    # chemin local du repo sigma (relatif, pas de '..', pas absolu)
  offline: false              # true = skip le pull au startup (repo existant requis). false (défaut) = pull
  contrib: false              # true = push au remote fork. false (défaut) = commits locaux uniquement
log:
  level_file: "debug"
filter:
  product: windows            # windows, linux, ou macos
  min_status: "stable"        # status minimum des règles (inclusif) : unsupported < deprecated < experimental < test < stable
  min_level: "critical"       # niveau minimum des règles (inclusif) : informational < low < medium < high < critical
  author: ""                  # filtre par author (optionnel, vide = pas de filtre)
  max_rule_size: 1048576      # octets (1MB par défaut, min 1024, max 10MB)
```

**Filtrage des règles :** `product`, `min_status`, `min_level` et `author` sont appliqués par `SigmahqRules::filter()`.
Les règles dont `status`/`level` est inférieur au seuil sont exclues (seulement si le champ est présent) ;
les règles sans `status`/`level` sont toujours acceptées. Si 0 règle reste, le programme bail.

**Validation :** `git.author` doit être un username GitHub valide (alphanumérique + tirets), `git.email`
est requis, et `sigma_repo_path` est validé contre le traversal/les chemins absolus. Le transport HTTP
exige un token (config ou env `GITHUB_TOKEN`) quand `needs_network()` est vrai — c.-à-d. `offline: false`
ou `contrib: true` ; un run entièrement offline (`offline: true` + `contrib: false`) n'a pas besoin de token.

**Offline / contrib :** `offline: true` utilise le repo existant tel quel (pas de pull, repo complet requis).
`contrib: true` active le push sur le fork à la fin ; par défaut (`false`) les commits restent locaux.
Les flags CLI `--offline` / `--contrib` forcent ces valeurs à `true`.

**CLI flags :** `--author <name>`, `--dry-run`, `--channels-only`, `--all-rules`, `--list-rules`, `--offline`, `--contrib`.

---

## 4. Pipeline détaillé

### Étape 1 — Init

```text
parse_args() → CliArgs
    ↓
Config::load_with_cli("config.yaml", cli)
    ├── manquant → écrit les défauts → exit(1) avec instructions
    └── --author <name> écrase git.author avant la validation
    ↓
--dry-run → dry_run_git() (diagnostics token/fork/API/info-refs) → exit
    ↓
[windows] setup_console() (codepage UTF-8 + traitement VT)
    ↓
init_logger(&config) → tracing (stderr info + fichier journal rolling debug)
```

### Étape 2 — Acquisition du repo

```text
ensure_dirs() → crée <sigma_repo_path>/ et logs/
    ↓
fork_url = "https://github.com/{author}/sigma"
    ↓
SigmaRepo::new()
    ├── set_info_user(author, email)
    ├── set_info_http(token) | set_info_ssh(key_path)
    ├── set_git_operations(offline, contrib)   # contrôle le pull au startup + le push final
    ├── set_remote_url(fork_url) → init() [async]
    │       ├── repo incomplet/absent + offline → bail actionnable
    │       ├── repo existant → pull étroit de la branche courante (skip si offline)
    │       └── sinon → clone complet (full-history, protocole v2) + pack
    ├── set_working_branch(branch_name)         # fetch branche ciblée (skip si offline) + create_branch
    │   └── switch_to_working_branch()          # matérialise l'arbre de la branche (miroir exact du commit)
    └── check_remote_working_branch()   # garde : rejette une branche du même jour orpheline/amputée
```

### Post-traitement : pack des objets loose

Le clone/fetch via grit-lib (`http_fetch`) écrit chaque objet reçu comme fichier **loose**
dans `.git/objects/xx/` (~131K fichiers, ~650 MB pour le repo Sigma) — grit n'a pas
d'équivalent `git gc --auto`. Après chaque clone/fetch (clone HTTP, clone SSH, pull HTTP,
pull SSH), `pack_loose_objects()` (`crates/sigmacatch-repo/src/plumbing/pack.rs`) consolide :

- collecte des loose objects (triés par OID) ;
- compression zlib (niveau défaut, **pas de delta**) **parallélisée** (rayon, chunks de 16K)
  puis sérialisation d'un pack **V2** + index `.idx` (magic `\xfftOc`, fanout, OIDs triés,
  table CRC32, offset table, checksums SHA-1) ;
- suppression des fichiers loose + répertoires `xx/` vides ;
- observabilité : messages de progression du serveur (`remote: Enumerating objects…`)
  relayés au log pendant le téléchargement.

Résultat : `.git/` passe de ~650 MB à ~218 MB (3x), `git fsck --full --strict` propre,
objets toujours lisibles via l'ODB (loose **ou** pack).

**Benchmark vs `git clone` natif** (fork `frack113/sigma`, branche master, Linux 24 cœurs) :

| | `git clone` natif | sigmacatch (grit + pack) |
|---|---|---|
| Temps clone frais | ~3s | ~70s (fetch ~50s + pack ~17s) |
| `.git/` | 52 MB | 218 MB |
| Pack | 47 MB (deltas) | 215 MB (sans delta) |

Écart : git natif écrit **directement** le pack delta-compressé du serveur ; grit décompresse
tout en loose puis on re-compresse **sans delta**. Le téléchargement lui-même est identique
(~47 MB). Coût payé **une seule fois** au premier clone — les pulls suivants ne transfèrent
que les deltas (sub-seconde si rien n'a changé). Sur une VM lente, le premier clone peut
prendre plusieurs minutes.

### Étape 3 — Skip set (régression existante)

```text
SigmahqRegression::new()            # charge ./sigma/regression_data
    └── scanne tous les info.yml (walk, profondeur 64, ignore les symlinks)
        └── permissif : dossier manquant → vide, pas une erreur
    ↓
existing_rules: HashSet<Uuid> = regression.get_sigma_id().collect()
    └── vide avec --all-rules
    ↓
SigmahqRules::new()                 # charge ./sigma
    ├── find_rules_dirs() → rules, rules-* (exclut rules-compliance, index.yml)
    ├── walk séquentiel, parse_sigma_yaml() par fichier
    ├── dédupe cross-file par id de règle (première occurrence gagne)
    └── pour chaque id dans existing_rules → rules.remove_id(&id)
    ↓
rules = rules.filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size })
    ├── stats() → rules_loaded, filtered_product/status/level/author
    ├── 0 règle chargée → bail avec un message d'erreur clair
    └── --list-rules → affiche id, titre, status/level, chemin relatif par règle + exit
```

> Les règles avec des données de régression existantes sont exclues du moteur Sigma — ce
> skip-at-load est la seule optimisation au chargement. Après génération, une règle est retirée
> et le moteur est rechargé en un seul batch (voir Étape 7).

### Étape 4 — Résolution des channels

```text
custom_map = load_custom_channel_mapping("custom_channels.yaml")   # manquant/vide → {}
    ↓
DetectionEngine::new(&rules)
    ├── charge les pipelines embarquées (flatten_winevt.yml, windows.yml) une fois
    ├── active bloom pre-filter + LogSourceExtractor
    ↓
cycle_channels = engine.resolve_channels(&custom_map)
    ├── lit CompiledRule.logsource post-pipeline → service:category → liste de channels (dédupliquée, triée)
    └── 0 channel → warn + return Ok (rien à collecter)
    ↓
--channels-only → affiche les channels + exit
```

### Étape 5 — Collecte continue

```text
output_base = <sigma_repo_path>/regression_data
clean_partial_artifacts(&output_base)     # supprime les dossiers avec json/evtx mais sans info.yml
    ↓
let (tx, rx) = mpsc::channel::<Event>(100_000)
    ↓
EventCollector::new(cycle_channels).run(tx, stop)   # task tokio, une task par channel
```

**Boucle par channel (`collect_continuous`, lancée via `spawn_blocking`) :**

```text
loop (jusqu'à stop):
    query = "*" si last_record_id == 0
            sinon "*[System[EventRecordID > {last_record_id}]]"
    EvtQuery(channel, query)
        ├── ERROR_EVT_CHANNEL_NOT_FOUND → error! une fois → exclusion permanente (return)
        └── autre erreur → warn! + sleep 5s → retry
    loop:
        EvtNext(batch de 32, timeout 5s)
            ├── timeout idle / plus d'items → break (re-query)
            └── erreur → warn! + sleep 5s → break
        pour chaque handle : EvtRender(EventXml) → Event::from_xml → inject_logsource_fields()
            └── tx.blocking_send(event)
        MAX_EVENTS (100k) atteint → arrêt du drain initial
    si 0 envoyé :
        ├── cycle_fetched > 0 → warn! "fetched N but 0 sent — dropped during render/parse"
        ├── premier cycle → info! "initial query OK — 0 events"
        ├── sinon heartbeat → info! "still alive" (toutes les 60s)
        └── probe rollover record-id (tous les 30 cycles vides) → reset last_record_id si besoin
    sinon :
        ├── premier drain → info! "initial drain collected N events"
        └── sinon progression → info! (toutes les 10s)
```

Le collecteur s'arrête quand `stop` est set (Ctrl+C) ou que le receiver est drop. Sur non-Windows,
chaque task de channel est un stub no-op.

### Étape 6 — Boucle d'events continue

```text
generate_interval = 30s (premier tick sauté immédiatement)
    ↓
loop:
    tokio::select! {
        shutdown_rx.changed()            → info "Shutting down" → break
        Some(event) = rx.recv()          → engine.put_events(vec![event])
        _ = generate_interval.tick()     → process_and_generate()
                                               → upload_regression() si fichiers créés
    }
```

### Étape 7 — process_and_generate

```text
engine.process_events() → engine.get_alerts()
    ├── alerts vides → return (pas de log "evaluation complete")
    ├── log stats : events_processed, matches_found (règles uniques), alerts_count
    └── pour chaque alert :
        regression.add(&alert) → Option<Vec<String>>
            ├── None si règle déjà retirée / Uuid::nil() / info.yml existant
            └── Some(files) :
                ├── RegressionData::for_rule(header, output_path, rule_rel_path, author, description)
                ├── écrit <rule_id>.json (event_json_raw du premier event matché, JSON pretty)
                ├── écrit <rule_id>.evtx via EvtExportLog (ou fallback .xml)
                ├── écrit info.yml
                ├── ajoute "regression_tests_path" au YAML de la règle source
                └── retire la règle (regression.retired + rules.remove_id)
    └── règles retirées → engine.reload_rules(rules)   # UN SEUL reload batch
    ↓
retourne batches: Vec<(Uuid, Vec<String>)>   # (rule_id, fichiers écrits) — vide si aucun alert
    ↓
upload_regression() → upload_rule_batches()   # dans sigmacatch-repo
    ├── un commit par règle : "test: add regression data for rule {rule_id}"
    ├── échec commit/push → rollback de la branche locale vers le tip pré-batch
    └── UN SEUL push si git.contrib: true (sinon commits locaux)
        └── succès → "Next step: create PR at https://github.com/SigmaHQ/sigma/pulls"
```

**Sortie :**

```text
<sigma_repo_path>/regression_data/<rule_rel_path>/
    ├── <rule_id>.json      # premier event matché (JSON Winevt brut, noms de clés EventData d'origine)
    ├── <rule_id>.evtx      # EVTX valide via EvtExportLog (ou fallback .xml)
    └── info.yml            # métadonnées compatibles SigmaHQ
```

`<rule_rel_path>` reflète le chemin de la règle sous `sigma/rules/` (ex.
`rules/windows/builtin/security/win_security_foo/`). La sortie vit toujours dans le repo sigma
et est commitée sur le fork si `git.contrib: true` (commits locaux sinon).

### Étape 8 — Arrêt / commit / push

```text
Ctrl+C → shutdown_rx.set(true)
    ↓
Flush final :
    await de la task collector (timeout 30s) → drain du rx restant → engine.put_events
    ↓
process_and_generate() → upload_regression() si fichiers
    ├── commit par règle ("test: add regression data for rule {id}")
    └── push() vers le fork si git.contrib: true
        └── succès → "Next step: create PR at https://github.com/SigmaHQ/sigma/pulls"
```

---

## 5. Structures de données clés

### Event (`sigmacatch-types`)

```rust
Event {
    event_json_raw: serde_json::Value,  // JSON Winevt brut (noms de clés EventData d'origine, espaces conservés) — utilisé pour la sortie regression
    event_json: serde_json::Value,      // JSON transformé pour la détection Sigma (espaces EventData supprimés)
    event_raw: Vec<u8>,                 // octets sources bruts (XML)
}
```

Méthodes publiques : `from_xml()`, `new()`, `record_id()`, `inject_logsource_fields()` (`channel()`,
`provider()` et `event_id()` sont privés). Le collecteur appelle `inject_logsource_fields()` qui injecte
`product`, `service`, `category` dans `event_json` ; le `LogSourceExtractor` du moteur lit ces champs
pour élaguer les règles incompatibles.

### Alert (`sigmacatch-types`)

```rust
Alert {
    rule_id: Uuid,               // parsé depuis l'id de la règle Sigma
    rule_title: String,
    description: Option<String>,
    rule_path: Option<PathBuf>,  // chemin du YAML de la règle source (relatif au repo sigma)
    severity: String,
    event_json_raw: serde_json::Value,  // JSON Winevt brut (noms de clés d'origine) — écrit dans <rule_id>.json
    event_json: serde_json::Value,      // JSON transformé pour la détection Sigma
    event_raw: Vec<u8>,
}
```

### SigmahqRegression (`sigmacatch-regression`)

```rust
struct SigmahqRegression {
    entries: Vec<(PathBuf, InfoYml, RegressionEntry)>,
    author: String,
    output_path: Option<PathBuf>,   // défaut ./sigma/regression_data
    retired: HashSet<Uuid>,
}
```

API : `new()` / `new_from_path()` (permissif), `set_author()` / `author()`, `len()` / `is_empty()`,
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

## 6. Modules clés

### DetectionEngine (`crates/sigmacatch-detection/src/lib.rs`)

- Charge les pipelines embarquées (`flatten_winevt.yml` + `windows.yml`) et les règles via rsigma-eval
- Active bloom pre-filter + LogSourceExtractor dans `new()` pour l'optimisation d'évaluation
- Cycle FIFO : `put_events()` / `process_events()` / `get_alerts()`
- `reload_rules(&SigmahqRules)` — reload batch après retrait de règles
- `resolve_channels(&custom_map)` — résout les channels depuis les logsources post-pipeline (voir §10)
- `rule_count()`, `stats()` (EngineStats), `explain_rule(rule_id, event)`, `save_hir` / `load_hir`
- Dépend de `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`

### SigmahqRules (`crates/sigmacatch-rule/src/lib.rs`)

- `new()` (hardcodé `./sigma`) / `new_from_path()` — walk + parse + dédupe
- `filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size })` → LoadStats
- `remove_id(&Uuid)`, `get(&Uuid)`, `rules()` / `iter()`, `to_collection()`, `rule_paths()`
- La résolution de channels n'est plus ici — elle vit dans `DetectionEngine::resolve_channels` (§10)

### EventCollector (`crates/input-windows-channels/src/lib.rs`)

- Collecteur Windows Event Log multi-channel, implémente `EventProducer` (module unique, plus de `collector.rs`)
- `new(channels)` → `run(self, tx, stop)` async ; une task blocking par channel
- Windows : EvtQuery → EvtNext (batch de 32, timeout 5s) → EvtRender → `Event::from_xml` → `inject_logsource_fields`
- Non-Windows : stub no-op
- Observabilité : exclusion permanente sur `ERROR_EVT_CHANNEL_NOT_FOUND` (un seul `error!`),
  logs de liveness ("initial query OK", "still alive" toutes les 60s, progression toutes les 10s),
  `warn!` quand des events sont fetchés mais perdus au render/parse, détection de rollover record-id

### EVTX Writer (`sigmacatch-regression/src/evtx.rs`)

- **Windows** : API `EvtExportLog` (winevt) — re-queries l'event par RecordID et exporte un `.evtx` binaire valide
  - `EvtExportLog(None, channel, query, path, EvtExportLogChannelPath | EvtExportLogOverwrite)`
  - **Limitation connue** : race condition avec la rétention du log — si l'event a été purgé entre la collecte et l'export, l'appel échoue silencieusement (`ERROR_EVT_QUERY_RESULT_STALE`)
- **Fallback** : XML brut écrit en `.xml` (pas `.evtx` — évite un binaire invalide qui casserait les outils en aval)
- **Non-Windows** : fallback XML brut en `.xml`

### Logger (`crates/sigmacatch-logger/src/lib.rs`)

- **Couche stderr** : niveau `info`, couleurs ANSI, filtrable via `RUST_LOG`
- **Couche fichier** : niveau `debug` (configurable), rotation journalière
- `logs/sigmacatch.YYYY-MM-DD.log`

---

## 7. Dépendances

| Dépendance | Usage |
|---|---|
| `grit-lib` | toutes les opérations git (clone, fetch, push, branch, commit, checkout) via HTTP, pure Rust |
| `reqwest` (blocking + async) | client HTTP pour le transport git |
| `rsigma-eval` + `rsigma-parser` | chargement/évaluation des règles Sigma |
| `tokio` | runtime async |
| `tracing` + `tracing-subscriber` | logging |
| `serde` / `serde_json` / `serde_yaml` | sérialisation config + event + regression |
| `anyhow` | gestion d'erreurs |
| `chrono` | dates |
| `uuid` | UUID v4 pour info.yml + ids de règles |
| `phf` | hash maps statiques pour les tables de taxonomie (dans `sigmacatch-types`) + résolution de channels (dans `sigmacatch-detection/src/channel_resolver.rs`) |
| `evtx` | parsing de fichiers EVTX (crate input-evtx, utilisé par localcheck/check_evtx) |
| `roxmltree` | parsing XML pour les events Winevt (dans `sigmacatch-types`) |
| `windows` | API Winevt (cfg-gated : windows uniquement, features : Foundation, System, Security, Com, Console, Threading) |
| `tempfile` (dev) | tests d'intégration |

**Supprimés :** `ratatui`, `crossterm`, `quick-xml`, `winevt-writer`, `tdh`, `ntapi`, `ferrisetw`

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
    [--author <name>]      # écrase git.author de la config
    [--dry-run]            # diagnostics git uniquement (pas de collecte)
    [--channels-only]      # affiche les channels résolus et exit
    [--all-rules]          # désactive le skip set (charge toutes les règles)
    [--list-rules]         # affiche les règles sans data-regression et exit
    [--offline]            # skip le pull au startup (force offline)
    [--contrib]            # active le push au remote fork
```

La config est auto-créée au premier run avec des défauts. Éditez `config.yaml` avant de lancer.

---

## 10. Pipelines embarquées & résolution de channels

### `windows.yml` (`crates/sigmacatch-detection/pipelines/`)

Pipeline de transformation embarquée (chargée via `include_str!` dans `sigmacatch-detection`), appliquée à chaque règle avant compilation :

- Mappe `logsource.category` → conditions Sysmon EventID via `add_condition`, gaté par `rule_conditions` (`type: logsource` avec filtres `category`, `product`, `service` ; toutes les conditions en logique AND).
- **rsigma-eval v0.21+** : `add_condition` accepte des séquences YAML (`conditions: {EventID: [17, 18]}`) dont les valeurs sont OR-liées, conformément au `AddConditionTransformation` de pySigma (API breaking : `AddCondition.conditions` est `HashMap<String, Vec<SigmaValue>>`). Une catégorie multi-EventID est une seule entrée de transformation (ex. `wmi_event` → `[19, 20, 21]`).
- **Filtres EventType registry** : `registry_add` = EventID 12 + `EventType: CreateKey`, `registry_set` = EventID 13 + `EventType: SetValue`, `registry_rename` = EventID 14 + `EventType: RenameKey`. **`registry_delete` n'a PAS de filtre EventType** — l'EventID 12 porte `DeleteKey` et `DeleteValue` (contrainte rsigma-eval), il matche donc sur le seul EventID 12.
- **`change_logsource` final (post-add_condition)** : un bloc `service: sysmon` par catégorie routée, même gate logsource `(category, product: windows)` que son `add_condition` → rend le logsource post-pipeline exploitable par `channel_resolver` (zéro mapping dupliqué category → service).
- `prepend` : ajoute la condition avant la détection existante (`new AND existing`) pour l'optimisation short-circuit.
- **Transformations supportées** : `field_name_mapping`, `field_name_prefix_mapping`, `field_name_prefix`, `field_name_suffix`, `drop_detection_item`, `add_condition`, `change_logsource`, `replace_string`, `value_placeholders`, `wildcard_placeholders`, `query_expression_placeholders`, `set_state`, `rule_failure`, `detection_item_failure`, `field_name_transform`, `hashes_fields`, `map_string`, `set_value`, `convert_type`, `regex`, `add_field`, `remove_field`, `set_field`, `set_custom_attribute`, `case_transformation`, `nest`, `include`.

`flatten_winevt.yml` : aplatit la structure XML Winevt imbriquée pour l'évaluation Sigma. Pipeline chargée une fois à l'init du moteur, appliquée à toutes les règles avant compilation.

### Résolution de channels (`crates/sigmacatch-detection/src/channel_resolver.rs`)

- **Post-pipeline logsource** : `resolve_channels` lit `CompiledRule.logsource` (post-pipeline, exposé publiquement par rsigma-eval 0.21) via `DetectionEngine::resolve_channels(&custom_map)` dans `main.rs` — résolution au moment de la création du moteur, aucun coût supplémentaire (pas de re-transform).
- `SERVICE_CHANNELS` : static `phf::Map<service, &[channel]>` — mapping service → channels Windows Event Log (runtime, pas une table générée).
- `CATEGORY_CHANNELS` : catégories que la pipeline ne route PAS (`ps_classic_*`, `ps_module`, `ps_script`).
- Lookup : `service` présent → `SERVICE_CHANNELS[service]` + `custom_map` (depuis `custom_channels.yaml`, `channel → service`) ; sinon `category` → `CATEGORY_CHANNELS[category]`.
- Les catégories Sysmon ne figurent **pas** dans la table — la pipeline les réécrit en `service: sysmon` (single source of truth dans `windows.yml`).
- Logsource non mappé → `warn!` (par logsource), aucun channel ; les règles non-Windows sont ignorées. Résultat : liste de channels dédupliquée et triée.
- `sigmacatch-types` reste propriétaire des tables de mapping inverses (`CHANNEL_TO_SERVICE`, `PROVIDER_TO_SERVICE`, `CHANNEL_EVENT_TO_CATEGORY`, `CHANNEL_EVENT_TO_SUBCATEGORY`) utilisées par `inject_logsource_fields()` (channel/provider → enrichment logsource).
