# Architecture

## Cargo workspace

Le projet est un cargo workspace de 7 crates :

```
sigmacatch/
├── Cargo.toml           # Racine workspace
├── crates/
│   ├── detection-engine/      # Wrapper fin autour de rsigma-eval pour pipelines et règles
│   ├── input-evtx/            # Parse les fichiers EVTX en objets Event
│   ├── input-windows-channels/ # Collecteur Winevt (EventProducer) + taxonomie via sigmacatch-types
│   ├── sigma-regression/      # InfoYml, SkipSet, validation triplet (format régression SigmaHQ)
│   └── sigmacatch-types/      # Types partagés : Event, Alert, RegressionHeader + parsing XML
└── sigmacatch/          # Binaire + pipeline
    └── src/
        ├── main.rs
        ├── bin/evtx_check.rs
        └── ...
```

## Arborescence (`sigmacatch/src/`)

```
sigmacatch/src/
├── main.rs              # Binaire + pipeline (run_pipeline, Stats, AggregatedRule)
├── lib.rs               # Déclarations pub mod
├── config.rs            # Config YAML (Config, SigmaFilterConfig, MinStatus, MinLevel)
├── logger.rs            # Abonnement tracing à deux couches (stderr info + fichier debug)
├── repo.rs              # wrapper grit-lib + SigmaRepo (clone/fetch/push/commit/branch)
├── github/
│   ├── mod.rs           # pub mod commit, fork
│   ├── commit.rs        # Workflow de commit avec validation author/email
│   └── fork.rs          # Détection de fork via API GitHub
└── bin/
    └── evtx_check.rs    # Outil de validation batch
```

## Graphe de dépendances

```
sigmacatch ──┬── detection-engine        (wrapper rsigma-eval + pipelines + bloom/logsource optimizations)
             ├── input-windows-channels  (collecteur Winevt + inject_logsource_fields via Event)
             ├── input-evtx              (parser fichiers EVTX → Event + inject_logsource_fields)
             ├── sigmacatch-types        (Event, Alert, RegressionHeader, Product, parsing XML, tables de mapping logsource)
             └── sigma-regression        (InfoYml, SkipSet, triplet)
```

`detection-engine` est indépendant (dépend uniquement de `sigmacatch-types` + `rsigma-eval`). `input-windows-channels` dépend de `sigmacatch-types` pour les types partagés et les tables de mapping. `sigmacatch` dépend des 5 crates, ainsi que de crates externes (`rsigma-eval`, `grit-lib`, `tokio`, `windows`, etc.).

## Pipeline (single run, sequential)

1. Load config (create `config.yaml` with defaults if missing)
2. Create directories: `regression_data/`, `regression_data/rules/`
3. Acquire SigmaHQ rules via `grit-lib` (clone); exit error if no rules found
4. `find_rules_dirs()` scans `sigma/` for `rules` / `rules-*` dirs (excludes `rules-compliance`)
5. Build skip set by scanning `regression_data/rules/` + `sigma/regression_data/` for existing `info.yml` → `HashSet<String>` of rule IDs
6. Load Sigma rules from all `rules*` dirs, **excluding skipped rule IDs**; post-parse filter via `rule.logsource.product` filters non-Windows rules; status/level filter via `config.sigma.min_status`/`min_level` (seule optimisation autorisée) — une table de règles est affichée au démarrage (chargées / skipées / services actifs). Le `RuleIndex` mappe chaque rule ID à son `Product` pour un accès filtré par produit.
7. Collect events via les collectors (`EventCollector`, `EVTXCollector`) → `Vec<Event>`:
   - Chaque event porte `event_json: Value` (pré-parsé par le collector, fallback `parse_winevt_xml`)
   - Les collectors injectent `product`, `service`, `category` via `Event::inject_logsource_fields()` avant l'envoi
   - Le moteur utilise `LogSourceExtractor` + bloom pre-filter de rsigma-eval pour elaguer les regles incompatibles
   - Evaluate against **all loaded rules** via FIFO API: `engine.put_events(events) → engine.process_events() → engine.get_alerts()` — **aucun event perdu**
   - Aggregate matches by `rule_id` in `HashMap<String, AggregatedRule>`
8. Generate regression for rules without existing `info.yml` (skip at generate time too)
9. Write: `<output>/<rule_rel_path>/<rule_id>.json` (first matched event) + `<rule_id>.evtx` + `info.yml`; append `regression_tests_path` line to the source rule YAML

> Skip set details, key design decisions, and skip set construction logic are in [`architecture-reference.md`](architecture-reference.md) (Stages 2, 5, 6, 7).
