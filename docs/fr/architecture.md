# Architecture

## Arborescence

```
src/
├── main.rs              # Binaire + pipeline (run_pipeline, Stats, AggregatedRule)
├── config.rs            # Config YAML (serde, Default) avec LogConfig
├── logger.rs            # Abonnement tracing à deux couches (stderr info + fichier debug)
├── sigma/
│   ├── loader.rs        # gix clone/pull + offline + find_rules_dirs()
│   └── engine.rs        # SigmaEngine: load rules (post-parse filter), evaluate events, evaluation des règles
├── collector/
│   ├── mod.rs           # pub mod winevt
│   └── winevt.rs        # WinevtCollector (EvtQueryW, EvtNext, EvtRender)
├── evtx/
│   └── writer.rs        # write_evtx() via EvtExportLog API (→ EVTX valide ou .xml fallback)
├── parser/
│   └── mod.rs           # XmlParser (Winevt XML → JSON plat)
└── regression/
    ├── mod.rs           # SkipSet, build_skip_set(), validate_rule_id(), triplet validation
    ├── generator.rs     # RegressionData: aggregate + write output
    └── info_yml.rs      # InfoYml struct (rule_metadata, regression_tests_info)
```

## Pipeline (single run, sequential)

1. Load config (create `config.yaml` with defaults if missing)
2. Create directories: `regression_data/`, `regression_data/rules/`
3. Acquire SigmaHQ rules via `gix` (clone); `--offline` uses existing repo; exit error if no rules found
4. `find_rules_dirs()` scans `sigma/` for `rules` / `rules-*` dirs (excludes `rules-compliance`)
5. Build skip set by scanning `regression_data/rules/` + `sigma/regression_data/` for existing `info.yml` → `HashSet<String>` of rule IDs
6. Load Sigma rules from all `rules*` dirs, **excluding skipped rule IDs**; post-parse filter via `rule.logsource.product` filters non-Windows rules (seule optimisation autorisée)
7. Collect events via `WinevtCollector` (channels from config) → `Vec<WinevtEvent>`:
   - Chaque event porte `event_json: Option<Value>` (pré-parsé par le collector, fallback XmlParser si None)
   - Each event's `LogSource` est dérivé du **channel** via `resolve_logsource` (channel → service > provider → service > default)
   - Evaluate against **all loaded rules** via `evaluate_event_with_logsource(event, logsource)` — **aucun event perdu**
   - Aggregate matches by `rule_id` in `HashMap<String, AggregatedRule>`
8. Generate regression for rules without existing `info.yml` (skip at generate time too)
9. Write: `<output>/<rule_rel_path>/<rule_id>.json` (first matched event) + `<rule_id>.evtx` + `info.yml`; append `regression_tests_path` line to the source rule YAML

## Invariants architecturaux (fondations non négociables)

- Pipeline 100% séquentiel : acquérir règles → charger moteur → collecter events → matcher → générer
- Tout en RAM : aggregation en mémoire avant écriture (pas de DB intermédiaire)
- Un run = cycle complet (pas de mode "juste collect" ou "juste generate")
- Collecte Windows via **Winevt API** (`windows` crate, `EvtQueryW`/`EvtNext`/`EvtRender`) — pas d'ETW, pas de ferrisetw
- Output = `regression_data/<rule_rel_path>/` (triplet: `<rule_id>.json` + `<rule_id>.evtx` + `info.yml` format SigmaHQ)
- **Moteur temps réel** : `rsigma-eval` chargé une fois avec toutes les règles non skipées ; chaque event est évalué contre toutes les règles chargées. Aucun event perdu. Le skip-at-load est l'unique optimisation.
- **LogSource dérivée du channel ETW** (`resolve_logsource`), avec provider comme fallback.
  - Priority: channel → service > provider → service > default
  - Voir `# INVARIANT:` comment in `src/sigma/mapping/mod.rs`
- **EVTX via `EvtExportLog`** : re-queries l'event par RecordID depuis le live log. Si succès → `.evtx` binaire valide. Si échec (event purgé) ou non-Windows → fallback `.xml` (raw XML, pas de binaire invalide).
  - **Known limitation** : race condition avec la rétention du log — si l'event a été purgé entre la collecte et l'export, `EvtExportLog` échoue silencieusement (`ERROR_EVT_QUERY_RESULT_STALE`).

> Skip set details, key design decisions, and skip set construction logic are in [`architecture-reference.md`](architecture-reference.md) (Stages 2, 5, 6, 7).
