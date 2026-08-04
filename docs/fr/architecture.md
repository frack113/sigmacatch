# Architecture

## Cargo workspace

Le projet est un cargo workspace de 11 packages (2 crates binaires + 9 bibliothèques) :

```
sigmacatch/
├── Cargo.toml                    # Racine workspace
├── crates/
│   ├── sigmacatch-config/        # Config YAML + parsing CLI + custom_channels.yaml + diagnostics git dry-run
│   ├── sigmacatch-logger/        # Abonnement tracing à deux couches (stderr info + fichier journal rolling debug)
│   ├── sigmacatch-rule/          # SigmahqRules : chargement de règles (parse_sigma_yaml), filtre, dédupe, channels()
│   ├── sigmacatch-detection/     # Wrapper DetectionEngine + pipelines embarquées (windows.yml, flatten_winevt.yml)
│   ├── input-windows-channels/   # Collecteur Winevt multi-channel (cfg(windows))
│   ├── sigmacatch-regression/    # SigmahqRegression (get_sigma_id, add, retire), InfoYml, triplet
│   ├── sigmacatch-types/         # Types partagés : Event, Alert, RegressionHeader + parsing XML + tables de mapping logsource
│   ├── sigmacatch-repo/          # wrapper grit-lib + SigmaRepo + opérations git
│   └── input-evtx/               # Parser fichiers EVTX → Event
├── sigmacatch/                   # Binaire + orchestration
│   └── src/
│       └── main.rs               # Config + init repo + boucle continue + process_and_generate + commit/push
└── localcheck/                   # Outils de dev (hors du crate principal)
    └── src/
        ├── check_filter.rs       # Valide SigmaFilterConfig contre les vraies règles Sigma (comptage ground-truth)
        └── check_evtx.rs         # Validation batch du moteur Sigma contre les données .evtx
```

## Arborescence

```
sigmacatch/src/
└── main.rs              # Binaire : orchestration, boucle continue, process_and_generate

localcheck/src/
├── check_filter.rs      # Outil de validation des filtres (pas d'args CLI, charge ./sigma lui-même)
└── check_evtx.rs        # Outil de validation batch (exit 1 sur entrée vide / aucun match)
```

Il n'y a pas de `config.rs` / `logger.rs` / `repo.rs` dans le binaire — ces modules ont été
déplacés dans les crates `sigmacatch-config`, `sigmacatch-logger` et `sigmacatch-repo`.

## Graphe de dépendances

```
sigmacatch ──┬── sigmacatch-config       (Config, CliArgs, diagnostics dry-run)
             ├── sigmacatch-logger       (init tracing)
             ├── sigmacatch-rule         (SigmahqRules : load/filter/remove_id/channels)
             ├── sigmacatch-detection    (DetectionEngine : pipelines + bloom + LogSourceExtractor)
             ├── input-windows-channels  (EventCollector : Winevt multi-channel)
             ├── sigmacatch-regression   (SigmahqRegression : skip set + génération triplet)
             ├── sigmacatch-types        (Event, Alert, RegressionHeader, Product, EventProducer, parsing XML)
             └── sigmacatch-repo         (SigmaRepo, wrapper grit-lib)

localcheck ──┬── sigmacatch-rule         (SigmahqRules + SigmaFilterConfig)
             ├── sigmacatch-detection    (DetectionEngine)
             ├── sigmacatch-regression   (SigmahqRegression)
             └── input-evtx              (parse_evtx_bytes)
```

`sigmacatch-detection` dépend de `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`.
`input-windows-channels` dépend de `sigmacatch-types` pour les types partagés et les tables de
mapping logsource. `sigmacatch-regression` dépend de `sigmacatch-types`. `sigmacatch-rule`
dépend de `rsigma-parser`. `sigmacatch-config` dépend de `sigmacatch-repo` + `sigmacatch-rule`.

## Pipeline (boucle continue)

```
1. parse_args() + Config::load_with_cli("config.yaml", cli)
   └── --dry-run → dry_run_git() (diagnostics git) + sortie
2. init_logger() → tracing (stderr info + fichier debug)
3. ensure_dirs() → dossier repo sigma + logs/
4. SigmaRepo init (remote_url = fork, branche de travail, token) → init() [clone/fetch]
   └── set_working_branch() → check_remote_working_branch() (garde sur branche du même jour)
5. SigmahqRegression::new() → charge les info.yml existants depuis ./sigma/regression_data
   └── existing_rules = regression.get_sigma_id() → HashSet<Uuid> (vide avec --all-rules)
6. SigmahqRules::new() → chargement + dédupe ; remove_id() par règle skipée
    └── filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size }) ; 0 règles → bail
    └── --list-rules → affiche les règles sans data-regression + sortie
7. custom_map = load_custom_channel_mapping("custom_channels.yaml")
   └── cycle_channels = rules.channels(&custom_map) ; 0 channels → warn + return
8. DetectionEngine::new(&rules)  (pipelines + bloom + LogSourceExtractor)
   └── --channels-only → affiche les channels + sortie
9. output_base = <sigma_repo_path>/regression_data ; clean_partial_artifacts()
10. EventCollector::new(cycle_channels).run(tx, stop) → task tokio
11. Boucle : tokio::select!
    ├── shutdown_rx (Ctrl+C) → break
    ├── event depuis rx → engine.put_events(vec![event])
    └── generate_interval (30s) → process_and_generate() → upload_regression() si fichiers
12. Flush final : drain des events restants → process_and_generate() → commit → push() fork
```

`process_and_generate()` :

```
engine.process_events() → get_alerts()
    ├── alerts vides → return (pas de log "evaluation complete")
    ├── log stats (events_processed, matches_found, alerts_count)
    └── pour chaque alert : regression.add(&alert) → Option<Vec<String>>
         ├── None si règle déjà retirée / pas d'id valide / info.yml existant
         └── Some(files) → écrit le triplet + regression_tests_path + retire la règle
    └── règles retirées → rules.remove_id() → engine.reload_rules() (un seul reload batch)
```

## Notes de conception

- **Skip set** = `HashSet<Uuid>` depuis `SigmahqRegression::get_sigma_id()` (info.yml existants),
  construit une seule fois au démarrage. `--all-rules` le désactive. Après génération, une règle
  est retirée et le moteur est rechargé en un seul batch (`engine.reload_rules`).
- **Output toujours dans le repo sigma** : `<sigma_repo_path>/regression_data/<rule_rel_path>/`
  (triplet `info.yml` + `<rule_id>.json` + `<rule_id>.evtx`), commité sur le fork.
- **Collecteur observable** : les channels inexistants sont exclus une fois pour toutes sur
  `ERROR_EVT_CHANNEL_NOT_FOUND` (un seul `error!`) ; chaque channel vivant log « initial query OK »
  puis un heartbeat « still alive » (60s) ; `warn!` quand des events sont fetchés mais perdus au
  render/parse.

> Les détails du skip set et les décisions de conception clés sont dans [`architecture-reference.md`](architecture-reference.md).
