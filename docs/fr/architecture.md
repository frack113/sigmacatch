# Architecture

## Cargo workspace

Le projet est un cargo workspace de 13 packages (1 crate lib + 12 bibliothèques) :

```text
sigmacatch/
├── Cargo.toml                    # Racine workspace
├── crates/
│   ├── sigmacatch-config/        # Config YAML + parsing CLI + custom_channels.yaml
│   ├── sigmacatch-logger/        # Abonnement tracing à deux couches (stderr `error` par défaut / `info` avec `-v`, fichier rolling debug)
│   ├── sigmacatch-rule/          # SigmahqRules : chargement de règles (parse_sigma_yaml), filtre, dédupe, remove_id + SigmaRuleExt (techniques ATT&CK)
│   ├── sigmacatch-detection/     # Wrapper DetectionEngine + pipelines embarquées (windows.yml, flatten_winevt.yml) + channel_resolver
│   ├── input-windows-channels/   # Collecteur Winevt multi-channel (cfg(windows))
│   ├── input-windows-etw/        # Collecteur ETW direct via ferrisetw (18 providers, routing générique provider→channel)
│   ├── input-linux-auditd/       # Collecteur auditd (tail /var/log/audit/audit.log, grouping par event id)
│   ├── sigmacatch-regression/    # SigmahqRegression (get_sigma_id, add, retire), InfoYml, DataFormat
│   ├── sigmacatch-types/         # Types partagés : Event, Alert, RegressionHeader + parsing XML + tables de mapping logsource
│   ├── sigmacatch-repo/          # wrapper grit-lib + SigmaRepo + opérations git
│   ├── sigmacatch-evtx-writer/   # Writer EVTX pur Rust (sans API winevt) + validation re-parse
│   └── input-evtx/               # Parser fichiers EVTX → Event
└── sigmacatch/                   # Lib + 3 binaires (boucle continue)
    └── src/
        ├── lib.rs                # runner partagé (pipeline commun aux 3 binaires)
        ├── runner.rs             # Config + init repo + boucle continue + process_and_generate + commit/push
        ├── main_winevt.rs        # bin `sigmacatch-channel` : collecteur Winevt multi-channel
        ├── main_etw.rs           # bin `sigmacatch-etw` : collecteur ETW direct (ferrisetw)
        ├── main_auditd.rs        # bin `sigmacatch-auditd` : collecteur auditd (tail)
        └── cli.rs                # Sous-commandes de diagnostic (check, check-filter, check-channels, list-rules, get-atomic)
```

## Collecteurs

Trois binaires sont produits, chacun embarquant un seul collecteur (features cargo `winevt`/`etw`/`auditd`, `required-features` par bin) :

| Binaire | Crate | Description |
|---|---|---|
| `sigmacatch-channel` | `input-windows-channels` | API Winevt native (`EvtQueryW`/`EvtNext`/`EvtRender`), multi-channel, rejouable |
| `sigmacatch-etw` | `input-windows-etw` | Collecte ETW directe via ferrisetw, 18 providers (9 Sysmon-masquerade + 9 génériques), routing générique provider→channel, EventID réel conservé [beta] |
| `sigmacatch-auditd` | `input-linux-auditd` | Tail de `/var/log/audit/audit.log`, parsing linux-audit-parser, groupement par event id (`timestamp:sequence`), logsource `product:linux, service:auditd, provider:auditd` |

Le collecteur ETW couvre les mêmes channels que le collecteur Winevt (Security, Defender, Firewall, Sysmon, …) en résolvant provider→channel à partir d'une table de mapping, et en gardant le vrai EventID. Pour les providers génériques, les champs `EventData` sont fournis par des field maps par provider (fidelité variable). Sur non-Windows, le collecteur ETW est un stub no-op avec un `warn!`.

Il n'y a pas de `config.rs` / `logger.rs` / `repo.rs` dans le binaire — ces modules ont été
déplacés dans les crates `sigmacatch-config`, `sigmacatch-logger` et `sigmacatch-repo`.

## Graphe de dépendances

```text
sigmacatch ──┬── sigmacatch-config       (Config, CliArgs, )
               ├── sigmacatch-logger       (init tracing)
               ├── sigmacatch-rule         (SigmahqRules : load/filter/remove_id)
               ├── sigmacatch-detection    (DetectionEngine : pipelines + bloom + LogSourceExtractor + resolve_channels)
               ├── input-windows-channels  (feature winevt, bin `sigmacatch-channel`)
               ├── input-windows-etw       (feature etw, bin `sigmacatch-etw`)
               ├── input-linux-auditd      (feature auditd, bin `sigmacatch-auditd`)
               ├── sigmacatch-regression   (SigmahqRegression : skip set + génération données)
               ├── sigmacatch-evtx-writer  (writer EVTX pur Rust + validation)
               ├── sigmacatch-types        (Event, Alert, RegressionHeader, Product, EventProducer, parsing XML)
               └── sigmacatch-repo         (SigmaRepo, wrapper grit-lib)
               [tools] clap, serde, input-evtx, input-linux-auditd
```

`sigmacatch-detection` dépend de `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`.
`input-windows-channels` dépend de `sigmacatch-types` pour les types partagés et les tables de
mapping logsource. `sigmacatch-regression` dépend de `sigmacatch-types`. `sigmacatch-rule`
dépend de `rsigma-parser`. `sigmacatch-config` dépend de `sigmacatch-repo` + `sigmacatch-rule`.
Les sous-commandes de diagnostic (`cli.rs`) utilisent `clap`, `serde`, `input-evtx` et
`input-linux-auditd` (feature `tools`, désactivée par défaut).

## Pipeline (boucle continue)

```text
1. parse_args() + Config::load_with_cli("config.yaml", cli)
2. init_logger(verbose) → tracing (stderr `error` par défaut, `info` avec `-v`, fichier debug)
3. ensure_dirs() → dossier repo sigma + logs/
4. SigmaRepo init (remote_url = fork, branche de travail, token) → init() [clone/fetch] — no-op en offline (pas de `.git` requis)
   └── set_git_operations(offline, contrib) → set_working_branch() → check_remote_working_branch() (garde sur branche du même jour) ; offline → contrib forcé à false, toutes les ops no-op
5. SigmahqRegression::new() → charge les info.yml existants depuis ./sigma/regression_data
   └── existing_rules = regression.get_sigma_id() ∪ sigma_repo.pending_regression_rule_ids() (branches remote sigmacatch/* en attente ; scan sauté en offline) → HashSet<Uuid> (vide avec --all-rules)
6. SigmahqRules::new() → chargement + dédupe ; remove_id() par règle skipée
    └── filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size }) ; 0 règles → bail
7. custom_map = load_custom_channel_mapping("custom_channels.yaml")
8. DetectionEngine::new(&rules)  (pipelines + bloom + LogSourceExtractor)
   └── cycle_channels = engine.resolve_channels(&custom_map) ; 0 channels → warn + return
9. output_base = <sigma_repo_path>/regression_data ; clean_partial_artifacts()
10. runner::run(kind) — le collecteur est injecté par chaque bin via le trait `CollectorKind` :
    ├── sigmacatch-channel (winevt)  → EventCollector::new(cycle_channels).run(tx, stop)
    ├── sigmacatch-etw (etw) → EventCollector::new().run(tx, stop) (pas de channels, routing provider→channel interne)
    └── sigmacatch-auditd (auditd) → EventCollector::new().run(tx, stop) (tail audit.log, pas de channels)
11. Boucle : tokio::select!
    ├── shutdown_rx (Ctrl+C) → break
    ├── event depuis rx → engine.put_events(vec![event])
    └── generate_interval (30s) → process_and_generate() → upload_regression() si fichiers
12. Flush final : drain des events restants → process_and_generate() → upload_regression() (commit par règle) → push unique si contrib
```

`process_and_generate()` :

```text
engine.process_events() → get_alerts()
    ├── alerts vides → return (pas de log "evaluation complete")
    ├── log stats (events_processed, matches_found, alerts_count)
    └── pour chaque alert : regression.add(&alert) → Option<Vec<String>>
         ├── None si règle déjà retirée / pas d'id valide / info.yml existant
         └── Some(files) → écrit les fichiers + regression_tests_path + retire la règle
    └── règles retirées → rules.remove_id() → engine.reload_rules() (un seul reload batch)
    ↓
retourne batches: Vec<(Uuid, Vec<String>)>  (règles générées + fichiers écrits)
    ↓
upload_regression() → upload_rule_batches() (dans sigmacatch-repo)
     ├── un commit par règle : "🧪 test: add regression data for rule {rule_id}"
    ├── échec commit/push → rollback de la branche locale vers le tip pré-batch
    └── UN SEUL push si git.contrib: true (sinon commits locaux) → message PR
```

## Notes de conception

- **Skip set** = `HashSet<Uuid>` depuis `SigmahqRegression::get_sigma_id()` (info.yml existants + données valides)
  ∪ `SigmaRepo::pending_regression_rule_ids()` (arbres des branches remote `sigmacatch/*` :
  PR en attente non mergés — une VM fraîche ne recapture pas leurs données),
  construit une seule fois au démarrage. `--all-rules` le désactive. Après génération, une règle
  est retirée et le moteur est rechargé en un seul batch (`engine.reload_rules`).
  Les règles dont les données commitées sont invalides (EVTX cassé / texte vide) sont exclues du skip set → régénérées.
- **Output toujours dans le repo sigma** : `<sigma_repo_path>/regression_data/<rule_rel_path>/`
  (`info.yml` + fichier de données `.evtx`/`.log`, `.json` optionnel), commité sur le fork si `contrib` (commits locaux sinon).
- **Collecteur observable** : les channels inexistants sont exclus une fois pour toutes sur
  `ERROR_EVT_CHANNEL_NOT_FOUND` (un seul `error!`) ; chaque channel vivant log « initial query OK »
  puis un heartbeat « still alive » (60s) ; `warn!` quand des events sont fetchés mais perdus au
  render/parse.

> Les détails du skip set et les décisions de conception clés sont documentés dans ce fichier (section *Notes de conception*).
