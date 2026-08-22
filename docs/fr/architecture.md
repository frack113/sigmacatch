# Architecture

## Cargo workspace

Le projet est un cargo workspace de 12 packages (2 crates binaires + 10 bibliothèques) :

```text
sigmacatch/
├── Cargo.toml                    # Racine workspace
├── sigmacatch-win/               # Binaires Windows (lib + 2 bins)
│   └── src/
│       ├── lib.rs                # pub use sigmacatch-runner + modules channels/etw
│       ├── main_winevt.rs        # bin `sigmacatch-channel` : collecteur Winevt multi-channel
│       ├── main_etw.rs           # bin `sigmacatch-etw` : collecteur ETW direct (ferrisetw)
│       ├── channels.rs           # Collecteur Winevt (EvtQueryW/EvtNext/EvtRender, multi-channel)
│       ├── etw/                  # Collecteur ETW direct : providers.rs (18 providers), field_maps,
│       │                         #   enrich, mapper, process_table, process_query, sysmon, paths, pe, filekey
│       └── cli.rs                # Sous-commandes de diagnostic (feature `tools`) : check, check-filter,
│                                 #   check-channels, list-rules, get-atomic
├── sigmacatch-lnx/               # Binaire Linux (lib + 1 bin)
│   └── src/
│       ├── lib.rs
│       ├── main_linux.rs         # bin `sigmacatch-linux` : choisit auditd ou syslog au démarrage
│       ├── auditd.rs             # Collecteur auditd (tail /var/log/audit/audit.log, groupement par event id)
│       ├── syslog.rs             # Collecteur syslog central (/var/log/messages → /var/log/syslog, RFC3164)
│       └── cli.rs                # Sous-commandes de diagnostic (feature `tools`) : check, check-filter, list-rules
└── crates/
    ├── sigmacatch-runner/        # Pipeline partagé aux 2 crates binaires :
    │   └── src/runner.rs         #   run<C: CollectorKind> + trait CollectorKind (config + repo init +
    │                             #   event loop + process_and_generate + commit/push)
    ├── sigmacatch-config/        # Config YAML + parsing CLI + custom_channels.yaml
    ├── sigmacatch-logger/        # Abonnement tracing à deux couches (stderr `error` par défaut / `info` avec `-v`, fichier rolling debug)
    ├── sigmacatch-rule/          # SigmahqRules : chargement de règles (parse_sigma_yaml), filtre, dédupe, remove_id
    │                             #   + attack.rs (SigmaRuleExt ATT&CK) + discover.rs + thresholds.rs (LoadStats)
    ├── sigmacatch-detection/     # Wrapper DetectionEngine + pipelines embarquées (windows.yml, flatten_winevt.yml) + channel_resolver
    ├── sigmacatch-regression/    # SigmahqRegression (get_sigma_id, add, retire), InfoYml, DataFormat
    │                             #   (evtx.rs, format.rs, info.rs, logtype.rs, long_path.rs)
    ├── sigmacatch-types/         # Types partagés : Event, Alert, RegressionHeader + parsing XML + tables de mapping logsource
    ├── sigmacatch-repo/          # wrapper grit-lib + SigmaRepo + opérations git + signing.rs + transport.rs
    ├── sigmacatch-evtx-writer/   # Writer EVTX pur Rust (events ETW / sans record id — pas d'EvtExportLog possible)
    └── input-windows-evtx/       # Parser fichiers EVTX → Event (feature `tools` du bin winevt)
```

## Collecteurs

Trois binaires sont produits depuis deux crates, chacun embarquant un seul collecteur (features cargo `winevt`/`etw` et `auditd`/`builtin`, `required-features` par binaire) :

| Binaire | Crate | Description |
|---|---|---|
| `sigmacatch-channel` | `sigmacatch-win/src/channels.rs` | API Winevt native (`EvtQueryW`/`EvtNext`/`EvtRender`), multi-channel, rejouable |
| `sigmacatch-etw` | `sigmacatch-win/src/etw/` | Collecte ETW directe via ferrisetw, 18 providers (9 Sysmon-masquerade + 9 génériques), routing générique provider→channel, EventID réel conservé [beta] |
| `sigmacatch-linux` | `sigmacatch-lnx/src/{auditd,syslog}.rs` | Auto-détection au démarrage : **auditd** si `/var/log/audit/audit.log` existe (tail, parsing linux-audit-parser, groupement par event id `timestamp:sequence`, logsource `product:linux, service:auditd`) ; sinon **syslog central** (`/var/log/messages` puis `/var/log/syslog`, lignes RFC3164, service dérivé du program tag). Aucune des deux sources → bail. Format de régression `DataFormat::Log` |

Le collecteur ETW couvre les mêmes channels que le collecteur Winevt (Security, Defender, Firewall, Sysmon, …) en résolvant provider→channel à partir d'une table de mapping, et en gardant le vrai EventID. Pour les providers génériques, les champs `EventData` sont fournis par des field maps par provider (fidelité variable). Sur non-Windows, les collecteurs Winevt/ETW sont des stubs no-op.

Chaque binaire définit son propre `CollectorKind` dans son `main_*.rs` (`name()`/`mode()`/`channels()`/`build()`/`regression_format()`) et l'injecte dans `sigmacatch_runner::run()`. Le format de régression est choisi par `regression_format()` : `DataFormat::Evtx` pour les deux bins Windows, `DataFormat::Log` pour `sigmacatch-linux`.

## Graphe de dépendances

```text
sigmacatch-win ──┬── sigmacatch-runner      (run<C: CollectorKind>, pipeline partagé)
sigmacatch-lnx ──┤   ├── sigmacatch-config      (Config, CliArgs)
                 │   ├── sigmacatch-logger      (init tracing)
                 │   ├── sigmacatch-rule        (SigmahqRules : load/filter/remove_id)
                 │   ├── sigmacatch-detection   (DetectionEngine : pipelines + bloom + LogSourceExtractor + resolve_channels)
                 │   ├── sigmacatch-regression  (SigmahqRegression : skip set + génération données)
                 │   ├── sigmacatch-types       (Event, Alert, RegressionHeader, Product, EventProducer, parsing XML)
                 │   └── sigmacatch-repo        (SigmaRepo, wrapper grit-lib)
                 ├── [win tools] input-windows-evtx (parse EVTX → Event pour `check`)
                 └── [tools] clap, serde
```

`sigmacatch-detection` dépend de `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`.
Les collecteurs vivent dans leur crate binaire et ne dépendent que de `sigmacatch-types`
(types partagés + tables de mapping logsource). `input-windows-evtx` dépend de
`sigmacatch-types` + la crate `evtx`. Les sous-commandes de diagnostic (`cli.rs`)
utilisent `clap` + `serde` (feature `tools`, désactivée par défaut).

## Pipeline (boucle continue)

```text
1. parse_args() + Config::load_with_cli("config.yaml", cli)
2. setup_console() (Windows) ; init_logger(&config, verbose) → tracing (stderr `error` par défaut, `info` avec `-v`, fichier debug)
3. ensure_dirs() → dossier repo sigma + logs/
4. SigmaRepo init : set_info_user/set_info_http|ssh (+ ensure_ssh_host_config si ssh+réseau),
   set_signing_key (si ssh_key_path), set_git_operations(offline, contrib),
   set_remote_url(fork) → set_working_branch(sigmacatch/<date>) → check_remote_working_branch()
   — no-op complet en offline (pas de `.git` requis, fichiers locaux tels quels)
5. SigmahqRegression::new() → set_author/max_failed_cycles/format(kind)/add_json_output
   └── existing_rules = regression.get_sigma_id() ∪ sigma_repo.pending_regression_rule_ids()
       (branches remote sigmacatch/* en attente ; scan sauté en offline) → HashSet<Uuid> (vide avec --all-rules)
6. SigmahqRules::new() → chargement + dédupe ; remove_id(existing_rules)
    └── filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size }) ; 0 règles → bail
7. custom_map = load_custom_channel_mapping("custom_channels.yaml")
8. DetectionEngine::new(&rules)  (pipelines + bloom + LogSourceExtractor)
   └── cycle_channels = kind.channels(&engine, &custom_map)
       ├── Some(vide) (winevt sans channel résolu) → warn + return
       └── None (etw, linux) → pas de résolution de channels
9. Handler Ctrl+C (watch channel) ; output_base = <sigma_repo_path>/regression_data ;
   clean_partial_artifacts()
10. collector = kind.build(&cycle_channels) → tokio::spawn(collector.run(tx, stop))
    ├── sigmacatch-channel (winevt)  → EventCollector::new(cycle_channels).run(tx, stop)
    ├── sigmacatch-etw (etw) → EventCollector::new().run(tx, stop) (routing provider→channel interne)
    └── sigmacatch-linux (auditd/syslog) → EventCollector::new().run(tx, stop) (tail, rotation détectée)
11. Boucle : tokio::select!
    ├── shutdown_rx (Ctrl+C ou --max-runs atteint) → break
    ├── event depuis rx → engine.put_events(vec![event])
    └── generate_interval (30s) → spawn_blocking(process_and_generate) → upload_regression() si fichiers
12. Flush final : arrêt collector (timeout 10s, abort sinon) → drain des events restants (timeout 5s)
    → process_and_generate() → upload_regression() (commit par règle) → push unique si contrib
```

`process_and_generate()` :

```text
engine.process_events() → get_alerts()
    ├── alerts vides → return (pas de log "evaluation complete")
    ├── regression.begin_cycle() ; log stats (events_processed, matches_found, alerts_count)
    └── pour chaque alert : regression.add(&alert) → Option<Vec<String>>
         ├── None si règle déjà retirée / pas d'id valide / info.yml existant
         └── Some(files) → écrit les fichiers + regression_tests_path + retire la règle
    └── retired_ids += regression.take_blocked() (règles bloquées après N cycles d'échec)
    └── règles retirées → rules.remove_id() → engine.reload_rules() (un seul reload batch)
    ↓
retourne (Pipeline restitué, batches: Vec<(Uuid, Vec<String>)>)
    ↓
upload_regression() → upload_rule_batches() (dans sigmacatch-repo)
     ├── un commit par règle : "🧪 test: add regression data for rule {rule_id}"
     ├── échec commit/push → rollback de la branche locale vers le tip pré-batch
     └── UN SEUL push si git.contrib: true (sinon commits locaux) → message PR
```

Toute la génération tourne en `spawn_blocking` (état `Pipeline` déplacé puis restitué) —
les retries `EvtExportLog` ne gèlent jamais la collecte (les events continuent à bufferiser
dans le canal mpsc).

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
  render/parse. Les collecteurs Linux détectent la rotation du fichier tailé (changement d'inode)
  et rouvrent le fichier.
