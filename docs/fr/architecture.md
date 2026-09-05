# Architecture

## Cargo workspace

Le projet est un cargo workspace de 14 packages, plus 1 crate nightly exclu (`sigmacatch-ebpf`) :

```text
sigmacatch/
├── Cargo.toml                    # Racine workspace
├── sigmacatch-win/               # Binaires Windows (lib + 1 bin)
│   └── src/
│       ├── lib.rs                # pub use sigmacatch-runner + module channels
│       ├── main_winevt.rs        # bin `sigmacatch-channel` : collecteur Winevt multi-channel
│       ├── channels.rs           # Collecteur Winevt (EvtQueryW/EvtNext/EvtRender, multi-channel)
│       │                         #   enrich, mapper, process_table, process_query, sysmon, paths, pe, filekey
│       └── cli.rs                # Sous-commandes de diagnostic : check-filter, list-rules
├── sigmacatch-lnx/               # Binaires Linux (lib + 3 bins, feature-gated)
│   └── src/
│       ├── lib.rs                # Module gates : auditd, builtin (syslog), sysmon (tail), ebpf
│       ├── entry.rs              # Pipeline Linux partagé `LinuxCollector` + `run()`
│       ├── main_base.rs          # bin `sigmacatch-linux` (wrapper fin sur entry::run)
│       ├── main_sysmon.rs        # bin `sigmacatch-linux-sysmon` (wrapper fin, + tail sysmon)
│       ├── main_ebpf.rs          # bin `sigmacatch-linux-ebpf` (wrapper fin, + eBPF natif)
│       ├── auditd.rs             # Collecteur auditd (tail /var/log/audit/audit.log, groupement par event id)
│       ├── syslog.rs             # Collecteur syslog builtin (central /var/log/messages → authpriv + cron, RFC3164)
│       ├── sysmon.rs             # Collecteur Sysmon-for-Linux (tail syslog, feature `sysmon`)
│       ├── sysmon_parse.rs       # Parsing Sysmon XML (toujours compilé, partagé par tail + eBPF)
│       ├── ebpf.rs               # Loader eBPF + dispatch (feature `ebpf`, privileges requis)
│       ├── ebpf_event.rs         # Synthèse XML eBPF → format Sysmon + tests
│       └── cli.rs                # Sous-commandes de diagnostic
├── regressiondata-check/             # Binaire standalone cross-platform : validation régression (--json, --ignore, --fix, --path)
└── crates/
    ├── sigmacatch-ebpf/          # eBPF probes (exclue workspace, nightly, bpfel-unknown-none)
    │   └── src/main.rs           # 6 tracepoints : execve/exec/exit/connect/openat+exit/sendto+sendmsg
    ├── sigmacatch-ebpf-common/   # Types no_std partagés (ring buffer) : ExecEvent, NetEvent, ...
    ├── sigmacatch-runner/        # Pipeline partagé aux crates binaires :
    │   └── src/runner.rs         #   run<C: CollectorKind> + trait CollectorKind
    ├── sigmacatch-config/        # Config YAML + parsing CLI + custom_channels.yaml
    ├── sigmacatch-logger/        # Abonnement tracing à deux couches (stderr error/info, fichier rolling)
    ├── sigmacatch-rule/          # SigmahqRules : chargement de règles, filtre, dédupe, remove_id
    ├── sigmacatch-detection/     # Wrapper DetectionEngine + pipelines par plateforme
    ├── sigmacatch-regression/    # SigmahqRegression, InfoYml, DataFormat (evtx/log)
    ├── sigmacatch-types/         # Types partagés : Event, Alert, RegressionHeader + parsing XML + logsource tables
    ├── sigmacatch-repo/          # wrapper grit-lib + SigmaRepo + opérations git + signing
    ├── sigmacatch-evtx-writer/   # Writer EVTX pur Rust
    └── input-windows-evtx/       # Parser fichiers EVTX → Event
```

## Collecteurs

Six binaires sont produits depuis trois crates (les binaires de collecte embarquent un
ensemble de collecteurs sélectionné par features cargo et `required-features` par binaire ;
`regressiondata-check` est un binaire standalone sans collecteur) :

| Binaire | Crate | Features | Description |
|---|---|---|---|
| `sigmacatch-channel` | `sigmacatch-win` | `winevt` | API Winevt native (`EvtQueryW`/`EvtNext`/`EvtRender`), multi-channel, rejouable |
| `sigmacatch-linux` | `sigmacatch-lnx` | `auditd` + `builtin` | auditd + syslog builtin uniquement (pas de sysmon, pas de root requis) |
| `sigmacatch-linux-sysmon` | `sigmacatch-lnx` | `auditd` + `builtin` + `sysmon` | + tail Sysmon-for-Linux XML (feature `sysmon`) |
| `sigmacatch-linux-ebpf` | `sigmacatch-lnx` | `auditd` + `builtin` + `ebpf` | + probes eBPF native (feature `ebpf`, root requis) |
| `regressiondata-check` | `regressiondata-check` | — | Validation de régression cross-platform (EVTX + auditd + JSON), pas de collector |

### Logsource Windows et catégories PowerShell

Les règles Windows sont contraintes par la pipeline `1_win_logsource.yml`
(`add_condition` sur les EventID + `change_logsource` vers le service) : les catégories
PowerShell sont bornées à leurs EventID — `ps_module` (4103), `ps_script` (4104) vers
`service: powershell` ; `ps_classic_start` (400), `ps_classic_provider_start` (600) et
`ps_classic_script` (800) vers `service: powershell-classic`. Sans champ `category` injecté
sur l'event, le `LogSourceExtractor` d'rsigma évalue chaque event fail-open contre toutes
les règles.

Les events PowerShell classique (400/600/800 …) émettent des `<Data>` **sans** attribut
`Name` : le parseur les expose sous des clés positionnelles (`Data0`, `Data1`, …), et
`inject_logsource_fields_for` surface le contenu `EventData` sous le champ Sigma générique
`Data` pour que `Data|contains` fonctionne (rsigma n'a pas de mapping de champ dédié
`powershell_classic`).

### Les collecteurs Linux

Chacun gardé par sa source ; aucune source disponible → bail :

- **auditd** — si `/var/log/audit/audit.log` existe : tail, parsing linux-audit-parser,
  groupement par event id `timestamp:sequence`, logsource `product:linux, service:auditd`.
- **syslog builtin** — tail de chaque fichier existant parmi central (`/var/log/messages`,
  `/var/log/syslog`), authpriv (`/var/log/secure`, `/var/log/auth.log`) et cron
  (`/var/log/cron`, `/var/log/cron.log`) : lignes RFC3164, service dérivé du program tag
  (fallback par groupe de fichier : authpriv → `auth`, cron → `cron`). Les lignes taggées
  `sysmon` sont exclues (prises en charge par le collecteur dédié).

Les deux binaires sysmon ajoutent un collecteur supplémentaire :

- **Sysmon eBPF (feature `ebpf`, `sigmacatch-linux-ebpf`)** — probes Aya embarquées
  (`crates/sigmacatch-ebpf`, nightly+bpf-linker, exclue du workspace) couvrant EID 1
  process_create, EID 3 network_connect, EID 5 process_terminate, EID 11 file_create et
  l'extension DNS (EID 22) : events rendus en XML Sysmon identique au chemin syslog puis
  injectés via le même pipeline (`inject_logsource_fields_for`). Prérequis runtime :
  root ou CAP_BPF+CAP_PERFMON (refus de démarrer sinon — `entry.rs` bail) + kernel avec BTF. Le hachage
  SHA256 des images est calculé userspace avec cache (chemin,mtime). Un échec de chargement
  des probes au runtime avertit (`warn!`) et continue **sans** source sysmon dans la saveur
  `-ebpf` ; seul un build all-features (`ebpf` + `sysmon`) retombe sur le tail
  Sysmon-for-Linux.
- **Sysmon-for-Linux tail (feature `sysmon`, `sigmacatch-linux-sysmon`)** — lignes du
  syslog central taggées `sysmon` dont le corps est XML winevt (`parse_winevt_xml`/`_raw`)
  → logsource `product:linux, service:sysmon` via le channel `Linux-Sysmon/Operational`.
  Lecture seule, pas de dépendance Aya.

Format de régression : `DataFormat::Log`.

Chaque binaire Windows définit son propre `CollectorKind` dans son `main_*.rs`
(`name()`/`mode()`/`channels()`/`build()`/`regression_format()`) ; les trois binaires Linux
partagent un unique `LinuxCollector` défini dans `entry.rs`. Le format de régression est
choisi par `regression_format()` : `DataFormat::Evtx` pour les deux bins Windows,
`DataFormat::Log` pour les trois bins Linux.

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
                 └── serde (sérialisation JSON des sorties diagnostics)

regressiondata-check ──┬── sigmacatch-detection   (DetectionEngine)
                   ├── sigmacatch-rule        (SigmahqRules : load/filter)
                   ├── sigmacatch-regression  (SigmahqRegression)
                   ├── sigmacatch-types       (Event)
                   ├── input-windows-evtx     (parse EVTX → Event)
                   └── linux-audit-parser     (parse records auditd → Event)
```

`sigmacatch-detection` dépend de `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`.
Les collecteurs vivent dans leur crate binaire et ne dépendent que de `sigmacatch-types`
(types partagés + tables de mapping logsource). `input-windows-evtx` dépend de
`sigmacatch-types` + la crate `evtx`. `regressiondata-check` (validation de régression,
cross-platform) assemble `detection` + `rule` + `regression` + `types` avec
`input-windows-evtx` (EVTX) et `linux-audit-parser` (auditd) selon le `LogType` de chaque
entrée. Les sous-commandes de diagnostic (`cli.rs`) font un parsing manuel des arguments
et utilisent `serde` pour leurs sorties JSON (toujours compilées).

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
       └── None (linux) → pas de résolution de channels
9. Handler Ctrl+C (watch channel) ; output_base = <sigma_repo_path>/regression_data ;
   clean_partial_artifacts()
10. collector = kind.build(&cycle_channels) → tokio::spawn(collector.run(tx, stop))
    ├── sigmacatch-channel (winevt)  → EventCollector::new(cycle_channels).run(tx, stop)
     └── sigmacatch-linux (auditd + syslog + sysmon) → MultiCollector (les trois tails en parallèle, rotation détectée)
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
les retries `EvtExportLog` ne gèlent jamais la collecte (les événements continuent à
s'accumuler dans le canal mpsc).

## Notes de conception

- **Skip set** = `HashSet<Uuid>` depuis `SigmahqRegression::get_sigma_id()` (info.yml existants + données valides)
  ∪ `SigmaRepo::pending_regression_rule_ids()` (arbres des branches remote `sigmacatch/*` :
  PR en attente non mergés — une VM fraîche ne recapture pas leurs données),
  construit une seule fois au démarrage. `--all-rules` le désactive. Après génération, une règle
  est retirée et le moteur est rechargé en un seul batch (`engine.reload_rules`).
  Les règles dont les données commitées sont invalides (EVTX cassé / texte vide) sont exclues du skip set → régénérées.
- **Output toujours dans le repo sigma** : `<sigma_repo_path>/regression_data/<rule_rel_path>/`
  (`info.yml` + fichier de données `.evtx`/`.log`, `.json` optionnel), commité sur le fork si `contrib` (commits locaux sinon).
  Attention : le chemin de génération est codé sur le dépôt local `./sigma` — gardez
  `git.sigma_repo_path: "sigma"` ; toute autre valeur casse le miroir de chemins et le
  nettoyage des artefacts partiels.
- **Collecteur observable** : le collecteur exclut une fois pour toutes les channels
  inexistants dès `ERROR_EVT_CHANNEL_NOT_FOUND` (un seul `error!`) ; chaque channel vivant
  journalise « initial query OK » puis un heartbeat « still alive » (60s) ; `warn!` quand des
  events sont récupérés mais perdus au rendu/parsing. Les collecteurs Linux détectent la
  rotation du fichier tailé (changement d'inode) et rouvrent le fichier ; le collecteur syslog
  exclut les lignes taggées `sysmon` pour éviter les doubles événements (pris en charge par le
  collecteur sysmon dédié).
