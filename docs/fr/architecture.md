# Architecture

## Workspace cargo

Le projet est un package cargo unique (`sigmacatch`), plus un crate eBPF nested nightly-only (`sigmacatch/ebpf`) exclu du workspace :

```text
sigmacatch/
├── Cargo.toml                    # Racine workspace
├── sigmacatch/                   # Package principal (library + deux binaires)
│   ├── Cargo.toml                # features : winevt (défaut), evtx, auditd, builtin, sysmon, ebpf
│   ├── build.rs                  # Build de l'objet eBPF (cible Linux + feature `ebpf` uniquement)
│   ├── src/
│       ├── main.rs               # Dispatch : --evtx → input evtx ; winevt sur Windows ; inputs Linux sur Linux
│       ├── lib.rs                # Déclarations de modules + re-exports (CollectorKind, run, bootstrap_repo_regression, DataFormat)
│       ├── cli.rs                # Dispatch + sous-commandes de diagnostic : check-filter, list-rules
│       ├── runner.rs             # run<C: CollectorKind> pipeline partagé + trait CollectorKind + bootstrap_repo_regression
│       ├── logging.rs            # Init tracing à deux couches (stderr error/info, fichier rolling)
│       ├── config.rs             # Config, GitConfig, SigmaFilterConfig, LogConfig, CliArgs, parse_args, custom_channels.yaml
│       ├── types.rs              # Event, Alert, RegressionHeader, Product, EventProducer, parsing XML, tables logsource phf
│       ├── evtx_reader.rs        # Parse fichiers EVTX → Event (cross-platform, utilisé par les deux binaires)
│       ├── ebpf_common.rs        # Types wire du ring buffer eBPF (partagés avec le crate probe via #[path])
│       ├── detection/            # DetectionEngine + pipelines par plateforme + channel_resolver
│       ├── rule/                 # SigmahqRules : load/filter/dedupe/remove_id + thresholds, attack, discover
│       ├── repo/                 # Wrapper grit-lib : SigmaRepo, plumbing/, porcelain, branch, signing, transport
│       ├── regression/           # SigmahqRegression, InfoYml, DataFormat (evtx/log), logtype, format, evtx_writer
│       ├── inputs/               # Modules d'input adapters (matrice gate feature × plateforme dans mod.rs) :
│       │   ├── mod.rs            #   matrice gate feature × target_os
│       │   ├── winevt.rs         #   WinevtCollector (Event Log live, feature `winevt`)
│       │   ├── evtx.rs           #   EvtxCollector (fichiers EVTX one-shot, feature `evtx`)
│       │   ├── channels.rs       #   Collecteur Winevt (EvtQueryW/EvtNext/EvtRender, multi-channel)
│       │   ├── linux.rs          #   LinuxCollector + run() (toute feature Linux)
│       │   ├── auditd.rs         #   Collecteur auditd (LineHandler, groupement par event id, via tail)
│       │   ├── syslog.rs         #   Collecteur syslog builtin (LineHandler par fichier, via tail)
│       │   ├── sysmon.rs         #   Collecteur Sysmon-for-Linux (LineHandler, via tail, feature `sysmon`)
│       │   ├── tail.rs           #   Driver tail partagé (trait LineHandler + détection rotation)
│       │   ├── sysmon_parse.rs   #   Parsing Sysmon XML (feature `builtin`)
│       │   ├── ebpf.rs           #   Loader eBPF + dispatch (feature `ebpf`, privileges requis)
│       │   └── ebpf_event.rs     #   Synthèse XML eBPF → format Sysmon + tests
│       └── bin/
│           └── regressiondata-check.rs  # Binaire standalone cross-platform : validation régression (--json, --ignore, --fix, --path)
│       └── tests/
│           └── fixtures/           # Fixtures : sample.xml, sample.evtx, valid-single.evtx
│   └── ebpf/                       # Crate eBPF probe nested nightly (exclu via [workspace], bpfel-unknown-none)
│       ├── .cargo/config.toml    #   cible bpfel, bpf-linker, build-std=core
│       └── src/main.rs           #   6 tracepoints : execve/exec/exit/connect/openat+exit/sendto+sendmsg
```

## Collecteurs

Une seule binaire `sigmacatch` est produite par le package `sigmacatch`. Les features cargo
sélectionnent quels inputs sont compilés, et `main.rs` choisit l'input au runtime : le
collecteur one-shot EVTX quand `--evtx` est présent, le collecteur Winevt live sur Windows,
ou l'ensemble des inputs Linux compilés et disponibles. S'y ajoute le binaire standalone
cross-platform `regressiondata-check` (deuxième binaire du package `sigmacatch`) :

| Input | Module | Features | Description |
|---|---|---|---|
| winevt | `sigmacatch/src/inputs/channels.rs` | `winevt` | API Winevt native (`EvtQueryW`/`EvtNext`/`EvtRender`), multi-channel, rejouable |
| evtx | `sigmacatch/src/inputs/evtx.rs` | `evtx` | Collecteur one-shot `.evtx` (`live_capture() = false`) : parse → détection → génération régression (writer EVTX pur Rust) → commit/push, puis sortie |
| auditd | `sigmacatch/src/inputs/auditd.rs` | `auditd` | tail auditd (pas de root requis) |
| syslog builtin | `sigmacatch/src/inputs/syslog.rs` | `builtin` | tails syslog central/authpriv/cron (pas de root requis) |
| sysmon (tail) | `sigmacatch/src/inputs/sysmon.rs` | `sysmon` (implique `builtin`) | tail XML Sysmon-for-Linux |
| sysmon (ebpf) | `sigmacatch/src/inputs/ebpf.rs` | `ebpf` | probes eBPF natifs (root ou CAP_BPF+CAP_PERFMON requis) |

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

Les features `sysmon` et `ebpf` ajoutent un collecteur dédié :

- **Sysmon eBPF (feature `ebpf`)** — probes Aya embarquées
  (`sigmacatch/ebpf`, nightly+bpf-linker, exclue du workspace) couvrant EID 1
  process_create, EID 3 network_connect, EID 5 process_terminate, EID 11 file_create et
  l'extension DNS (EID 22) : events rendus en XML Sysmon identique au chemin syslog puis
  injectés via le même pipeline (`inject_logsource_fields_for`). Prérequis runtime :
  root ou CAP_BPF+CAP_PERFMON (refus de démarrer sinon — `linux.rs` bail) + kernel avec BTF.
  Le hachage SHA256 des images est calculé userspace avec cache (chemin,mtime). Un échec de
  chargement des probes au runtime avertit (`warn!`) et continue **sans** source sysmon ;
  seul un build avec les features `ebpf` **et** `sysmon` retombe sur le tail Sysmon-for-Linux.
- **Sysmon-for-Linux tail (feature `sysmon`)** — lignes du
  syslog central taggées `sysmon` dont le corps est XML winevt (`parse_winevt_xml`/`_raw`)
  → logsource `product:linux, service:sysmon` via le channel `Linux-Sysmon/Operational`.
  Lecture seule, pas de dépendance Aya.

Format de régression : `DataFormat::Log`.

Chaque input définit son propre `CollectorKind`
(`name()`/`mode()`/`channels()`/`build()`/`regression_format()`/`live_capture()`) ; les
inputs Linux partagent un unique `LinuxCollector` défini dans `linux.rs`. Le format de
régression est choisi par `regression_format()` : `DataFormat::Evtx` pour les inputs
winevt/evtx, `DataFormat::Log` pour les inputs Linux. `name()` vaut `sigmacatch` pour
chaque input.

`live_capture()` est une propriété intrinsèque du collecteur, pas un flag CLI : elle vaut
`true` par défaut et n'est redéfinie que par l'input `evtx` (`false`). Les collecteurs
continus tournent en boucle infinie bornée par le stop-file ; un collecteur one-shot laisse
`EventProducer::run()` se terminer, le sender mpsc tombe, et `run()` sort quand `rx.recv()`
renvoie `None`.

`tail.rs` est le driver tail partagé des collecteurs fichier Linux (auditd, syslog builtin,
sysmon) : il possède le handle fichier, la boucle de poll 100 ms, la détection de rotation
(changement dev/ino → réouverture depuis offset 0) et le channel, et pilote un `LineHandler`
pur par collecteur. Chaque `LineHandler` transforme des lignes complètes en events (auditd
groupe les records par event id et flush au changement de séquence ou sur poll idle ; syslog
émet un event par ligne RFC3164 en excluant les lignes `sysmon` ; sysmon parse les corps XML
en sautant les tronqués). Gate par les features qui font du tail.

L'input `evtx` (feature `evtx`) est un `CollectorKind` avec `live_capture() = false` : il
passe par le **même** pipeline partagé `run()` que les collecteurs continus, en mode one-shot —
énumérer les fichiers `.evtx`, parser chaque event (`evtx_reader`), alimenter la
`DetectionEngine`, puis réutiliser la machinerie partagée `SigmahqRegression` + `SigmaRepo`
pour écrire les données de régression `DataFormat::Evtx` (toujours via le writer EVTX pur
Rust, jamais `EvtExportLog`) et les commit/push vers le fork. Comme `EventProducer::run()` se
termine quand tous les fichiers sont épuisés, le processus s'arrête de lui-même. Pas de
`channels()`, pas d'interval, pas de poller stop-file. Le champ `EventRecordID` est retiré par
event (l'event 4688 exige son absence pour déclencher la règle d'imagerie). Comme il est
100 % pur Rust, il se compile et tourne aussi sous Linux.

## Graphe de dépendances

```text
sigmacatch (package)
├── src/runner.rs         (run<C: CollectorKind>, pipeline partagé + init tracing + module cli)
├── src/config.rs         (Config, CliArgs)
├── src/rule/             (SigmahqRules : load/filter/remove_id)
├── src/detection/        (DetectionEngine : pipelines + bloom + LogSourceExtractor + resolve_channels)
├── src/regression/       (SigmahqRegression : skip set + génération données)
├── src/types.rs          (Event, Alert, RegressionHeader, Product, EventProducer, parsing XML)
├── src/repo/             (SigmaRepo, wrapper grit-lib)
├── src/evtx_reader.rs    (parse EVTX → Event)
└── serde                 (sérialisation JSON des sorties diagnostics)

regressiondata-check (deuxième binaire du package sigmacatch)
├── réutilise src/detection/ (DetectionEngine)
├── réutilise src/rule/      (SigmahqRules : load/filter)
├── réutilise src/regression/ (SigmahqRegression)
├── réutilise src/types.rs   (Event)
├── réutilise src/evtx_reader.rs (parse EVTX → Event)
└── linux-audit-parser       (parse records auditd → Event)
```

Le module `evtx_reader` dépend de `types` + la crate `evtx`. `regressiondata-check`
(validation de régression, cross-platform) réutilise les mêmes modules (`detection`,
`rule`, `regression`, `types`, `evtx_reader`) avec `linux-audit-parser` (auditd) selon le
`LogType` de chaque entrée. Les sous-commandes de diagnostic (`cli.rs`) font un parsing
manuel des arguments et utilisent `serde` pour leurs sorties JSON (toujours compilées).

## Pipeline (runner partagé)

```text
1. parse_args() + Config::load_with_cli("config.yaml", cli)
   └── -n/--dry-run : chargement allégé (pas de validation git), aucun état sur disque
       (ni config.yaml ni logs/), sortie après validation des règles + du moteur
2. setup_console() (Windows) ; logging::init du runner (&config, verbose) → tracing (stderr `error` par défaut, `info` avec `-v`, fichier debug)
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
       └── None (linux, evtx) → pas de résolution de channels
9. Handlers d'arrêt (watch channel) : Ctrl+C, plus poller stop-file (500 ms) si live_capture()
   ; output_base = <sigma_repo_path>/regression_data ; clean_partial_artifacts()
10. collector = kind.build(&cycle_channels) → tokio::spawn(collector.run(tx, stop))
    ├── sigmacatch --evtx (one-shot) → EvtxCollector.run(tx, stop) : énumère les fichiers, envoie chaque event parsé,
    │                                  se termine à épuisement → sender tombé
    ├── sigmacatch (winevt, Windows)  → EventCollector::new(cycle_channels).run(tx, stop)
    └── sigmacatch (Linux)            → MultiCollector (tous les tails compilés et disponibles en parallèle, rotation détectée)
11. Boucle : tokio::select!
    ├── shutdown_rx (Ctrl+C, ou stop file / --max-runs atteint si live_capture()) → break
    ├── event depuis rx → engine.put_events(vec![event])
    ├── generate_interval (30s, live_capture seulement) → spawn_blocking(process_and_generate) → upload_regression() si fichiers
    └── [one-shot seulement] rx.recv() → None (sender tombé, collecteur terminé) → break
12. Flush final : arrêt collector (timeout 10s, abort sinon) → drain des events restants (timeout 5s)
    → process_and_generate() → upload_regression() (commit par règle) → push unique si contrib
    — one-shot propage l'erreur de l'upload final (code de sortie non nul) ; live mode log et continue
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
upload_regression() → upload_rule_batches() (dans sigmacatch::repo)
     ├── un commit par règle : "🧪 test: add regression data for rule {rule_id}"
     ├── échec commit/push → rollback de la branche locale vers le tip pré-batch
     └── UN SEUL push si git.contrib: true (sinon commits locaux) → message PR
```

Toute la génération tourne en `spawn_blocking` (état `Pipeline` déplacé puis restitué) —
les retries `EvtExportLog` ne gèlent jamais la collecte (les événements continuent à
s'accumuler dans le canal mpsc).

### Variante one-shot : `--evtx`

Tout ce qui précède décrit le pipeline partagé `run()`. L'input `evtx`
(`live_capture() = false`) en est l'analogue one-shot : son `EventCollector` est préchargé
avec les fichiers `.evtx` énumérés et `EventProducer::run()` émet chaque event parsé puis se
termine — le sender mpsc tombe, `rx.recv()` renvoie `None`, et la boucle partagée sort. Pas de
`channels()`, pas de `generate_interval`, pas de poller stop-file, et `--max-runs` est ignoré
(sémantique `-r 0`). Ctrl+C avorte toujours la passe (le runner l'enregistre toujours) ;
tout cycle en vol est abandonné et le push de ce qui n'a pas encore été commité est sauté.

## Notes de conception

- **Stop file** : `config.stop_file` (défaut `.sigmacatch.stop`) est pollé toutes les
   500 ms ; si le fichier existe, la collecte s'arrête proprement (drain + flush +
   commit du cycle en cours) — c'est le signal pour terminer un run continu
   (`-r 0`) sans kill dur qui perdrait les données de régression du cycle en cours.
- **Skip set** = `HashSet<Uuid>` depuis `SigmahqRegression::get_sigma_id()` (info.yml existants + données valides)
  ∪ `SigmaRepo::pending_regression_rule_ids()` (arbres des branches remote `sigmacatch/*` :
  PR en attente non mergés — une VM fraîche ne recapture pas leurs données),
  construit une seule fois au démarrage. `--all-rules` le désactive. Après génération, une règle
  est retirée et le moteur est rechargé en un seul batch (`engine.reload_rules`).
  Les règles dont les données commitées sont invalides (EVTX cassé / texte vide) sont exclues du skip set → régénérées.
- **Output toujours dans le repo sigma** : `<sigma_repo_path>/regression_data/<rule_rel_path>/`
  (`info.yml` + fichier de données `.evtx`/`.log`, `.json` optionnel), commité sur le fork si `contrib` (commits locaux sinon).
  Le chemin de la règle est miroité par rapport au `sigma_repo_path` configuré (relatif ou
  absolu) — le commit par règle embarque aussi la règle mise à jour avec
  `regression_tests_path: regression_data/<rule_rel_path>/info.yml`.
- **Collecteur observable** : le collecteur exclut une fois pour toutes les channels
  inexistants dès `ERROR_EVT_CHANNEL_NOT_FOUND` (un seul `error!`) ; chaque channel vivant
  journalise « initial query OK » puis un heartbeat « still alive » (60s) ; `warn!` quand des
  events sont récupérés mais perdus au rendu/parsing. Les collecteurs Linux détectent la
  rotation du fichier tailé (changement d'inode) et rouvrent le fichier ; le collecteur syslog
  exclut les lignes taggées `sysmon` pour éviter les doubles événements (pris en charge par le
  collecteur sysmon dédié).