# Sigmacatch

Outil headless qui capture de vrais événements Windows via l'**API Windows Event Log** (`winevt`) ou l'**ETW direct** (`ferrisetw`), ou des événements Linux via **auditd**, le **syslog builtin** (fichiers central, authpriv et cron) et **Sysmon-for-Linux**, les compare à des règles [SigmaHQ](https://github.com/SigmaHQ/sigma), et produit des données de régression structurées prêtes pour les PR SigmaHQ.

## Workspace

Le projet est un cargo workspace de 12 packages (2 crates binaires + 10 bibliothèques) :

| Crate | Rôle |
|---|---|
| `sigmacatch-win` | Binaires Windows : `sigmacatch-channel` (winevt) et `sigmacatch-etw` (ETW direct) + collecteurs `channels.rs`/`etw/` + diagnostics `cli.rs` |
| `sigmacatch-lnx` | Binaire Linux : `sigmacatch-linux` (collecteurs auditd + syslog builtin + Sysmon-for-Linux en parallèle, garde par source) + diagnostics `cli.rs` |
| `sigmacatch-runner` | Pipeline partagé (`run<C: CollectorKind>`) : config, init repo, boucle d'événements, génération, commit/push |
| `sigmacatch-config` | Config YAML + parsing CLI + custom_channels.yaml |
| `sigmacatch-logger` | Abonnement tracing à deux couches (stderr `error` par défaut / `info` avec `-v`, fichier journal rolling debug) |
| `sigmacatch-rule` | `SigmahqRules` : chargement de règles, filtre, dédupe, remove_id + `SigmaRuleExt` (techniques ATT&CK) |
| `sigmacatch-detection` | Wrapper fin autour de rsigma-eval (pipelines, bloom, LogSourceExtractor, resolve_channels) |
| `sigmacatch-regression` | `SigmahqRegression`, `InfoYml`, `DataFormat` (Evtx/Log), génération + validation des données |
| `sigmacatch-evtx-writer` | Writer EVTX pur Rust pour les events ETW / sans record id |
| `sigmacatch-types` | Types partagés : `Event`, `Alert`, `RegressionHeader`, parsing XML, tables logsource |
| `sigmacatch-repo` | wrapper grit-lib : SigmaRepo, opérations git, signature SSH des commits |
| `input-windows-evtx` | Parse les fichiers EVTX en objets `Event` (utilisé par les sous-commandes de diagnostic) |

## Démarrage rapide

```bash
cargo build --release
./target/release/sigmacatch-channel   # Winevt (Windows)
./target/release/sigmacatch-etw       # ETW direct (Windows)
./target/release/sigmacatch-linux     # auditd + syslog + sysmon (Linux)
```

## Documentation

Une version compilée de cette documentation est publiée sur GitHub Pages : **https://frack113.github.io/sigmacatch/**

| | English | Francais |
|---|---|---|
| Architecture | [EN](architecture/) | [FR](fr/architecture/) |
| Build | [EN](build/) | [FR](fr/build/) |
| CLI | [EN](cli/) | [FR](fr/cli/) |
| Git | [EN](git/) | [FR](fr/git/) |
| Output format | [EN](output-format/) | [FR](fr/output-format/) |
| Regression data format | [EN](regression-data-format/) | [FR](fr/regression-data-format/) |

## Licence

MIT
