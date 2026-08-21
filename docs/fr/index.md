# Sigmacatch

Outil headless qui capture de vrais événements Windows via l'**API Windows Event Log** (`winevt`), les compare à des règles [SigmaHQ](https://github.com/SigmaHQ/sigma), et produit des données de régression structurées prêtes pour les PR SigmaHQ.

## Workspace

Le projet est un cargo workspace de 13 crates (11 bibliothèques + 2 crates binaires) :

| Crate | Rôle |
|---|---|
| `sigmacatch` | Lib + 2 binaires (`sigmacatch-channel` winevt, `sigmacatch-etw`) + runner partagé (boucle continue) |
| `sigmacatch-config` | Config YAML + parsing CLI + custom_channels.yaml + diagnostics git dry-run |
| `sigmacatch-logger` | Abonnement tracing à deux couches (stderr `error` par défaut / `info` avec `-v`, fichier journal rolling debug) |
| `sigmacatch-rule` | `SigmahqRules` : chargement de règles, filtre, dédupe, remove_id + `SigmaRuleExt` (techniques ATT&CK) |
| `sigmacatch-detection` | Wrapper fin autour de rsigma-eval (pipelines, bloom, LogSourceExtractor, resolve_channels) |
| `input-windows-channels` | Collecteur Windows Event Log multi-channel (EvtQueryW/EvtNext/EvtRender) |
| `input-windows-etw` | Collecteur ETW direct via ferrisetw (18 providers, routing provider→channel, field maps) |
| `sigmacatch-regression` | `SigmahqRegression`, `InfoYml`, génération des données de régression |
| `sigmacatch-evtx-writer` | Writer EVTX pur Rust + validation re-parse |
| `sigmacatch-types` | Types partagés : `Event`, `Alert`, `RegressionHeader`, parsing XML, tables logsource |
| `sigmacatch-repo` | wrapper grit-lib : SigmaRepo, opérations git |
| `input-evtx` | Parse les fichiers EVTX en objets `Event` (utilisé par `tools`) |
| `tools` | Outils de dev : `check_dry_run`, `check_channels`, `list_rules`, `check_filter`, `check_evtx`, `get_atomic`, `coverage` |

## Démarrage rapide

```bash
cargo build --release
./target/release/sigmacatch-channel
```

## Documentation

Une version compilée de cette documentation est publiée sur GitHub Pages : **https://frack113.github.io/sigmacatch/**

| | English | Francais |
|---|---|---|
| Architecture | [EN](architecture/) | [FR](fr/architecture/) |
| Architecture reference | [EN](architecture-reference/) | [FR](fr/architecture-reference/) |
| Build | [EN](build/) | [FR](fr/build/) |
| Git | [EN](git/) | [FR](fr/git/) |
| Output format | [EN](output-format/) | [FR](fr/output-format/) |
| Regression data format | [EN](regression-data-format/) | [FR](fr/regression-data-format/) |
| Nice-to-have | [EN](nice-to-have/) | [FR](fr/nice-to-have/) |
| Outils | [EN](tools/) | [FR](fr/tools/) |

## Licence

MIT
