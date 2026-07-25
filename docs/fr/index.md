# Sigmacatch

Outil headless qui capture de vrais événements Windows via l'**API Windows Event Log** (`winevt`), les compare à des règles [SigmaHQ](https://github.com/SigmaHQ/sigma), et produit des données de régression structurées prêtes pour les PR SigmaHQ.

## Workspace

Le projet est un cargo workspace de 7 crates :

| Crate | Rôle |
|---|---|
| `sigmacatch` | Binaire + pipeline, toute l'orchestration |
| `detection-engine` | Wrapper fin autour de rsigma-eval pour charger pipelines et règles, puis évaluer les events |
| `input-windows-channels` | Collecteur multi-channels Windows Event Log (EvtQueryW, EvtNext, EvtRender) |
| `input-evtx` | Parse les fichiers EVTX en objets `Event` pour le moteur de détection |
| `sigma-mapping` | Résolution LogSource, tables de taxonomie, mappings custom |
| `sigma-regression` | Format de régression SigmaHQ (InfoYml, SkipSet, triplet) |
| `sigmacatch-types` | Types partagés : Event, Alert, RegressionHeader, parsing XML/JSON |

## Démarrage rapide

```bash
cargo build --release
./target/release/sigmacatch
```

## Documentation

Une version compilée de cette documentation est publiée sur GitHub Pages : **https://frack113.github.io/sigmacatch/**

| | English | Francais |
|---|---|---|
| Architecture | [EN](architecture/) | [FR](fr/architecture/) |
| Architecture reference | [EN](architecture-reference/) | [FR](fr/architecture-reference/) |
| Build | [EN](build/) | [FR](fr/build/) |
| Output format | [EN](output-format/) | [FR](fr/output-format/) |
| Regression data format | [EN](regression-data-format/) | [FR](fr/regression-data-format/) |
| Nice-to-have | [EN](nice-to-have/) | [FR](fr/nice-to-have/) |

## Licence

MIT
