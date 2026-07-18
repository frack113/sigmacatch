# Sigmacatch

Outil headless qui capture de vrais événements Windows via l'**API Windows Event Log** (`winevt`), les compare à des règles [SigmaHQ](https://github.com/SigmaHQ/sigma), et produit des données de régression structurées prêtes pour les PR SigmaHQ.

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
