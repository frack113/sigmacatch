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
| Architecture | [EN](en/architecture.md) | [FR](fr/architecture.md) |
| Architecture reference | [EN](en/architecture-reference.md) | [FR](fr/architecture-reference.md) |
| Build | [EN](en/build.md) | [FR](fr/build.md) |
| Output format | [EN](en/output-format.md) | [FR](fr/output-format.md) |
| Regression data format | [EN](en/regression-data-format.md) | [FR](fr/regression-data-format.md) |
| Nice-to-have | [EN](en/nice-to-have.md) | [FR](fr/nice-to-have.md) |

## Licence

MIT
