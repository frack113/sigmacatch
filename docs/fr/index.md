# Sigmacatch

Outil headless qui capture de vrais événements système : **Windows Event Log API**
(`winevt`), fichiers **EVTX** en one-shot (cross-platform), et sur Linux **auditd**,
le **syslog builtin** (fichiers central, authpriv et cron), **Sysmon-for-Linux**
(tail XML) et des **probes eBPF** natifs. Il les compare à des règles
[SigmaHQ](https://github.com/SigmaHQ/sigma) et produit des données de
régression structurées prêtes pour les PR SigmaHQ.

Un seul binaire nommé `sigmacatch` : les inputs sont choisis à la compilation
par des features cargo et à l'exécution par l'argument `--evtx` (one-shot EVTX),
sinon Winevt live sur Windows et tous les inputs Linux compilés et disponibles
en parallèle.

Le projet est un workspace cargo à un seul package (`sigmacatch`), plus un crate
eBPF nested nightly-only (`sigmacatch/ebpf`) ; l'arborescence principale et les rôles
de chaque module sont détaillés dans [architecture.md](architecture.md).

## Démarrage rapide

```bash
# Windows (features par défaut) :
cargo build --release -p sigmacatch
./target/release/sigmacatch            # Winevt live
# Linux (auditd + syslog builtin, pas de root) :
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin
./target/release/sigmacatch            # auditd + syslog builtin
# One-shot EVTX (cross-platform) :
cargo build --release -p sigmacatch --no-default-features --features evtx
./target/release/sigmacatch --evtx /chemin/vers/dossier-evtx
```

La matrice complète des features (`sysmon`, `ebpf`), le binaire de validation
`regressiondata-check` et les commandes de build/test sont dans [build.md](build.md).

## Documentation

Une version compilée de cette documentation est publiée sur GitHub Pages :
**https://frack113.github.io/sigmacatch/**

| | English | Français |
|---|---|---|
| Architecture | [EN](../architecture/) | [FR](architecture.md) |
| Build | [EN](../build/) | [FR](build.md) |
| Configuration | [EN](../config/) | [FR](config.md) |
| CLI | [EN](../cli/) | [FR](cli.md) |
| Git | [EN](../git/) | [FR](git.md) |
| Output format | [EN](../output-format/) | [FR](output-format.md) |
| Regression data format | [EN](../regression-data-format/) | [FR](regression-data-format.md) |

## Licence

MIT
