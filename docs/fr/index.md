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

Le projet est un package cargo unique (`sigmacatch`), plus un crate eBPF
nested nightly-only (`sigmacatch/ebpf`) ; l'arborescence complète et les rôles
de chaque module sont détaillés dans [architecture.md](architecture.md).

## Démarrage rapide

```bash
cargo build --release -p sigmacatch                          # Input Windows (features par défaut)
./target/release/sigmacatch                                  # Winevt (Windows)
# Linux — compile les inputs voulus (ex. auditd + syslog builtin) :
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin
./target/release/sigmacatch                                  # auditd + syslog builtin (Linux, pas de root)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,sysmon,ebpf # + tail Sysmon + probes eBPF (root + nightly requis)
# One-shot EVTX, n'importe quelle plateforme :
cargo build --release -p sigmacatch --no-default-features --features evtx
./target/release/sigmacatch --evtx /chemin/vers/dossier-evtx
cargo build --release -p sigmacatch --bin regressiondata-check                # Validation de régression cross-platform (Linux & Windows)
```

## Documentation

Une version compilée de cette documentation est publiée sur GitHub Pages :
**https://frack113.github.io/sigmacatch/**

| | English | Français |
|---|---|---|
| Architecture | [EN](../en/architecture.md) | [FR](architecture.md) |
| Build | [EN](../en/build.md) | [FR](build.md) |
| CLI | [EN](../en/cli.md) | [FR](cli.md) |
| Git | [EN](../en/git.md) | [FR](git.md) |
| Output format | [EN](../en/output-format.md) | [FR](output-format.md) |
| Regression data format | [EN](../en/regression-data-format.md) | [FR](regression-data-format.md) |

## Licence

MIT
