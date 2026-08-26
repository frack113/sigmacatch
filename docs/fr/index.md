# Sigmacatch

Outil headless qui capture de vrais événements Windows via l'**API Windows Event Log**
(`winevt`) ou l'**ETW direct** (`ferrisetw`), ou des événements Linux via **auditd**, le
**syslog builtin** (fichiers central, authpriv et cron) et **Sysmon-for-Linux**. Il les
compare à des règles [SigmaHQ](https://github.com/SigmaHQ/sigma) et produit des données de
régression structurées prêtes pour les PR SigmaHQ.

Le projet est un cargo workspace de 12 packages (2 crates binaires + 10 bibliothèques), plus 1 crate nightly exclu (`sigmacatch-ebpf`) ;
l'arborescence complète et les rôles de chaque crate sont détaillés dans
[architecture.md](architecture.md).

## Démarrage rapide

```bash
cargo build --release
./target/release/sigmacatch-channel       # Winevt (Windows)
./target/release/sigmacatch-etw           # ETW direct (Windows)
./target/release/sigmacatch-linux         # auditd + syslog builtin (Linux, pas de root)
./target/release/sigmacatch-linux-sysmon  # + tail Sysmon-for-Linux (Linux)
./target/release/sigmacatch-linux-ebpf    # + probes eBPF native (Linux, root requis)
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
