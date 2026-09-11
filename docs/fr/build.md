# Build

## Prérequis

- Rust 2024 edition (1.85+)
- Pour la compilation croisée Windows depuis Linux : `cargo install cargo-xwin` (télécharge automatiquement le Windows SDK)

## Features cargo

Un seul binaire `sigmacatch` ; les **features cargo** choisissent quels inputs
sont compilés :

| Feature | Input | Plateforme | Par défaut ? |
|---|---|---|---|
| `winevt` | Windows Event Log live (`EvtQueryW` → `EvtNext` → `EvtRender`) | Windows | oui |
| `evtx` | fichiers EVTX en one-shot, pure Rust | n'importe | non |
| `auditd` | auditd `/var/log/audit/audit.log` | Linux | non |
| `builtin` | syslog builtin (central, authpriv, cron) | Linux | non |
| `sysmon` | tail XML Sysmon-for-Linux (dépend de `builtin`) | Linux | non |
| `ebpf` | probes eBPF natifs (process/network/file/DNS) | Linux | non |

À l'exécution : `--evtx <PATH>` sélectionne le one-shot EVTX ; sur Windows le
collecteur Winevt live par défaut ; sur Linux tous les inputs compilés **et
disponibles** tournent en parallèle. Bail au démarrage s'il n'y a aucune source.

## Linux

```bash
# auditd + syslog builtin (features de base, pas de root)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin

# + tail Sysmon-for-Linux
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,sysmon

# + probes eBPF natifs (root/CAP_BPF+CAP_PERFMON requis au runtime, kernel 5.14+/BTF,
#   toolchain nightly + bpf-linker pour compiler les probes — sinon placeholder replié sur
#   le tail en local ; sur CI, le placeholder vide est une erreur de build, jamais un repli)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,ebpf

# Lint
cargo clippy -p sigmacatch --no-default-features --features auditd,builtin,sysmon,ebpf -- -W warnings
```

Tournent en parallèle : le collecteur **auditd** si `/var/log/audit/audit.log` existe et les
collecteurs **syslog builtin** (chaque fichier existant parmi central `/var/log/messages`,
`/var/log/syslog` ; authpriv `/var/log/secure`, `/var/log/auth.log` ; cron `/var/log/cron`,
`/var/log/cron.log`). Spécification complète des collecteurs : [architecture.md](architecture.md).

La feature `winevt` (défaut) est compilée sur Linux comme stubs no-op : commuter vers un
build Linux se fait toujours avec `--no-default-features`.

## Windows

```bash
cargo build --release -p sigmacatch        # winevt (feature par défaut)
cargo build --release -p sigmacatch --features evtx   # + one-shot EVTX
```

Le collecteur **winevt** utilise l'API Winevt native sur les channels résolus ; nécessite
les droits admin pour les channels `Security` et `System`. L'input **evtx** (`live_capture() = false`)
scanne récursivement un dossier de `.evtx`, matche les events contre les règles Sigma, génère
les données de régression SigmaHQ, puis commit/push vers une branche `sigmacatch/<date>` et sort —
sans API Windows, donc il se compile et tourne aussi sous Linux (`--no-default-features --features evtx`).

```bash
# Collecteur EVTX one-shot uniquement (cross-platform)
cargo build --release -p sigmacatch --no-default-features --features evtx
```

> Les sous-commandes de diagnostic (`check-filter`, `list-rules`) sont toujours compilées
> dans le binaire — aucune feature supplémentaire n'est requise.

## Compilation croisée Windows (depuis Linux)

```bash
# winevt (défaut)
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch
# winevt + evtx (à déployer sur la VM de collecte)
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --features evtx
```

Le binaire résultant est à `target/x86_64-pc-windows-msvc/release/sigmacatch.exe`.
La CI GitHub Actions build nativement sur `windows-latest`.

## Taille du binaire

Build release optimisé : ~10 MB (constaté en cross
x86_64-pc-windows-msvc : `sigmacatch.exe` ~10.4 MB, ~11.7 MB avec `evtx`).

Profil appliqué :

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- features tokio : `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Sous-commandes de diagnostic

Les sous-commandes `check-filter` et `list-rules` sont **toujours compilées** dans le
binaire `sigmacatch` — plus aucune feature cargo dédiée n'est requise (la feature
`tools` a été supprimée).

La validation de régression (`check`) n'est pas une sous-commande : c'est le deuxième
binaire **`regressiondata-check`** du package `sigmacatch`, cross-platform, qui n'exige ni
collector ni feature supplémentaire :

```bash
# Linux
cargo build --release -p sigmacatch --bin regressiondata-check
# Windows
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --bin regressiondata-check
```

Détails et exemples de sortie → [cli.md](cli.md).
