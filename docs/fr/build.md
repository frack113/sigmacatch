# Build

## Prérequis

- Rust 2024 edition (1.85+)
- Pour la compilation croisée Windows depuis Linux : `cargo install cargo-xwin` (télécharge automatiquement le Windows SDK)

## Linux / macOS

```bash
# Build du binaire Linux
cargo build --release -p sigmacatch-lnx

# Lint
cargo clippy -- -W warnings
```

Produit `sigmacatch-linux` (features par défaut `auditd` + `builtin`). Tournent en
parallèle : le collecteur **auditd** si `/var/log/audit/audit.log` existe et les collecteurs
**syslog builtin** (chaque fichier existant parmi central `/var/log/messages`,
`/var/log/syslog` ; authpriv `/var/log/secure`, `/var/log/auth.log` ; cron `/var/log/cron`,
`/var/log/cron.log`). Aucune source sysmon : les binaires `-sysmon` et `-ebpf` l'ajoutent
(voir plus bas). Bail au démarrage si aucune source. Spécification complète des trois
collecteurs : [architecture.md](architecture.md).

Les deux saveurs Linux étendues embarquent en plus une source Sysmon, choisie par feature
cargo :

```bash
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin,sysmon  # sigmacatch-linux-sysmon
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin,ebpf   # sigmacatch-linux-ebpf (root/CAP_BPF+CAP_PERFMON requis)
```

Sur Linux/macOS les collecteurs Windows sont des stubs no-op — le pipeline tourne de bout
en bout pour tests (`cargo build -p sigmacatch-win`).

## Windows

```bash
cargo build --release -p sigmacatch-win
```

Deux binaires sont produits dans la crate `sigmacatch-win` :

- **`sigmacatch-channel`** (winevt, feature `winevt`, activée par défaut) : API Winevt native (`EvtQueryW` → `EvtNext` → `EvtRender`) sur les channels résolus. Nécessite les droits admin pour les channels `Security` et `System`.
- **`sigmacatch-evtx`** (feature `evtx`, hors défauts) : processeur EVTX statique à run unique — scanne récursivement un dossier de fichiers `.evtx`, matche les events contre les règles Sigma et génère des données de régression SigmaHQ, puis commit/push vers une branche `sigmacatch/<date>`. Pas de collecte live, pas d'API Windows : l'EVTX est parsé et réécrit en pur Rust, donc ce binaire se compile et tourne aussi sous Linux (`cargo build --release --bin sigmacatch-evtx --no-default-features --features evtx`).

Builds isolés :

```bash
# Winevt uniquement
cargo build --release --bin sigmacatch-channel --no-default-features --features winevt
# Processeur EVTX statique uniquement (cross-platform)
cargo build --release --bin sigmacatch-evtx --no-default-features --features evtx
```

> Les sous-commandes de diagnostic (`check-filter`, `list-rules`) sont toujours compilées
> dans le binaire — aucune feature supplémentaire n'est requise. La cible `[[bin]]`
> exige sa feature de collecteur (`winevt`) via `required-features`.

Variantes isolées équivalentes côté Linux :

```bash
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin
```

## Compilation croisée Windows (depuis Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win
```

Le binaire résultant est à `target/x86_64-pc-windows-msvc/release/sigmacatch-channel.exe`.
La CI GitHub Actions build nativement sur `windows-latest`.

Le processeur EVTX statique (feature `evtx`) :

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win --features evtx
```

Le binaire résultant est à `target/x86_64-pc-windows-msvc/release/sigmacatch-evtx.exe`.
Le build croisé par défaut ci-dessus produit les deux binaires sigmacatch-win ; la forme
`--features evtx` n'est nécessaire que pour un `sigmacatch-evtx.exe` isolé.

## Taille du binaire

Build release optimisé : ~10 MB par binaire (constaté en cross
x86_64-pc-windows-msvc : `sigmacatch-channel.exe` ~10.4 MB, `sigmacatch-evtx.exe` ~11.7 MB).

Profil appliqué :

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- features tokio : `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Sous-commandes de diagnostic

Les sous-commandes `check-filter` et `list-rules` sont **toujours compilées** dans
`sigmacatch-channel` comme dans `sigmacatch-linux` — plus aucune feature cargo dédiée
n'est requise (la feature `tools` a été supprimée).

La validation de régression (`check`) n'est plus une sous-commande : c'est le binaire
standalone **`regressiondata-check`** (`regressiondata-check`), cross-platform, qui
n'exige ni collector ni feature supplémentaire :

```bash
# Linux
cargo build --release -p regressiondata-check
# Windows
cargo xwin build --release --target x86_64-pc-windows-msvc -p regressiondata-check
```

Détails et exemples de sortie → [cli.md](cli.md).
