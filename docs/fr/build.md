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

Produit `sigmacatch-linux`. Tournent en parallèle : le collecteur **auditd** si
`/var/log/audit/audit.log` existe, les collecteurs **syslog builtin** (chaque fichier
existant parmi central `/var/log/messages`, `/var/log/syslog` ; authpriv `/var/log/secure`,
`/var/log/auth.log` ; cron `/var/log/cron`, `/var/log/cron.log`) et le collecteur
**Sysmon-for-Linux** sur le syslog central. Bail au démarrage si aucune source. Spécification
complète des trois collecteurs : [architecture.md](architecture.md).

Sur Linux/macOS les collecteurs Windows sont des stubs no-op — le pipeline tourne de bout
en bout pour tests (`cargo build -p sigmacatch-win`).

## Windows

```bash
cargo build --release -p sigmacatch-win
```

Deux binaires sont produits, chacun avec un seul collecteur (features cargo, les deux
activées par défaut) :

- **`sigmacatch-channel`** (winevt) : API Winevt native (`EvtQueryW` → `EvtNext` → `EvtRender`) sur les channels résolus. Nécessite les droits admin pour les channels `Security` et `System`.
- **`sigmacatch-etw`** (etw) [beta] : collecte ETW directe via ferrisetw (18 providers, routing générique provider→channel, EventID réel conservé). Pas de droits admin requis pour la plupart des providers.

Builds isolés (un binaire sans l'autre collecteur linké) :

```bash
# Winevt uniquement
cargo build --release --bin sigmacatch-channel --no-default-features --features winevt

# ETW uniquement
cargo build --release --bin sigmacatch-etw --no-default-features --features etw

# Un collecteur + les sous-commandes de diagnostic
cargo build --release --bin sigmacatch-channel --no-default-features --features winevt,tools
```

> La feature `tools` seule ne produit aucun binaire : chaque cible `[[bin]]` exige sa
> feature de collecteur (`winevt` ou `etw`) via `required-features`.

Variantes isolées équivalentes côté Linux :

```bash
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin,tools
```

## Compilation croisée Windows (depuis Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win
```

Les binaires résultants sont à `target/x86_64-pc-windows-msvc/release/sigmacatch-channel.exe`
et `sigmacatch-etw.exe`. La CI GitHub Actions build nativement sur `windows-latest`.

## Taille du binaire

Build release optimisé : ~10–11 MB par binaire (constaté en cross
x86_64-pc-windows-msvc : `sigmacatch-channel.exe` ~10.4 MB, `sigmacatch-etw.exe` ~11 MB).

Profil appliqué :

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- features tokio : `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Sous-commandes de diagnostic

Feature `tools`, désactivée par défaut et à combiner avec une feature de collecteur
(voir plus haut). Sur `sigmacatch-channel` comme sur `sigmacatch-linux` :
`check-filter`, `list-rules`.

La validation de régression (`check`) n'est plus une sous-commande : c'est le binaire
standalone **`sigmacatch-check`** (`sigmacatch-check`), cross-platform, qui
n'exige ni collector ni feature `tools` :

```bash
# Linux
cargo build --release -p sigmacatch-check
# Windows
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-check
```

Détails et exemples de sortie → [cli.md](cli.md).
