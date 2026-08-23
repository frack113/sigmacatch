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

Produit `sigmacatch-linux` : collecteur **auditd** si `/var/log/audit/audit.log` existe **et** collecteurs **syslog builtin** (chaque fichier existant parmi central `/var/log/messages`, `/var/log/syslog` ; authpriv `/var/log/secure`, `/var/log/auth.log` ; cron `/var/log/cron`, `/var/log/cron.log`) plus le collecteur **Sysmon-for-Linux** sur le syslog central — tous tournent en parallèle ; bail au démarrage si aucune source.

Sur Linux/macOS les collecteurs Windows sont des stubs no-op — le pipeline tourne de bout en bout pour tests (`cargo build -p sigmacatch-win`).

## Windows

```bash
cargo build --release -p sigmacatch-win
```

Deux binaires sont produits, chacun avec un seul collecteur (features cargo, défaut les deux) :

- **`sigmacatch-channel`** (winevt) : API Winevt native (`EvtQueryW` → `EvtNext` → `EvtRender`) sur les channels résolus. Nécessite les droits admin pour les channels `Security` et `System`.
- **`sigmacatch-etw`** (etw) [beta] : collecte ETW directe via ferrisetw (18 providers, routing générique provider→channel, EventID réel conservé). Pas de droits admin requis pour la plupart des providers.

Builds isolés (un binaire sans l'autre collecteur linké) :

```bash
# Winevt uniquement
cargo build --release --bin sigmacatch-channel --no-default-features --features winevt

# ETW uniquement
cargo build --release --bin sigmacatch-etw --no-default-features --features etw

# Diagnostics uniquement (feature tools)
cargo build --release -p sigmacatch-win --no-default-features --features tools
```

Isolé équivalent côté Linux :

```bash
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin
cargo build --release -p sigmacatch-lnx --no-default-features --features tools
```

## Compilation croisée Windows (depuis Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win
```

Les binaires résultants sont à `target/x86_64-pc-windows-msvc/release/sigmacatch-channel.exe` et `sigmacatch-etw.exe`. La CI GitHub Actions build nativement sur `windows-latest`.

## Taille du binaire

Build release optimisé : ~11MB par binaire.

Profil appliqué :

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- features tokio : `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Workspace

Le projet est un cargo workspace de 12 packages (2 crates binaires + 10 bibliothèques) :

```bash
# Tout builder
cargo build --workspace

# Builder un crate spécifique
cargo build -p sigmacatch-win
cargo build -p sigmacatch-lnx
cargo build -p sigmacatch-runner
cargo build -p sigmacatch-config
cargo build -p sigmacatch-logger
cargo build -p sigmacatch-rule
cargo build -p sigmacatch-detection
cargo build -p sigmacatch-regression
cargo build -p sigmacatch-evtx-writer
cargo build -p sigmacatch-types
cargo build -p sigmacatch-repo
cargo build -p input-windows-evtx
```

## Binaires principaux

| Binaire | Chemin | Description |
|---|---|---|
| `sigmacatch-channel` | `sigmacatch-win/src/main_winevt.rs` | Capture Winevt (multi-channel) + évaluation + génération de régression |
| `sigmacatch-etw` | `sigmacatch-win/src/main_etw.rs` | Capture ETW (ferrisetw) + évaluation + génération de régression [beta] |
| `sigmacatch-linux` | `sigmacatch-lnx/src/main_linux.rs` | Capture auditd + syslog + Sysmon-for-Linux (en parallèle, selon disponibilité) + évaluation + génération de régression |

## Sous-commandes de diagnostic

Feature `tools`, désactivée par défaut. Deux jeux : sur `sigmacatch-channel` (check, check-filter, check-channels, list-rules, get-atomic) et sur `sigmacatch-linux` (check, check-filter, list-rules).

| Commande | Description |
|---|---|
| `check` | Validation approfondie des données de régression (`./sigma/regression_data`) |
| `check-filter` | Valide `SigmaFilterConfig` contre les vraies règles Sigma (comptage ground-truth) |
| `check-channels` *(win uniquement)* | Résout et liste les channels Windows collectés |
| `list-rules` | Liste les règles chargées (techniques, lien ART) |
| `get-atomic` *(win uniquement)* | Génère `run_atomic.ps1` (chaîne `Invoke-AtomicTest`) pour les règles sans regression data |

Détails et exemples de sortie → [cli.md](cli.md).

Tailles constatées (cross x86_64-pc-windows-msvc, release) : `sigmacatch-channel.exe` ~10.4 MB,
`sigmacatch-etw.exe` ~11 MB.
