# Build

## Prérequis

- Rust 2021 edition (1.70+)
- Pour la compilation croisée Windows : `cargo install cargo-xwin` (télécharge automatiquement le Windows SDK)

## Linux / macOS (collecteur stub)

```bash
# Build
cargo build --release

# Lint
cargo clippy -- -W warnings
```

Le collecteur est un stub no-op sur non-Windows (`collect()` retourne un vecteur vide, pas une erreur).
Le pipeline s'exécute toujours de bout en bout (chargement des règles, matching sur l'ensemble vide d'events, logique skip-set).

## Windows

```bash
cargo build --release
```

Collecte Winevt complète via `EvtQueryW` → `EvtNext` → `EvtRender` sur les channels configurés.
Nécessite les droits admin pour les channels `Security` et `System`.

## Compilation croisée Windows (depuis Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

Le binaire résultant est à `target/x86_64-pc-windows-msvc/release/sigmacatch.exe`.

## Taille du binaire

Build release optimisé : ~10MB (binaire headless unique).

Profil appliqué :

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- features tokio : `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Workspace

Le projet est un cargo workspace de 11 packages (2 crates binaires — `sigmacatch` avec 1 binaire, `tools` avec 7 binaires — et 9 bibliothèques) :

```bash
# Tout builder
cargo build --workspace

# Builder un crate spécifique
cargo build -p sigmacatch
cargo build -p sigmacatch-config
cargo build -p sigmacatch-logger
cargo build -p sigmacatch-rule
cargo build -p sigmacatch-detection
cargo build -p input-windows-channels
cargo build -p sigmacatch-regression
cargo build -p sigmacatch-types
cargo build -p sigmacatch-repo
cargo build -p input-evtx
cargo build -p tools
```

## Binaires

| Binaire | Chemin | Description |
|---|---|---|
| `sigmacatch` | `sigmacatch/src/main.rs` | Capture + évaluation + génération de régression |
| `check_dry_run` | `tools/src/check_dry_run.rs` | Diagnostics git (token, fork, API, info/refs, état repo) |
| `check_channels` | `tools/src/check_channels.rs` | Résout et liste les channels Windows collectés |
| `list_rules` | `tools/src/list_rules.rs` | Liste les règles chargées (techniques, lien ART) |
| `check_filter` | `tools/src/check_filter.rs` | Valide `SigmaFilterConfig` contre les vraies règles Sigma (comptage ground-truth, pas d'args CLI) |
| `check_evtx` | `tools/src/check_evtx.rs` | Validation batch du moteur Sigma contre des .evtx |
| `get_atomic` | `tools/src/get_atomic.rs` | Génère `run_atomic.ps` (chaîne `Invoke-AtomicTest`) pour les règles sans regression data |
| `coverage` | `tools/src/coverage.rs` | Statistiques de couverture des règles (locales + branches remote en attente) |

Tailles constatées (cross x86_64-pc-windows-msvc, release) : `sigmacatch.exe` ~10.4 MB,
`check_evtx.exe` ~4.0 MB, `check_filter.exe` ~0.9 MB.
