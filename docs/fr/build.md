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

Build release optimisé : ~12MB (binaire headless unique).

Profil appliqué :
- `strip = true`
- `lto = true`
- `codegen-units = 1`
- features tokio : `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Workspace

Le projet est un cargo workspace de 11 packages (1 crate binaire avec 2 binaires + 10 bibliothèques) :

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
cargo build -p localcheck
```

## Binaires

| Binaire | Chemin | Description |
|---|---|---|
| `sigmacatch` | `sigmacatch/src/main.rs` | Capture + évaluation + génération de régression |
| `check_filter` | `localcheck/src/check_filter.rs` | Valide `SigmaFilterConfig` contre les vraies règles Sigma (comptage ground-truth, pas d'args CLI) |
| `check_evtx` | `localcheck/src/check_evtx.rs` | Validation batch du moteur Sigma contre des .evtx |
