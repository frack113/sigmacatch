# Build

## Prérequis

- Rust 2024 edition (1.85+)
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

Deux binaires sont produits, chacun avec un seul collecteur (features cargo, défaut les deux) :

- **`sigmacatch-channel`** (winevt) : API Winevt native (`EvtQueryW` → `EvtNext` → `EvtRender`) sur les channels résolus. Nécessite les droits admin pour les channels `Security` et `System`.
- **`sigmacatch-etw`** (etw) [beta] : collecte ETW directe via ferrisetw (18 providers, routing générique provider→channel, EventID réel conservé). Pas de droits admin requis pour la plupart des providers.

Builds isolés (un binaire sans l'autre collecteur linké) :

```bash
# Winevt uniquement
cargo build --release --bin sigmacatch-channel

# ETW uniquement
cargo build --release --bin sigmacatch-etw --no-default-features --features etw
```

## Compilation croisée Windows (depuis Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

Les binaires résultants sont à `target/x86_64-pc-windows-msvc/release/sigmacatch-channel.exe` et `sigmacatch-etw.exe`.

## Taille du binaire

Build release optimisé : ~11MB par binaire.

Profil appliqué :

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- features tokio : `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Workspace

Le projet est un cargo workspace de 13 packages (1 crate lib + 12 bibliothèques) :

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
cargo build -p input-windows-etw
cargo build -p sigmacatch-regression
cargo build -p sigmacatch-evtx-writer
cargo build -p sigmacatch-types
cargo build -p sigmacatch-repo
cargo build -p input-evtx
```

## Binaire principal

| Binaire | Chemin | Description |
|---|---|---|
| `sigmacatch-channel` | `sigmacatch/src/main_winevt.rs` | Capture Winevt (multi-channel) + évaluation + génération de régression |
| `sigmacatch-etw` | `sigmacatch/src/main_etw.rs` | Capture ETW (ferrisetw) + évaluation + génération de régression [beta] |
| `sigmacatch-auditd` | `sigmacatch/src/main_auditd.rs` | Capture auditd (tail) + évaluation + génération de régression |

## Sous-commandes de diagnostic

Toutes les commandes de diagnostic sont des sous-commandes de `sigmacatch-channel` (feature `tools`, désactivée par défaut) :

| Commande | Description |
|---|---|
| `check` | Validation approfondie des données de régression (`./sigma/regression_data`) |
| `check-filter` | Valide `SigmaFilterConfig` contre les vraies règles Sigma (comptage ground-truth) |
| `check-channels` | Résout et liste les channels Windows collectés |
| `list-rules` | Liste les règles chargées (techniques, lien ART) |
| `get-atomic` | Génère `run_atomic.ps` (chaîne `Invoke-AtomicTest`) pour les règles sans regression data |

Tailles constatées (cross x86_64-pc-windows-msvc, release) : `sigmacatch-channel.exe` ~10.4 MB,
`sigmacatch-etw.exe` ~11 MB.
