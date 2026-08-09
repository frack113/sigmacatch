# Build

## Prerequisites

- Rust 2021 edition (1.70+)
- For Windows cross-compilation: `cargo install cargo-xwin` (auto-downloads Windows SDK)

## Linux / macOS (stub collector)

```bash
# Build
cargo build --release

# Lint
cargo clippy -- -W warnings
```

The collector is a no-op stub on non-Windows (`collect()` returns an empty vector, not an error).
The pipeline still runs end-to-end (rule loading, matching on empty event set, skip-set logic).

## Windows

```bash
cargo build --release
```

Full Winevt collection via `EvtQueryW` → `EvtNext` → `EvtRender` on configured channels.
Requires admin rights for `Security` and `System` channels.

## Windows cross-compilation (from Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

The resulting binary is at `target/x86_64-pc-windows-msvc/release/sigmacatch.exe`.

## Binary size

Optimized release build: ~10MB (single headless binary).

Applied profile:

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- tokio features: `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Workspace

The project is a cargo workspace of 11 packages (2 binary crates — `sigmacatch` with 1 bin, `localcheck` with 5 bins — and 9 libraries):

```bash
# Build everything
cargo build --workspace

# Build a specific crate
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

## Binaries

| Binary | Path | Description |
|---|---|---|
| `sigmacatch` | `sigmacatch/src/main.rs` | Headless capture + evaluation + regression generation |
| `check_dry_run` | `localcheck/src/check_dry_run.rs` | Git diagnostics (token, fork, API, info/refs, repo state) |
| `check_channels` | `localcheck/src/check_channels.rs` | Resolves and lists the collected Windows channels |
| `list_rules` | `localcheck/src/list_rules.rs` | Lists the loaded rules (techniques, ART link) |
| `check_filter` | `localcheck/src/check_filter.rs` | Validates `SigmaFilterConfig` against real Sigma rules (ground-truth counts, no CLI args) |
| `check_evtx` | `localcheck/src/check_evtx.rs` | Batch validation of Sigma engine against .evtx regression data |

Observed sizes (x86_64-pc-windows-msvc cross, release): `sigmacatch.exe` ~10.4 MB,
`check_evtx.exe` ~4.0 MB, `check_filter.exe` ~0.9 MB.
