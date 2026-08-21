# Build

## Prerequisites

- Rust 2024 edition (1.85+)
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

Two binaries are produced, each with a single collector (cargo features, default both):

- **`sigmacatch-channel`** (winevt): native Winevt API (`EvtQueryW` → `EvtNext` → `EvtRender`) on resolved channels. Requires admin rights for `Security` and `System` channels.
- **`sigmacatch-etw`** (etw) [beta]: direct ETW collection via ferrisetw (18 providers, generic provider→channel routing, real EventID preserved). Requires no admin rights for most providers.

Isolated builds (a binary without the other collector linked):

```bash
# Winevt only
cargo build --release --bin sigmacatch-channel

# ETW only
cargo build --release --bin sigmacatch-etw --no-default-features --features etw
```

## Windows cross-compilation (from Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc
```

The resulting binaries are at `target/x86_64-pc-windows-msvc/release/sigmacatch-channel.exe` and `sigmacatch-etw.exe`.

## Binary size

Optimized release build: ~11MB per binary.

Applied profile:

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- tokio features: `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Workspace

The project is a cargo workspace of 13 packages (1 lib crate + 12 libraries):

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
cargo build -p input-windows-etw
cargo build -p sigmacatch-regression
cargo build -p sigmacatch-evtx-writer
cargo build -p sigmacatch-types
cargo build -p sigmacatch-repo
cargo build -p input-evtx
```

## Main binaries

| Binary | Path | Description |
|---|---|---|
| `sigmacatch-channel` | `sigmacatch/src/main_winevt.rs` | Winevt capture (multi-channel) + evaluation + regression generation |
| `sigmacatch-etw` | `sigmacatch/src/main_etw.rs` | ETW capture (ferrisetw) + evaluation + regression generation [beta] |
| `sigmacatch-auditd` | `sigmacatch/src/main_auditd.rs` | Auditd capture (tail) + evaluation + regression generation |

## Diagnostic subcommands

All diagnostic commands are subcommands of `sigmacatch-channel` (feature `tools`, off by default):

| Command | Description |
|---|---|
| `check` | Deep validation of regression data (`./sigma/regression_data`) |
| `check-filter` | Validates `SigmaFilterConfig` against real Sigma rules (ground-truth counts) |
| `check-channels` | Resolves and lists the collected Windows channels |
| `list-rules` | Lists the loaded rules (techniques, ART link) |
| `get-atomic` | Generates `run_atomic.ps` (chained `Invoke-AtomicTest`) for rules without regression data |

Observed sizes (x86_64-pc-windows-msvc cross, release): `sigmacatch-channel.exe` ~10.4 MB,
`sigmacatch-etw.exe` ~11 MB.
