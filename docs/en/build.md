# Build

## Prerequisites

- Rust 2024 edition (1.85+)
- For Windows cross-compilation from Linux: `cargo install cargo-xwin` (auto-downloads Windows SDK)

## Linux / macOS

```bash
# Build the Linux binary
cargo build --release -p sigmacatch-lnx

# Lint
cargo clippy -- -W warnings
```

Produces `sigmacatch-linux`: **auditd** collector if `/var/log/audit/audit.log` exists, otherwise **central syslog** collector (`/var/log/messages` then `/var/log/syslog`), otherwise bail at startup.

On Linux/macOS the Windows collectors are no-op stubs — the pipeline still runs end-to-end for testing (`cargo build -p sigmacatch-win`).

## Windows

```bash
cargo build --release -p sigmacatch-win
```

Two binaries are produced, each with a single collector (cargo features, default both):

- **`sigmacatch-channel`** (winevt): native Winevt API (`EvtQueryW` → `EvtNext` → `EvtRender`) on resolved channels. Requires admin rights for `Security` and `System` channels.
- **`sigmacatch-etw`** (etw) [beta]: direct ETW collection via ferrisetw (18 providers, generic provider→channel routing, real EventID preserved). Requires no admin rights for most providers.

Isolated builds (a binary without the other collector linked):

```bash
# Winevt only
cargo build --release --bin sigmacatch-channel --no-default-features --features winevt

# ETW only
cargo build --release --bin sigmacatch-etw --no-default-features --features etw

# Diagnostics only (tools feature)
cargo build --release -p sigmacatch-win --no-default-features --features tools
```

Linux equivalent isolated builds:

```bash
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin
cargo build --release -p sigmacatch-lnx --no-default-features --features tools
```

## Windows cross-compilation (from Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win
```

The resulting binaries are at `target/x86_64-pc-windows-msvc/release/sigmacatch-channel.exe` and `sigmacatch-etw.exe`. GitHub Actions CI builds natively on `windows-latest`.

## Binary size

Optimized release build: ~11MB per binary.

Applied profile:

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- tokio features: `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Workspace

The project is a cargo workspace of 12 packages (2 binary crates + 10 libraries):

```bash
# Build everything
cargo build --workspace

# Build a specific crate
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

## Main binaries

| Binary | Path | Description |
|---|---|---|
| `sigmacatch-channel` | `sigmacatch-win/src/main_winevt.rs` | Winevt capture (multi-channel) + evaluation + regression generation |
| `sigmacatch-etw` | `sigmacatch-win/src/main_etw.rs` | ETW capture (ferrisetw) + evaluation + regression generation [beta] |
| `sigmacatch-linux` | `sigmacatch-lnx/src/main_linux.rs` | Auditd or syslog capture (auto-detected) + evaluation + regression generation |

## Diagnostic subcommands

Feature `tools`, off by default. Two sets: on `sigmacatch-channel` (check, check-filter, check-channels, list-rules, get-atomic) and on `sigmacatch-linux` (check, check-filter, list-rules).

| Command | Description |
|---|---|
| `check` | Deep validation of regression data (`./sigma/regression_data`) |
| `check-filter` | Validates `SigmaFilterConfig` against real Sigma rules (ground-truth counts) |
| `check-channels` *(win only)* | Resolves and lists the collected Windows channels |
| `list-rules` | Lists the loaded rules (techniques, ART link) |
| `get-atomic` *(win only)* | Generates `run_atomic.ps1` (chained `Invoke-AtomicTest`) for rules without regression data |

Details and sample output → [cli.md](cli.md).

Observed sizes (x86_64-pc-windows-msvc cross, release): `sigmacatch-channel.exe` ~10.4 MB,
`sigmacatch-etw.exe` ~11 MB.
