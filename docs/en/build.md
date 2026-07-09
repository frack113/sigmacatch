# Build

## Prerequisites

- Rust 2021 edition (1.70+)
- For Windows cross-compilation: `rustup target add x86_64-pc-windows-gnu` + mingw-w64

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
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

The resulting binary is at `target/x86_64-pc-windows-gnu/release/sigmacatch.exe`.

## Binary size

Optimized release build: ~12MB (single headless binary).

Applied profile:
- `strip = true`
- `lto = true`
- `codegen-units = 1`
- tokio features reduced to `rt`, `rt-multi-thread`, `macros`, `sync`, `time`

## Binary

| Binary | Path | Description |
|---|---|---|
| `sigmacatch` | `src/main.rs` | Headless only. Outputs stats as JSON to stdout, writes regression data to disk |
