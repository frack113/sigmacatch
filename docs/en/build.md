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

Produces `sigmacatch-linux` (default features `auditd` + `builtin`). It runs, in parallel,
the **auditd** collector when `/var/log/audit/audit.log` exists and the **builtin syslog**
collectors (every existing file among central `/var/log/messages`, `/var/log/syslog`;
authpriv `/var/log/secure`, `/var/log/auth.log`; cron `/var/log/cron`, `/var/log/cron.log`).
No Sysmon source: the `-sysmon` and `-ebpf` flavour binaries add it (see below). Bail at
startup if no source is found. Full specification of the three collectors:
[architecture.md](architecture.md).

The two extended Linux flavours additionally embed a Sysmon source, selected by cargo feature:

```bash
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin,sysmon  # sigmacatch-linux-sysmon
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin,ebpf   # sigmacatch-linux-ebpf (root/CAP_BPF+CAP_PERFMON required)
```

On Linux/macOS the Windows collectors are no-op stubs — the pipeline still runs end-to-end
for testing (`cargo build -p sigmacatch-win`).

## Windows

```bash
cargo build --release -p sigmacatch-win
```

Two binaries are produced, each with a single collector (cargo features, both enabled by default):

- **`sigmacatch-channel`** (winevt): native Winevt API (`EvtQueryW` → `EvtNext` → `EvtRender`) on resolved channels. Requires admin rights for `Security` and `System` channels.
- **`sigmacatch-etw`** (etw) [beta]: direct ETW collection via ferrisetw (18 providers, generic provider→channel routing, real EventID preserved). Requires no admin rights for most providers.

Isolated builds (a binary without the other collector linked):

```bash
# Winevt only
cargo build --release --bin sigmacatch-channel --no-default-features --features winevt

# ETW only
cargo build --release --bin sigmacatch-etw --no-default-features --features etw
```

> The diagnostic subcommands (`check-filter`, `list-rules`) are always compiled into the
> binary — no extra feature is required. Each `[[bin]]` target requires its collector
> feature (`winevt` or `etw`) via `required-features`.

Linux equivalent isolated builds:

```bash
cargo build --release -p sigmacatch-lnx --no-default-features --features auditd,builtin
```

## Windows cross-compilation (from Linux)

```bash
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch-win
```

The resulting binaries are at `target/x86_64-pc-windows-msvc/release/sigmacatch-channel.exe`
and `sigmacatch-etw.exe`. GitHub Actions CI builds natively on `windows-latest`.

## Binary size

Optimized release build: ~10–11 MB per binary (observed on the x86_64-pc-windows-msvc cross:
`sigmacatch-channel.exe` ~10.4 MB, `sigmacatch-etw.exe` ~11 MB).

Applied profile:

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- tokio features: `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Diagnostic subcommands

The `check-filter` and `list-rules` subcommands are **always compiled** into both
`sigmacatch-channel` and `sigmacatch-linux` — no dedicated cargo feature is required
(the `tools` feature has been removed).

Regression validation (`check`) is no longer a subcommand: it is the standalone
**`regressiondata-check`** binary (`regressiondata-check`), cross-platform, which needs no
collector and no extra feature:

```bash
# Linux
cargo build --release -p regressiondata-check
# Windows
cargo xwin build --release --target x86_64-pc-windows-msvc -p regressiondata-check
```

Details and sample output → [cli.md](cli.md).
