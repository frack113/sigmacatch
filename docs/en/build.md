# Build

## Prerequisites

- Rust 2024 edition (1.85+)
- For Windows cross-compilation from Linux: `cargo install cargo-xwin` (auto-downloads Windows SDK)

## Cargo features

One binary `sigmacatch`; the **cargo features** select which inputs are compiled in:

| Feature | Input | Platform | Default? |
|---|---|---|---|
| `winevt` | Windows Event Log live (`EvtQueryW` → `EvtNext` → `EvtRender`) | Windows | yes |
| `evtx` | EVTX files one-shot, pure Rust | any | no |
| `auditd` | auditd `/var/log/audit/audit.log` | Linux | no |
| `builtin` | builtin syslog (central, authpriv, cron) | Linux | no |
| `sysmon` | Sysmon-for-Linux XML tail (depends on `builtin`) | Linux | no |
| `ebpf` | native eBPF probes (process/network/file/DNS) | Linux | no |

At runtime `--evtx <PATH>` selects the one-shot EVTX input; on Windows the live
Winevt collector is the default; on Linux every compiled **and available** input
runs in parallel. Bail at startup if no source is found.

## Linux

```bash
# auditd + builtin syslog (base features, no root)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin

# + Sysmon-for-Linux tail
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,sysmon

# + native eBPF probes (root/CAP_BPF+CAP_PERFMON required at runtime, kernel 5.14+/BTF,
#   nightly toolchain + bpf-linker to build the probes — otherwise a placeholder falls back to the tail)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,ebpf

# Lint
cargo clippy -p sigmacatch --no-default-features --features auditd,builtin,sysmon,ebpf -- -W warnings
```

It runs, in parallel, the **auditd** collector when `/var/log/audit/audit.log` exists and the
**builtin syslog** collectors (every existing file among central `/var/log/messages`,
`/var/log/syslog`; authpriv `/var/log/secure`, `/var/log/auth.log`; cron `/var/log/cron`,
`/var/log/cron.log`). Full specification of the collectors: [architecture.md](architecture.md).

The `winevt` feature (default) compiles as no-op stubs on Linux: toggling to a Linux
build always uses `--no-default-features`.

## Windows

```bash
cargo build --release -p sigmacatch        # winevt (default feature)
cargo build --release -p sigmacatch --features evtx   # + one-shot EVTX
```

The **winevt** collector uses the native Winevt API on the resolved channels; it requires
admin rights for the `Security` and `System` channels. The **evtx** input (`live_capture() = false`)
recursively scans a directory of `.evtx` files, matches the events against Sigma rules, generates
SigmaHQ regression data, then commits/pushes to a `sigmacatch/<date>` branch and exits — no
Windows API, so it also builds and runs on Linux (`--no-default-features --features evtx`).

```bash
# One-shot EVTX input only (cross-platform)
cargo build --release -p sigmacatch --no-default-features --features evtx
```

> The diagnostic subcommands (`check-filter`, `list-rules`) are always compiled into the
> binary — no extra feature is required.

## Windows cross-compilation (from Linux)

```bash
# winevt (default)
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch
# winevt + evtx (to deploy on the collection VM)
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --features evtx
```

The resulting binary is at `target/x86_64-pc-windows-msvc/release/sigmacatch.exe`.
GitHub Actions CI builds natively on `windows-latest`.

## Binary size

Optimized release build: ~10 MB (observed on the x86_64-pc-windows-msvc cross:
`sigmacatch.exe` ~10.4 MB, ~11.7 MB with `evtx`).

Applied profile:

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- tokio features: `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`

## Diagnostic subcommands

The `check-filter` and `list-rules` subcommands are **always compiled** into the
`sigmacatch` binary — no dedicated cargo feature is required (the `tools` feature
has been removed).

Regression validation (`check`) is not a subcommand: it is the second binary
**`regressiondata-check`** of the `sigmacatch` package, cross-platform, which needs no
collector and no extra feature:

```bash
# Linux
cargo build --release -p sigmacatch --bin regressiondata-check
# Windows
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --bin regressiondata-check
```

Details and sample output → [cli.md](cli.md).
