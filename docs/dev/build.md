# Build

## Prerequisites

- Rust 2024 edition — 1.96+ required by rsigma 0.26 (the workspace does not
  declare a `rust-version` field)
- For Windows cross-compilation from Linux: `cargo install cargo-xwin`
  (auto-downloads Windows SDK)
- For the kernel driver only: a **Windows host** with WDK 10.0.22621, LLVM
  17.0.6 and the Visual Studio C++ workload (never `cargo xwin`)
- Platform inputs: see [Requirements](https://github.com/frack113/sigmacatch#requirements) in the README

## Cargo features

One binary `sigmacatch` (plus the standalone `regressiondata-check`
validator); the **cargo features** select which inputs are compiled in:

| Feature | Input | Platform | Default? |
|---|---|---|---|
| `winevt` | Windows Event Log live (`EvtQueryW` → `EvtNext` → `EvtRender`) | Windows | yes |
| `etw` | native ETW sessions + TDH decode (Sysmon-schema events, no Sysmon) | Windows | no |
| `driver` | client of the `sigmacatch` kernel sensor (implies `etw`) | Windows | no |
| `evtx` | EVTX files one-shot, pure Rust | any | no |
| `auditd` | auditd `/var/log/audit/audit.log` | Linux | no |
| `builtin` | builtin syslog (central, authpriv, cron) | Linux | no |
| `sysmon` | Sysmon-for-Linux XML tail (depends on `builtin`) | Linux | no |
| `ebpf` | native eBPF probes (process/network/file/DNS) | Linux | no |

At runtime `--evtx <PATH>` selects the one-shot EVTX input; on Windows the
collector runs the Event Log channels next to exactly one process source (the
kernel driver when loaded, native ETW otherwise); on Linux every compiled **and
available** input runs in parallel. Bail at startup if no source is found.
The collectors' full specification (tailed files, guards, parsing) lives in
[Collectors](collectors/index.md); the runtime selection is documented in
[cli.md](../user/cli.md#windows-which-sources-run).

## Linux

```bash
# auditd + builtin syslog (base features, no root)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin

# + Sysmon-for-Linux tail
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,sysmon

# + native eBPF probes (root/CAP_BPF+CAP_PERFMON required at runtime, kernel 5.14+/BTF,
#   nightly toolchain + bpf-linker to build the probes). Without that toolchain a local
#   build embeds an empty placeholder that the loader rejects; a build without `sysmon`
#   then runs auditd/syslog with no sysmon source. On CI an empty placeholder is a hard
#   build error, never a fallback.
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin,ebpf

# Lint (separate variants — sysmon and ebpf are never merged into a single build)
cargo clippy -p sigmacatch --no-default-features --features auditd,builtin,sysmon -- -W warnings
cargo clippy -p sigmacatch --no-default-features --features auditd,builtin,ebpf -- -W warnings
```

`SIGMACATCH_EBPF_OBJECT` may point at a prebuilt probe object. It must be
built from the current wire format and expose the `EVENTS_ABI_V2` map; an
older object is rejected at load time instead of decoding records with stale
layouts.

The `winevt` feature (default) compiles as no-op stubs on Linux: toggling to
a Linux build always uses `--no-default-features`.

## Windows

```bash
cargo build --release -p sigmacatch                        # winevt (default feature)
cargo build --release -p sigmacatch --features evtx        # + one-shot EVTX
cargo build --release -p sigmacatch --features etw         # + native ETW (no Sysmon)
cargo build --release -p sigmacatch --features etw,driver  # + kernel sensor client
```

The **winevt** collector uses the native Winevt API on the resolved channels
and requires admin rights for the `Security` and `System` channels. The
**etw** collector adds the Sysmon-schema telemetry natively (elevated token
required); **driver** prefers the `sigmacatch` kernel sensor when its service is
loaded and falls back to ETW otherwise — the runtime split is in
[cli.md](../user/cli.md#windows-which-sources-run) and the coverage in
[sysmon-vs-sigmacatch.md](sysmon-vs-sigmacatch.md). The **evtx** input
(`live_capture() = false`) needs no Windows API, so it also
builds and runs on Linux (`--no-default-features --features evtx`); its
semantics are documented in [cli.md](../user/cli.md#-evtx-one-shot-evtx-input-single-run).

> The diagnostic subcommands (`check-filter`, `list-rules`) are always
> compiled into the binary — no extra feature is required.

### Kernel driver

`sigmacatch/driver/` is a separate KMDF crate outside the workspace (like
`sigmacatch/ebpf`), built with the WDK + LLVM **on Windows**:

```pwsh
cargo build --release --target x86_64-pc-windows-msvc   # inside sigmacatch/driver/
```

The artifact is `sigmacatch_driver.dll`; rename it to `.sys` for the service
(test-signing required, see the [driver README](https://github.com/frack113/sigmacatch/blob/main/sigmacatch/driver/README.md)).
`.github/workflows/driver.yml` is the gate: it pins WDK 10.0.22621 and LLVM
17.0.6, and the local dev VM
([Windows dev VM](windows-vm.md), `scripts/dev_win_build.sh`) builds with the
same settings. Driver and collector share `src/windows/driver_protocol.rs`
(wire record + IOCTLs, protocol version 6): a mismatched pair logs a warning and
the collector runs on ETW alone.

> The `etw` feature has no dedicated CI job — the Windows CI job builds
> `winevt` and `winevt+evtx`. Cross-build it before a PR:
> `cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --features winevt,etw`.

## Windows cross-compilation (from Linux)

```bash
# winevt (default)
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch
# winevt + evtx (to deploy on the collection VM)
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --features winevt,evtx
# winevt + etw (no driver: the driver crate needs the WDK on Windows)
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --features winevt,etw
# the standalone validator
cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --bin regressiondata-check
```

The resulting binaries are under `target/x86_64-pc-windows-msvc/release/`.
GitHub Actions CI builds natively on `windows-latest`.

## Binary size

Optimized release build: ~10 MB (observed on the x86_64-pc-windows-msvc
cross: `sigmacatch.exe` ~10.4 MB, ~11.7 MB with `evtx`).

Applied profile:

- `strip = true`
- `lto = true`
- `codegen-units = 1`
- tokio features: `rt`, `rt-multi-thread`, `macros`, `sync`, `time`, `signal`
