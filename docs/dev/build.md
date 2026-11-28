# Build

## Prerequisites

- Rust 2024 edition — 1.97.1+ required by rsigma 0.28; the workspace declares
  `rust-version = "1.97.1"` in `[workspace.package]`, inherited by every member,
  and uses `resolver = "3"`, so `cargo` refuses an older toolchain and will not
  resolve a dependency needing one
- For Windows cross-compilation from Linux: `cargo install cargo-xwin`
  (auto-downloads Windows SDK)
- For the macOS executable: a **macOS host** — the Linux cross-linker has no
  macOS SDK, so only `cargo check`/`cargo clippy` can cross-compile that target
- For the kernel driver only: a **Windows host** with WDK 10.0.22621, LLVM
  17.0.6 and the Visual Studio C++ workload (never `cargo xwin`)
- Platform inputs: see [What you need](../getting-started.md#what-you-need)

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
| `macos` | Endpoint Security (native client + `eslogger` fallback) | macOS | no |

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

The Linux release archive follows the `ubuntu-latest` runner image, so its
glibc requirement moves with that image (Ubuntu 26.04 currently means glibc
2.42). Build locally on an older LTS if you need broader compatibility.

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
[Sysmon coverage](windows/coverage.md). The **evtx** input
(`live_capture() = false`) needs no Windows API, so it also
builds and runs on Linux (`--no-default-features --features evtx`); its
semantics are documented in [cli.md](../user/cli.md#-evtx-one-shot-evtx-input-single-run).

> The diagnostic subcommands (`check-filter`, `list-rules`) are always
> compiled into the binary — no extra feature is required.

### Kernel driver

`sensor/windows/` is a separate KMDF crate outside the workspace (like
`sensor/ebpf`), built with the WDK + LLVM **on Windows**:

```pwsh
cargo build --locked --release --target x86_64-pc-windows-msvc   # inside sensor/windows/
```

The artifact is `sigmacatch_driver.dll`; rename it to `.sys` for the service
(test-signing required, see the [driver README](https://github.com/frack113/sigmacatch/blob/main/sensor/windows/README.md)).
`.github/workflows/driver.yml` is the gate: it pins WDK 10.0.22621 and LLVM
17.0.6, and the local [Windows dev VM](windows/vm.md) builds with the same
settings. Driver and collector both depend on `sensor/windows/protocol/`
(`sigmacatch-driver-protocol`: wire record + IOCTLs, protocol version 6): a
mismatched pair logs a warning and the collector runs on ETW alone.

> The `etw` feature has no dedicated CI job — the Windows CI job builds
> `winevt` and `winevt+evtx`. Cross-build it before a PR:
> `cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch --features winevt,etw`.

## macOS

```bash
cargo build --release -p sigmacatch --no-default-features --features macos
cargo test -p sigmacatch --no-default-features --features macos
```

`Backend::Auto` tries the native `endpoint-sec` client and falls back to
Apple's `eslogger` when the binary is not entitled. On a stock machine with SIP
enabled only the `eslogger` path works; see [macOS support](macos/index.md) for
the AMFI findings and the live-VM results.

The event model and the `eslogger` NDJSON parser are platform-independent and
also run on Linux with the same feature. The ES client and the process-spawning
code are compiled and tested only on macOS.

The macOS executable cannot be linked from Linux: the `x86_64-apple-darwin`
linker needs the macOS SDK and its frameworks. A compile-only cross-check is
still useful before a PR:

```bash
CRATE_CC_NO_DEFAULTS=1 CC_x86_64_apple_darwin=cc AR_x86_64_apple_darwin=ar \
  cargo clippy --target x86_64-apple-darwin --all-targets -p sigmacatch \
  --no-default-features --features macos
```

CI builds and tests the binary on a `macos-15-intel` runner.

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
