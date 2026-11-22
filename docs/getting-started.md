# Getting Started

The end-to-end first run: build the binary, fill in `config.yaml`, start a
capture, and check what was produced.

## What you need

- **Rust 1.97.1+** (2024 edition, required by rsigma 0.27). Building Windows from Linux additionally
  needs `cargo install cargo-xwin`.
- **A GitHub account with an SSH key and a fork of
  [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)** — sigmacatch pushes
  the captured regression data to your fork. Transport is SSH only; there is
  no HTTPS and no GitHub token.
  - To just try the tool, skip the git part:
    [offline mode](user/config.md#git) needs no account, no fork and no key.
- **A capture source**:
  - **Windows** — admin rights are required for the `Security` and `System`
    channels; the other channels work without. Sysmon is **not** required: the
    `etw` feature captures the same telemetry natively, and the `driver`
    feature adds the `sigmacatch` kernel driver for the ids ETW cannot reach
    (see [Windows without Sysmon](dev/windows/index.md)).
  - **Linux** — an auditd log at `/var/log/audit/audit.log` and/or the
    standard syslog files. No root needed. See
    [Linux telemetry](dev/linux/index.md).
  - **macOS** — a macOS host (the executable cannot be linked from Linux).
    The Endpoint Security collector runs as root and uses Apple's `eslogger`
    on a stock machine — no entitlement needed. See
    [macOS support](dev/macos/index.md).

## 1. Build

```bash
# Windows (default features — live Winevt)
cargo build --release -p sigmacatch

# Windows without Sysmon (Event Log + ETW; add ,driver for the kernel sensor)
cargo build --release -p sigmacatch --features etw
cargo build --release -p sigmacatch --features etw,driver

# Linux (auditd + builtin syslog, no root)
cargo build --release -p sigmacatch --no-default-features --features auditd,builtin

# One-shot EVTX pass (cross-platform)
cargo build --release -p sigmacatch --no-default-features --features evtx
```

The full feature matrix (`sysmon`, `ebpf`), the kernel-driver build and
cross-compilation are in [Build](dev/build.md).

## 2. First run — fill in `config.yaml`

Run the binary in the directory that will hold your work:

```bash
./target/release/sigmacatch
```

The first run writes a `config.yaml` with placeholder values and **stops
with `exit 1`**. Edit the file:

```yaml
git:
  author: "your-github-username"      # the placeholder "sigmacatch" is rejected
  email: "you@example.com"            # required, must contain @
  fork_repo_url: "git@github.com:your-github-username/sigma.git"
```

Every other key has a working default. Re-run the same command.

## 3. What happens next

1. The sigma repo is cloned **shallow and sparse** (only `rules*` and
   `regression_data/` materialize) under `./sigma`.
2. A working branch `sigmacatch/<YYYYMMDD>` is created from it.
3. The collector starts — the live Winevt collector together with one process
   source on Windows (the `sigmacatch` kernel driver when it is loaded, native
   ETW otherwise), or every compiled and available Linux input in parallel —
   and the engine evaluates events against the loaded rules.
4. Every 30 s, matched events are written as regression data under
   `./sigma/regression_data/` — one commit per captured rule.
5. With `git.contrib: true` (or `--contrib`), the branch is pushed to your
   fork when the run ends.

The full git mechanics are in [SigmaHQ workflow](dev/git.md); the output
format is specified in [Regression data](regression_data/index.md).

## 4. Stop the run

- **Graceful stop** (the in-flight cycle is drained, flushed and committed):
  `touch .sigmacatch.stop`
- **Bounded run**: `-r <N>` exits after N collection cycles
- **Hard stop**: Ctrl+C — an in-flight generation cycle is dropped

## 5. Check what was produced

```bash
cargo build --release -p sigmacatch --bin regressiondata-check
./target/release/regressiondata-check
```

It replays every stored event through the detection engine and prints a
pass/fail summary (exit 1 on any failure). Full reference:
[regressiondata-check](user/regressiondata-check.md).

## Next steps

- [CLI](user/cli.md) — flags and `--evtx`
- [Diagnostic subcommands](user/diagnostics.md) — `check-filter`, `list-rules`
- [Configuration](user/config.md) — every `config.yaml` key
- [Troubleshooting](user/troubleshooting.md) — when the run refuses to go
- [regressiondata-check](user/regressiondata-check.md) — validate what was produced
- [Windows without Sysmon](dev/windows/index.md) — ETW and kernel-driver telemetry
