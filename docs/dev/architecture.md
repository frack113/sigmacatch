# Architecture

One binary `sigmacatch` captures real OS events, matches them against
[SigmaHQ](https://github.com/SigmaHQ/sigma) rules and writes regression data.
Cargo features select which inputs are compiled in, and `main.rs` picks the
runtime input. A second binary, `regressiondata-check`, validates regression
data without a collector.

| Page | Content |
|---|---|
| [Collectors](collectors.md) | Per-input behaviour: Windows logsource, Linux tails, eBPF, one-shot EVTX, shared tail driver |
| [Pipeline](pipeline.md) | The shared `run()` runner, generation cycles, one-shot variant |
| [Design notes](design-notes.md) | Stop file, skip set, output location, observability, memory |
| [Build](build.md) | Features, platform builds, cross-compilation |
| [SigmaHQ workflow](git.md) | Transport, clone, working branch, commits, skip set, offline |

## Cargo workspace

The project is a single cargo workspace package (`sigmacatch`), plus a nested nightly-only eBPF probe crate (`sigmacatch/ebpf`) excluded from the workspace:

```text
sigmacatch/
├── Cargo.toml                    # Workspace root
├── sigmacatch/                   # Main package (library + two binaries)
│   ├── Cargo.toml                # features: winevt (default), evtx, auditd, builtin, sysmon, ebpf
│   ├── build.rs                  # eBPF object builder (Linux target + feature `ebpf` only)
│   ├── src/
│       ├── main.rs               # Dispatch: --evtx → evtx input; winevt on Windows; linux inputs on Linux
│       ├── lib.rs                # Module declarations + re-exports (CollectorKind, run, bootstrap_repo_regression, DataFormat)
│       ├── cli.rs                # Dispatch + diagnostic subcommands: check-filter, list-rules
│       ├── runner.rs             # run<C: CollectorKind> shared pipeline + CollectorKind trait + bootstrap_repo_regression
│       ├── logging.rs            # Two-layer tracing init (stderr error/info, daily rolling file)
│       ├── config.rs             # Config, GitConfig, SigmaFilterConfig, LogConfig, CliArgs, parse_args, custom_channels.yaml
│       ├── types.rs              # Event, Alert, RegressionHeader, Product, EventProducer, XML parsing, phf logsource tables
│       ├── evtx_reader.rs        # EVTX file parsing → Event (cross-platform, used by both binaries)
│       ├── ebpf_common.rs        # eBPF ring-buffer wire types (shared with the probe crate via #[path])
│       ├── detection/            # DetectionEngine + per-platform pipelines + channel_resolver
│       ├── rule/                 # SigmahqRules: load/filter/dedupe/remove_id + thresholds, attack, discover
│       ├── repo/                 # grit-lib wrapper: SigmaRepo, plumbing/, porcelain, branch, signing, transport
│       ├── regression/           # SigmahqRegression, InfoYml, DataFormat (evtx/log), logtype, format, evtx_writer
│       ├── inputs/               # Input adapters (feature × platform gate matrix in mod.rs):
│       │   ├── mod.rs            #   feature × target_os gate matrix
│       │   ├── winevt.rs         #   WinevtCollector (Event Log live, feature `winevt`)
│       │   ├── evtx.rs           #   EvtxCollector (one-shot EVTX files, feature `evtx`)
│       │   ├── channels.rs       #   Winevt collector (EvtQueryW/EvtNext/EvtRender, multi-channel)
│       │   ├── linux.rs          #   LinuxCollector + run() (any Linux input feature)
│       │   ├── auditd.rs         #   Auditd collector (LineHandler grouping by event id, via tail)
│       │   ├── syslog.rs         #   Builtin syslog collector (LineHandler per file, via tail)
│       │   ├── sysmon.rs         #   Sysmon-for-Linux collector (LineHandler, via tail, feature `sysmon`)
│       │   ├── tail.rs           #   Shared tail driver (LineHandler trait + rotation detection)
│       │   ├── sysmon_parse.rs   #   Sysmon XML parsing (feature `builtin`)
│       │   ├── ebpf.rs           #   eBPF loader + dispatch (feature `ebpf`, privileges required)
│       │   └── ebpf_event.rs     #   eBPF → nested Sysmon-shaped JSON + tests
│       ├── bin/
│       │   └── regressiondata-check.rs  # Standalone cross-platform binary: regression check (--json, --ignore, --fix, --path)
│       └── tests/                  # 20 integration tests (runner, cli, collectors, e2e)
│           └── fixtures/           # sample.xml, sample.evtx, valid-single.evtx + sigma{,_malformed,_malformed_reference,_negative}/ fixtures
│   └── ebpf/                       # Nested nightly eBPF probe crate (excluded via [workspace], bpfel-unknown-none)
│       ├── .cargo/config.toml    #   bpfel target, bpf-linker, build-std=core
│       └── src/main.rs           #   8 tracepoints: execve, exec, exit, connect, openat (enter+exit), sendto, sendmsg
```

## Collectors

One binary `sigmacatch` is produced from the `sigmacatch` package. Cargo features
select which inputs are compiled in, and `main.rs` picks the runtime input: the
one-shot EVTX collector when `--evtx` is present, the live Winevt collector on
Windows, or the set of compiled-in, available Linux inputs. Plus the standalone
cross-platform `regressiondata-check` (second binary of the `sigmacatch` package):

| Input | Module | Features | Description |
|---|---|---|---|
| winevt | `sigmacatch/src/inputs/channels.rs` | `winevt` | Native Winevt API (`EvtQueryW`/`EvtNext`/`EvtRender`), multi-channel, replayable |
| evtx | `sigmacatch/src/inputs/evtx.rs` | `evtx` | One-shot `.evtx` collector (`live_capture() = false`): parse → detect → generate regression (pure-Rust EVTX writer) → commit/push, then exit |
| auditd | `sigmacatch/src/inputs/auditd.rs` | `auditd` | auditd tail (no root needed) |
| builtin syslog | `sigmacatch/src/inputs/syslog.rs` | `builtin` | Central/authpriv/cron syslog tails (no root needed) |
| sysmon (tail) | `sigmacatch/src/inputs/sysmon.rs` | `sysmon` (implies `builtin`) | Legacy Sysmon-for-Linux XML tail |
| sysmon (ebpf) | `sigmacatch/src/inputs/ebpf.rs` | `ebpf` | Native eBPF probes (root or CAP_BPF+CAP_PERFMON required) |

The per-input behaviour — Windows logsource handling, the Linux collectors,
the shared `CollectorKind` machinery and the tail driver — is in
[Collectors](collectors.md).

## Module dependency graph

```text
sigmacatch (package)
├── src/runner.rs         (run<C: CollectorKind>, shared pipeline + tracing init + cli module)
├── src/config.rs         (Config, CliArgs)
├── src/rule/             (SigmahqRules: load/filter/remove_id)
├── src/detection/        (DetectionEngine: pipelines + bloom + LogSourceExtractor + resolve_channels)
├── src/regression/       (SigmahqRegression: skip set + data generation)
├── src/types.rs          (Event, Alert, RegressionHeader, Product, EventProducer, XML parsing)
├── src/repo/             (SigmaRepo, grit-lib wrapper)
├── src/evtx_reader.rs    (parse EVTX → Event)
└── serde                 (JSON serialization of diagnostic output)

regressiondata-check (second binary of sigmacatch package)
├── reuses src/detection/ (DetectionEngine)
├── reuses src/rule/      (SigmahqRules: load/filter)
├── reuses src/regression/ (SigmahqRegression)
├── reuses src/types.rs   (Event)
├── reuses src/evtx_reader.rs (parse EVTX → Event)
└── linux-audit-parser    (parse auditd records → Event)
```

The module `evtx_reader` depends on `types` + the `evtx` crate.
`regressiondata-check` (regression validation, cross-platform) reuses the same modules
(`detection`, `rule`, `regression`, `types`, `evtx_reader`) with `linux-audit-parser`
(auditd) according to each entry's `LogType`. The diagnostic subcommands (`cli.rs`) parse
arguments manually and use `serde` for their JSON output (always compiled).
