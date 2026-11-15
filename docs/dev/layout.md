# Layout

Reference page: the directory tree and the module dependency graph. Read
[Architecture](architecture.md) first — this page is for looking things up.

## Repository tree

```text
sigmacatch/
├── Cargo.toml                    # Workspace root
├── sigmacatch/                   # Main package (library + two binaries)
│   ├── Cargo.toml                # features: winevt (default), evtx, etw, driver, auditd, builtin, sysmon, ebpf
│   ├── build.rs                  # eBPF object builder (Linux target + feature `ebpf` only)
│   ├── examples/                 # etw_dump (etw), etw_driver_probe (driver), ebpf_parse_check (ebpf)
│   ├── src/
│   │   ├── main.rs               # Dispatch: --evtx → evtx input; Windows → inputs::windows; Linux → inputs::linux
│   │   ├── lib.rs                # Module declarations + re-exports (CollectorKind, run, bootstrap_repo_regression, DataFormat)
│   │   ├── cli.rs                # Dispatch + diagnostic subcommands: check-filter, list-rules
│   │   ├── runner.rs             # run<C: CollectorKind> shared pipeline + CollectorKind trait + bootstrap_repo_regression
│   │   ├── logging.rs            # Two-layer tracing init (stderr error/info, daily rolling file)
│   │   ├── config.rs             # Config, GitConfig, SigmaFilterConfig, LogConfig, CliArgs, parse_args, custom_channels.yaml
│   │   ├── types.rs              # Event, Alert, RegressionHeader, Product, EventProducer, XML parsing, phf logsource tables
│   │   ├── evtx_reader.rs        # EVTX file parsing → Event (cross-platform, used by both binaries)
│   │   ├── ebpf_common.rs        # eBPF ring-buffer wire types (shared with the probe crate via #[path])
│   │   ├── detection/            # DetectionEngine + per-platform pipelines + channel_resolver
│   │   ├── rule/                 # SigmahqRules: load/filter/dedupe/remove_id + thresholds, attack, discover
│   │   ├── repo/                 # grit-lib wrapper: SigmaRepo, plumbing/, porcelain, branch, signing, transport
│   │   ├── regression/           # SigmahqRegression, InfoYml, DataFormat (evtx/log/json), logtype, format, evtx_writer
│   │   ├── windows/              # Shared with the driver crate via #[path]: driver_protocol (wire + IOCTLs),
│   │   │                         #   nt_file, signature (WinVerifyTrust + catalogs), version_info (PE resources)
│   │   ├── inputs/               # Input adapters (feature × platform gate matrix in mod.rs):
│   │   │   ├── mod.rs            #   feature × target_os gate matrix
│   │   │   ├── windows.rs        #   Windows orchestrator: channels + exactly one process source (driver or ETW)
│   │   │   ├── winevt.rs         #   WinevtCollector (Event Log live, feature `winevt`)
│   │   │   ├── channels.rs       #   Winevt query loop (EvtQueryW/EvtNext/EvtRender, multi-channel)
│   │   │   ├── etw.rs            #   Native ETW sessions + TDH dispatch (feature `etw`, Windows)
│   │   │   ├── etw_event.rs      #   TDH properties → typed fields
│   │   │   ├── etw_process.rs    #   Live-process facts (CommandLine, User, parent, creation) + pid→image cache
│   │   │   ├── etw_registry.rs   #   Kernel-Registry handle → path cache (EID 12/13/14)
│   │   │   ├── etw_sysmon.rs     #   Sysmon-schema XML rendering (provider/channel `sigmacatch`)
│   │   │   ├── etw_driver.rs     #   Kernel-sensor client: kind-tagged record → Sysmon-schema event (feature `driver`)
│   │   │   ├── pe_format.rs      #   PE reader: hashes, IMPHASH, version resource
│   │   │   ├── registry_format.rs #  Native registry path → Sigma spelling (HKLM\…, HKU\…)
│   │   │   ├── wmi_format.rs     #   WMI-Activity 5858 → EID 19/20/21
│   │   │   ├── evtx.rs           #   EvtxCollector (one-shot EVTX files, feature `evtx`)
│   │   │   ├── linux.rs          #   LinuxCollector + run() (any Linux input feature)
│   │   │   ├── auditd.rs         #   Auditd collector (LineHandler grouping by event id, via tail)
│   │   │   ├── syslog.rs         #   Builtin syslog collector (LineHandler per file, via tail)
│   │   │   ├── sysmon.rs         #   Sysmon-for-Linux collector (LineHandler, via tail, feature `sysmon`)
│   │   │   ├── tail.rs           #   Shared tail driver (LineHandler trait + rotation detection)
│   │   │   ├── sysmon_parse.rs   #   Sysmon XML parsing (feature `builtin`)
│   │   │   ├── ebpf.rs           #   eBPF loader + dispatch (feature `ebpf`, privileges required)
│   │   │   └── ebpf_event.rs     #   eBPF → nested Sysmon-shaped JSON + tests
│   │   ├── bin/
│   │   │   └── regressiondata-check.rs # Standalone validator (--json, --ignore, --fix, --path)
│   │   └── tests/                # 20 integration tests (runner, cli, collectors, e2e)
│   │       └── fixtures/         # sample.xml, sample.evtx, valid-single.evtx + sigma* fixtures
│   ├── ebpf/                     # Nested nightly eBPF probe crate (excluded via [workspace], bpfel-unknown-none)
│   │   ├── .cargo/config.toml    #   bpfel target, bpf-linker, build-std=core
│   │   └── src/main.rs           #   8 tracepoints: execve, exec, exit, connect, openat (enter+exit), sendto, sendmsg
│   └── driver/                   # Nested KMDF kernel driver (excluded via [workspace], built by .github/workflows/driver.yml)
│       ├── Cargo.toml            #   wdk-build / wdk-sys, KMDF 1.33
│       ├── build.rs              #   WDK configuration (WDKContentRoot / Version_Number honoured)
│       └── src/
│           ├── lib.rs            #   DriverEntry, control device \Device\sigmacatch, IOCTLs, ring buffer,
│           │                     #   process/image/thread/registry callbacks
│           └── flt.rs            #   Hand-written fltmgr FFI + minifilter (file/pipe events)
```

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
├── src/inputs/windows.rs (channels + driver/ETW orchestration, Windows only)
├── src/inputs/etw*.rs    (ETW sessions, TDH decode, process facts, registry, Sysmon rendering)
├── src/inputs/etw_driver.rs (kernel sensor client, wire types from src/windows/driver_protocol.rs)
├── src/windows/          (driver_protocol, nt_file, signature, version_info — shared with the driver crate)
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

`evtx_reader` depends on `types` + the `evtx` crate. `regressiondata-check`
reuses the same modules (`detection`, `rule`, `regression`, `types`,
`evtx_reader`) with `linux-audit-parser` according to each entry's `LogType`.
