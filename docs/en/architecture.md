# Architecture

## Cargo workspace

The project is a cargo workspace of 12 packages, plus 1 excluded nightly crate (`sigmacatch-ebpf`):

```text
sigmacatch/
├── Cargo.toml                    # Workspace root
├── sigmacatch/                   # Single binary `sigmacatch` (features select the inputs)
│   ├── Cargo.toml                # features: winevt (default), evtx, auditd, builtin, sysmon, ebpf
│   └── src/
│       ├── main.rs               # Dispatch: --evtx → evtx input; winevt on Windows; linux inputs on Linux
│       ├── lib.rs                # Module gates (platform + feature)
│       ├── cli.rs                # Diagnostic subcommands: check-filter, list-rules
│       ├── winevt.rs             # WinevtCollector (live Event Log, feature `winevt`)
│       ├── evtx.rs               # EvtxCollector (one-shot EVTX files, feature `evtx`)
│       ├── channels.rs           # Winevt collector (EvtQueryW/EvtNext/EvtRender, multi-channel)
│       ├── linux.rs              # LinuxCollector + run() (any Linux input feature)
│       ├── auditd.rs             # Auditd collector (LineHandler grouping by event id, via tail)
│       ├── syslog.rs             # Builtin syslog collector (LineHandler per file, via tail)
│       ├── sysmon.rs             # Sysmon-for-Linux collector (LineHandler, via tail, feature `sysmon`)
│       ├── tail.rs               # Shared tail driver (LineHandler trait + rotation detection)
│       ├── sysmon_parse.rs       # Sysmon XML parsing (feature `builtin`)
│       ├── ebpf.rs               # eBPF loader + dispatch (feature `ebpf`, privileges required)
│       ├── ebpf_event.rs         # eBPF → Sysmon XML synthesis + tests
│       └── build.rs              # eBPF object builder (Linux target + feature `ebpf` only)
├── regressiondata-check/             # Standalone cross-platform binary: regression check (--json, --ignore, --fix, --path)
└── crates/
    ├── sigmacatch-ebpf/          # eBPF probes (excluded workspace, nightly, bpfel-unknown-none)
    │   └── src/main.rs           # 6 tracepoints: execve/exec/exit/connect/openat+exit/sendto+sendmsg
    ├── sigmacatch-ebpf-common/   # Shared no_std types for eBPF ring buffer (ExecEvent, NetEvent, ...)
    ├── sigmacatch-runner/        # Pipeline shared by every collector crate:
    │   ├── src/runner.rs         #   run<C: CollectorKind> + CollectorKind trait + bootstrap_repo_regression (sigmacatch/<date> branch, clone/pull)
    │   │                         #   event loop + process_and_generate + commit/push)
    │   ├── src/cli.rs            #   shared diagnostic CLI (check-filter, list-rules)
    │   └── src/logging.rs        #   two-layer tracing init (stderr `error`/`info`, daily rolling file)
    ├── sigmacatch-config/        # Config YAML + CLI parsing + custom_channels.yaml
    ├── sigmacatch-rule/          # SigmahqRules: rule loading (parse_sigma_yaml), filter, dedupe, remove_id
    │                             #   + attack.rs (SigmaRuleExt ATT&CK) + discover.rs + thresholds.rs (LoadStats)
    ├── sigmacatch-detection/     # DetectionEngine wrapper + embedded per-platform pipelines
    │                             #   (1_win_logsource.yml, 2_win_field_name.yml, 3_lnx_logsource.yml,
    │                             #   4_lnx_field_name.yml — transformations gated by product rule_conditions) + channel_resolver
    ├── sigmacatch-regression/    # SigmahqRegression (get_sigma_id, add, retire), InfoYml, DataFormat
    │                             #   (evtx.rs, evtx_writer.rs, format.rs, info.rs, logtype.rs, long_path.rs)
    ├── sigmacatch-types/         # Shared types: Event, Alert, RegressionHeader + XML parsing + logsource mapping tables
    ├── sigmacatch-repo/          # grit-lib wrapper + SigmaRepo + git operations + signing.rs + transport.rs
    └── input-windows-evtx/       # EVTX file parser → Event
```

## Collectors

One binary `sigmacatch` is produced from the `sigmacatch/` crate. Cargo features
select which inputs are compiled in, and `main.rs` picks the runtime input: the
one-shot EVTX collector when `--evtx` is present, the live Winevt collector on
Windows, or the set of compiled-in, available Linux inputs. Plus the standalone
cross-platform `regressiondata-check`:

| Input | Module | Features | Description |
|---|---|---|---|
| winevt | `sigmacatch/src/channels.rs` | `winevt` | Native Winevt API (`EvtQueryW`/`EvtNext`/`EvtRender`), multi-channel, replayable |
| evtx | `sigmacatch/src/evtx.rs` | `evtx` | One-shot `.evtx` collector (`live_capture() = false`): parse → detect → generate regression (pure-Rust EVTX writer) → commit/push, then exit |
| auditd | `sigmacatch/src/auditd.rs` | `auditd` | auditd tail (no root needed) |
| builtin syslog | `sigmacatch/src/syslog.rs` | `builtin` | Central/authpriv/cron syslog tails (no root needed) |
| sysmon (tail) | `sigmacatch/src/sysmon.rs` | `sysmon` (implies `builtin`) | Legacy Sysmon-for-Linux XML tail |
| sysmon (ebpf) | `sigmacatch/src/ebpf.rs` | `ebpf` | Native eBPF probes (root or CAP_BPF+CAP_PERFMON required) |
| regressiondata-check | `regressiondata-check/src/main.rs` | — | Cross-platform regression validation (EVTX + auditd + JSON); no collector |

### Windows logsource and PowerShell categories

Windows rules are constrained by the `1_win_logsource.yml` pipeline (`add_condition` on
EventIDs + `change_logsource` to the service): the PowerShell categories are bounded to
their EventIDs — `ps_module` (4103), `ps_script` (4104) → `service: powershell`;
`ps_classic_start` (400), `ps_classic_provider_start` (600) and `ps_classic_script` (800) →
`service: powershell-classic`. Without a `category` field injected on the event, rsigma's
`LogSourceExtractor` evaluates every event fail-open against all rules.

Classic PowerShell events (400/600/800 …) emit `<Data>` elements **without** a `Name`
attribute: the parser exposes them under positional keys (`Data0`, `Data1`, …), and
`inject_logsource_fields_for` surfaces the `EventData` content under the generic Sigma
`Data` field so `Data|contains` matching works (rsigma has no dedicated `powershell_classic`
field mapping).

### The Linux collectors

Each guarded by its source; no source available → bail:

- **auditd** — when `/var/log/audit/audit.log` exists: tail, linux-audit-parser parsing,
  grouping by event id `timestamp:sequence`, logsource `product:linux, service:auditd`.
- **builtin syslog** — tails every existing file among central (`/var/log/messages`,
  `/var/log/syslog`), authpriv (`/var/log/secure`, `/var/log/auth.log`) and cron
  (`/var/log/cron`, `/var/log/cron.log`): RFC3164 lines, service derived from the program
  tag (fallback per file group: authpriv → `auth`, cron → `cron`). Lines tagged `sysmon`
  are excluded (handled by the dedicated collector).

The `sysmon` and `ebpf` features add a dedicated collector:

- **Sysmon eBPF (feature `ebpf`)** — embedded Aya probes
  (`crates/sigmacatch-ebpf`, nightly+bpf-linker, excluded from workspace) covering EID 1
  process_create, EID 3 network_connect, EID 5 process_terminate, EID 11 file_create and
  DNS extension (EID 22): events rendered as Sysmon XML identical to the syslog path then
  injected via the same pipeline (`inject_logsource_fields_for`). Runtime requirements:
  root or CAP_BPF+CAP_PERFMON (refuses to start otherwise — `linux.rs` bails) + kernel with
  BTF. SHA256 hashing of images is calculated userspace with cache (path,mtime). A failed
  probe load at runtime warns and continues **without** any sysmon source; only a build with
  both `ebpf` and `sysmon` features falls back to the Sysmon-for-Linux syslog tail.
- **Sysmon-for-Linux tail (feature `sysmon`)** — central syslog
  lines tagged `sysmon` whose body is winevt XML (`parse_winevt_xml`/`_raw`) → logsource
  `product:linux, service:sysmon` via channel `Linux-Sysmon/Operational`. Read-only, no
  Aya dependency.

Regression format: `DataFormat::Log`.

Each input defines its own `CollectorKind`
(`name()`/`mode()`/`channels()`/`build()`/`regression_format()`/`live_capture()`); the Linux
inputs share a single `LinuxCollector` defined in `linux.rs`. The regression format
comes from `regression_format()`: `DataFormat::Evtx` for the winevt/evtx inputs,
`DataFormat::Log` for the Linux inputs. `name()` is `sigmacatch` for every input.

`live_capture()` is an intrinsic property of the collector, not a CLI flag: it defaults to
`true` and is overridden only by the `evtx` input (`false`). Continuous collectors run an
endless loop gated by the stop-file; a one-shot collector lets its `EventProducer::run()`
return, the mpsc sender drops, and `run()` exits when `rx.recv()` returns `None`.

`tail.rs` is the shared tail driver for the Linux file collectors (auditd, builtin syslog,
sysmon): it owns the file handle, the 100 ms poll loop, rotation detection (dev/ino change →
re-open from offset 0) and the channel, and drives a pure `LineHandler` per collector. Each
`LineHandler` turns whole lines into events (`auditd` groups records by event id and flushes
on sequence change or idle poll; `syslog` emits one event per RFC3164 line, excluding `sysmon`
lines; `sysmon` parses XML bodies, skipping truncated ones). Gated on the tailling features.

The `evtx` input (feature `evtx`) is a `CollectorKind` with `live_capture() = false`: it runs
through the same shared `run()` pipeline as the continuous collectors, in one-shot mode —
enumerate `.evtx` files, parse each event (`input-windows-evtx`), feed the `DetectionEngine`,
then reuse the shared `SigmahqRegression` + `SigmaRepo` machinery to write `DataFormat::Evtx`
regression data (always via the pure-Rust EVTX writer, never `EvtExportLog`) and commit/push
it to the fork. Because `EventProducer::run()` returns when all files are exhausted, the
process self-terminates. It has no `channels()`, no interval, and no stop-file poller. Its
`EventRecordID` field is stripped per event (Event 4688 requires absence to trigger the
imaging rule). Because it is pure Rust it also builds and runs on Linux.

## Crate dependency graph

```text
sigmacatch ──┬── sigmacatch-runner      (run<C: CollectorKind>, shared pipeline + tracing init + cli module)
             │   ├── sigmacatch-config      (Config, CliArgs)
             │   ├── sigmacatch-rule        (SigmahqRules: load/filter/remove_id)
             │   ├── sigmacatch-detection   (DetectionEngine: pipelines + bloom + LogSourceExtractor + resolve_channels)
             │   ├── sigmacatch-regression  (SigmahqRegression: skip set + data generation)
             │   ├── sigmacatch-types       (Event, Alert, RegressionHeader, Product, EventProducer, XML parsing)
             │   └── sigmacatch-repo        (SigmaRepo, grit-lib wrapper)
             ├── input-windows-evtx     (parse EVTX → Event; feature `evtx`)
             └── serde (JSON serialization of diagnostic output)

regressiondata-check ──┬── sigmacatch-detection   (DetectionEngine)
                   ├── sigmacatch-rule        (SigmahqRules: load/filter)
                   ├── sigmacatch-regression  (SigmahqRegression)
                   ├── sigmacatch-types       (Event)
                   ├── input-windows-evtx     (parse EVTX → Event)
                   └── linux-audit-parser     (parse auditd records → Event)
```

`input-windows-evtx` depends on `sigmacatch-types` + the `evtx` crate.
`regressiondata-check` (regression validation, cross-platform) assembles `detection` +
`rule` + `regression` + `types` with `input-windows-evtx` (EVTX) and `linux-audit-parser`
(auditd) according to each entry's `LogType`. The diagnostic subcommands (`cli.rs`) parse
arguments manually and use `serde` for their JSON output (always compiled).

## Pipeline (shared runner)

```text
1. parse_args() + Config::load_with_cli("config.yaml", cli)
   └── -n/--dry-run: lightweight load (no git validation), zero on-disk state (no
       config.yaml, no logs/), exits after validating the rules + the engine
2. setup_console() (Windows) ; runner's logging::init(&config, verbose) → tracing (stderr `error` by default, `info` with `-v`, file debug)
3. ensure_dirs() → sigma repo dir + logs/
4. SigmaRepo init: set_info_user/set_info_http|ssh (+ ensure_ssh_host_config when ssh+network),
   set_signing_key (if ssh_key_path), set_git_operations(offline, contrib),
   set_remote_url(fork) → set_working_branch(sigmacatch/<date>) → check_remote_working_branch()
   — fully no-op offline (no `.git` required, local files used as-is)
5. SigmahqRegression::new() → set_author/max_failed_cycles/format(kind)/add_json_output
   └── existing_rules = regression.get_sigma_id() ∪ sigma_repo.pending_regression_rule_ids()
       (remote sigmacatch/* branches pending merge; scan skipped offline) → HashSet<Uuid> (empty with --all-rules)
6. SigmahqRules::new() → load + dedupe; remove_id(existing_rules)
   └── filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size }); 0 rules → bail
7. custom_map = load_custom_channel_mapping("custom_channels.yaml")
8. DetectionEngine::new(&rules)  (pipelines + bloom + LogSourceExtractor)
   └── cycle_channels = kind.channels(&engine, &custom_map)
       ├── Some(empty) (winevt with no resolved channel) → warn + return
       └── None (linux, evtx) → no channel resolution
9. Shutdown handlers (watch channel): Ctrl+C, plus stop-file poller (500 ms) when live_capture()
   ; output_base = <sigma_repo_path>/regression_data ; clean_partial_artifacts()
10. collector = kind.build(&cycle_channels) → tokio::spawn(collector.run(tx, stop))
    ├── sigmacatch --evtx (one-shot) → EvtxCollector.run(tx, stop): enumerate files, send every parsed event,
    │                                  returns when exhausted → sender dropped
    ├── sigmacatch (winevt, Windows)  → EventCollector::new(cycle_channels).run(tx, stop)
    └── sigmacatch (Linux)            → MultiCollector (every compiled, available tail in parallel, rotation detected)
11. Loop: tokio::select!
    ├── shutdown_rx (Ctrl+C, or stop file / --max-runs reached when live_capture()) → break
    ├── event from rx → engine.put_events(vec![event])
    ├── generate_interval (30s, live_capture only) → spawn_blocking(process_and_generate) → upload_regression() if files
    └── [one-shot only] rx.recv() → None (sender dropped, collector finished) → break
12. Final flush: collector stop (10s timeout, abort otherwise) → drain remaining events (5s timeout)
    → process_and_generate() → upload_regression() (per-rule commit) → single push if contrib
    — one-shot propagates the final upload's error (non-zero exit); live mode logs and continues
```

`process_and_generate()`:

```text
engine.process_events() → get_alerts()
    ├── alerts empty → return (no "evaluation complete" log)
    ├── regression.begin_cycle() ; log stats (events_processed, matches_found, alerts_count)
    └── per alert: regression.add(&alert) → Option<Vec<String>>
         ├── None if rule already retired / no valid id / info.yml exists
         └── Some(files) → write files + regression_tests_path + retire rule
    └── retired_ids += regression.take_blocked() (rules blocked after N failing cycles)
    └── retired rules → rules.remove_id() → engine.reload_rules() (single batch reload)
    ↓
returns (restored Pipeline, batches: Vec<(Uuid, Vec<String>)>)
    ↓
upload_regression() → upload_rule_batches()   # in sigmacatch-repo
     ├── one commit per rule: "🧪 test: add regression data for rule {rule_id}"
     ├── commit/push failure → rollback local branch to pre-batch tip
     └── SINGLE push if git.contrib: true (otherwise local commits only)
```

All generation runs in `spawn_blocking` (the `Pipeline` state is moved out and returned) —
`EvtExportLog` retries never freeze collection (events keep buffering in the mpsc channel).

### One-shot variant: `--evtx`

Everything above describes the shared `run()` pipeline. The `evtx` input
(`live_capture() = false`) is the one-shot analogue: its `EventCollector` is preloaded with
the enumerated `.evtx` files and `EventProducer::run()` emits every parsed event then returns
— the mpsc sender drops, `rx.recv()` yields `None`, and the shared loop breaks. There is no
`channels()`, no `generate_interval`, no stop-file poller, and `--max-runs` is ignored
(`-r 0` semantics). Ctrl+C still aborts the pass (the runner always registers it); any
in-flight cycle is dropped and the push of what was not yet committed is skipped.

## Design notes

- **Stop file**: `config.stop_file` (default `.sigmacatch.stop`) is polled every 500 ms;
  when the file exists, collection stops gracefully (drain + flush + commit of the
  in-flight cycle) — the signal used to end a continuous (`-r 0`) run without a hard
  kill that would lose the cycle's regression data.
- **Skip set** = `HashSet<Uuid>` from `SigmahqRegression::get_sigma_id()` (existing info.yml + valid data)
  ∪ `SigmaRepo::pending_regression_rule_ids()` (trees of remote `sigmacatch/*` branches:
  unmerged pending PRs — a fresh VM does not re-capture their data), built once at startup.
  `--all-rules` disables it. After generation a rule is retired and the engine is reloaded in
  one batch (`engine.reload_rules`). Rules whose committed data is invalid (broken EVTX / empty text)
  are excluded from the skip set → regenerated.
- **Output always in the sigma repo**: `<sigma_repo_path>/regression_data/<rule_rel_path>/`
  (`info.yml` + data file `.evtx`/`.log`, optional `.json`), committed to the fork if
  `contrib` (local commits otherwise). The rule's repo path is mirrored relative to the
  configured `sigma_repo_path` (absolute or relative) — the per-rule commit also carries the
  rule yaml updated with `regression_tests_path: regression_data/<rule_rel_path>/info.yml`.
- **Collector observability**: the collector excludes non-existent channels once on
  `ERROR_EVT_CHANNEL_NOT_FOUND` (single `error!`); each live channel logs "initial query OK"
  then a "still alive" heartbeat (60s); `warn!` when events are fetched but dropped at
  render/parse. The Linux collectors detect tail-file rotation (inode change) and re-open
  the file; the builtin syslog collector excludes lines tagged `sysmon` to avoid double
  capture (handled by the dedicated Sysmon-for-Linux collector).