# Architecture

## Cargo workspace

The project is a cargo workspace of 14 packages, plus 1 excluded nightly crate (`sigmacatch-ebpf`):

```text
sigmacatch/
├── Cargo.toml                    # Workspace root
├── sigmacatch-win/               # Windows binaries (lib + 2 bins)
│   └── src/
│       ├── lib.rs                # pub use sigmacatch-runner + channels/etw modules
│       ├── main_winevt.rs        # bin `sigmacatch-channel`: multi-channel Winevt collector
│       ├── main_etw.rs           # bin `sigmacatch-etw`: direct ETW collector (ferrisetw)
│       ├── channels.rs           # Winevt collector (EvtQueryW/EvtNext/EvtRender, multi-channel)
│       ├── etw/                  # Direct ETW collector: providers.rs (18 providers), field_maps,
│       │                         #   enrich, mapper, process_table, process_query, sysmon, paths, pe, filekey
│       └── cli.rs                # Diagnostic subcommands: check-filter, list-rules
├── sigmacatch-lnx/               # Linux binaries (lib + 3 bins, feature-gated)
│   └── src/
│       ├── lib.rs                # Module gates: auditd, builtin (syslog), sysmon (tail), ebpf
│       ├── entry.rs              # Shared Linux pipeline `LinuxCollector` + `run()`
│       ├── main_base.rs          # bin `sigmacatch-linux` (thin wrapper over entry::run)
│       ├── main_sysmon.rs        # bin `sigmacatch-linux-sysmon` (thin wrapper, + sysmon tail)
│       ├── main_ebpf.rs          # bin `sigmacatch-linux-ebpf` (thin wrapper, + native eBPF)
│       ├── auditd.rs             # Auditd collector (tail /var/log/audit/audit.log, event id grouping)
│       ├── syslog.rs             # Builtin syslog collector (central /var/log/messages → /var/log/syslog + authpriv + cron files, RFC3164)
│       ├── sysmon.rs             # Sysmon-for-Linux collector (`sysmon`-tagged syslog lines, feature `sysmon`)
│       ├── sysmon_parse.rs       # Sysmon XML parsing (always compiled, shared by tail + eBPF)
│       ├── ebpf.rs               # eBPF loader + dispatch (feature `ebpf`, privileges required)
│       ├── ebpf_event.rs         # eBPF → Sysmon XML synthesis + tests
│       └── cli.rs                # Diagnostic subcommands: check-filter, list-rules
├── sigmacatch-check/             # Standalone cross-platform binary: regression check (--json, --ignore, --fix, --path)
└── crates/
    ├── sigmacatch-ebpf/          # eBPF probes (excluded workspace, nightly, bpfel-unknown-none)
    │   └── src/main.rs           # 6 tracepoints: execve/exec/exit/connect/openat+exit/sendto+sendmsg
    ├── sigmacatch-ebpf-common/   # Shared no_std types for eBPF ring buffer (ExecEvent, NetEvent, ...)
    ├── sigmacatch-runner/        # Pipeline shared by both binary crates:
    │   └── src/runner.rs         #   run<C: CollectorKind> + CollectorKind trait (config + repo init +
    │                             #   event loop + process_and_generate + commit/push)
    ├── sigmacatch-config/        # Config YAML + CLI parsing + custom_channels.yaml
    ├── sigmacatch-logger/        # Two-layer tracing subscriber (stderr `error` by default / `info` with `-v`, daily rolling file debug)
    ├── sigmacatch-rule/          # SigmahqRules: rule loading (parse_sigma_yaml), filter, dedupe, remove_id
    │                             #   + attack.rs (SigmaRuleExt ATT&CK) + discover.rs + thresholds.rs (LoadStats)
    ├── sigmacatch-detection/     # DetectionEngine wrapper + embedded per-platform pipelines
    │                             #   (1_win_logsource.yml, 2_win_field_name.yml, 3_lnx_logsource.yml,
    │                             #   4_lnx_field_name.yml — transformations gated by product rule_conditions) + channel_resolver
    ├── sigmacatch-regression/    # SigmahqRegression (get_sigma_id, add, retire), InfoYml, DataFormat
    │                             #   (evtx.rs, format.rs, info.rs, logtype.rs, long_path.rs)
    ├── sigmacatch-types/         # Shared types: Event, Alert, RegressionHeader + XML parsing + logsource mapping tables
    ├── sigmacatch-repo/          # grit-lib wrapper + SigmaRepo + git operations + signing.rs + transport.rs
    ├── sigmacatch-evtx-writer/   # Pure Rust EVTX writer (ETW / record-id-less events — no EvtExportLog possible)
    └── input-windows-evtx/       # EVTX file parser → Event
```

## Collectors

Six binaries are produced: five collector binaries from two crates (`sigmacatch-win` → 2,
`sigmacatch-lnx` → 3), each embedding a selected set of collectors (cargo features `winevt`/`etw`
and `auditd`/`builtin`/`sysmon`/`ebpf`, `required-features` per binary), plus the standalone
cross-platform `sigmacatch-check`:

| Binary | Crate | Description |
|---|---|---|
| `sigmacatch-channel` | `sigmacatch-win/src/channels.rs` | Native Winevt API (`EvtQueryW`/`EvtNext`/`EvtRender`), multi-channel, replayable |
| `sigmacatch-etw` | `sigmacatch-win/src/etw/` | Direct ETW collection via ferrisetw (details below) |
| `sigmacatch-linux` | `sigmacatch-lnx/src/{auditd,syslog}.rs` | auditd + builtin syslog only (no root needed) |
| `sigmacatch-linux-sysmon` | `sigmacatch-lnx/src/{auditd,syslog,sysmon}.rs` | + legacy Sysmon-for-Linux XML tail |
| `sigmacatch-linux-ebpf` | `sigmacatch-lnx/src/{auditd,syslog,ebpf}.rs` | + native eBPF probes (root or CAP_BPF+CAP_PERFMON required) |
| `sigmacatch-check` | `sigmacatch-check/src/main.rs` | Cross-platform regression validation (EVTX + auditd + JSON); no collector |

### Direct ETW

The ETW collector covers the same channels as the Winevt collector (Security, Defender,
Firewall, Sysmon, …): 18 providers (9 Sysmon-masquerade + 9 generic), provider→channel
resolution from a mapping table, real EventID preserved [beta]. For generic providers,
`EventData` fields are provided by per-provider field maps (variable fidelity). On
non-Windows the Winevt/ETW collectors are no-op stubs.

**Two-step logsource resolution (provider → channel → service)**:
`inject_logsource_fields_for` first looks up the service by channel (`CHANNEL_TO_SERVICE`);
when missing, it resolves the provider through `ETW_PROVIDER_TO_CHANNEL` (single source of
truth in `sigmacatch-types`) and falls back onto `CHANNEL_TO_SERVICE`. Sysmon-masquerade
providers with no real Winevt channel are routed to synthetic `sigmacatch/etw-*` channels
(produced by `mapper::unmapped_channel_for_masquerade`) that resolve to the `etw` service:
the event keeps a real logsource instead of being evaluated fail-open against every rule.

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

### The three Linux collectors

Each guarded by its source; no source available → bail:

- **auditd** — when `/var/log/audit/audit.log` exists: tail, linux-audit-parser parsing,
  grouping by event id `timestamp:sequence`, logsource `product:linux, service:auditd`.
- **builtin syslog** — tails every existing file among central (`/var/log/messages`,
  `/var/log/syslog`), authpriv (`/var/log/secure`, `/var/log/auth.log`) and cron
  (`/var/log/cron`, `/var/log/cron.log`): RFC3164 lines, service derived from the program
  tag (fallback per file group: authpriv → `auth`, cron → `cron`). Lines tagged `sysmon`
  are excluded (handled by the dedicated collector).

The two sysmon binaries add an additional collector:

- **Sysmon eBPF (feature `ebpf`, `sigmacatch-linux-ebpf`)** — embedded Aya probes
  (`crates/sigmacatch-ebpf`, nightly+bpf-linker, excluded from workspace) covering EID 1
  process_create, EID 3 network_connect, EID 5 process_terminate, EID 11 file_create and
  DNS extension (EID 22): events rendered as Sysmon XML identical to the syslog path then
  injected via the same pipeline (`inject_logsource_fields_for`). Runtime requirements:
  root or CAP_BPF+CAP_PERFMON (refuses to start otherwise — `entry.rs` bails) + kernel with
  BTF. SHA256 hashing of images is calculated userspace with cache (path,mtime). A failed
  probe load at runtime warns and continues **without** any sysmon source in the `-ebpf`
  flavour; only an all-features build (`ebpf` + `sysmon`) falls back to the Sysmon-for-Linux
  syslog tail.
- **Sysmon-for-Linux tail (feature `sysmon`, `sigmacatch-linux-sysmon`)** — central syslog
  lines tagged `sysmon` whose body is winevt XML (`parse_winevt_xml`/`_raw`) → logsource
  `product:linux, service:sysmon` via channel `Linux-Sysmon/Operational`. Read-only, no
  Aya dependency.

Regression format: `DataFormat::Log`.

Each Windows binary defines its own `CollectorKind` in its `main_*.rs`
(`name()`/`mode()`/`channels()`/`build()`/`regression_format()`); the three Linux binaries
share a single `LinuxCollector` defined in `entry.rs`. The regression format comes from
`regression_format()`: `DataFormat::Evtx` for both Windows binaries, `DataFormat::Log` for
all three Linux binaries.

## Crate dependency graph

```text
sigmacatch-win ──┬── sigmacatch-runner      (run<C: CollectorKind>, shared pipeline)
sigmacatch-lnx ──┤   ├── sigmacatch-config      (Config, CliArgs)
                 │   ├── sigmacatch-logger      (tracing init)
                 │   ├── sigmacatch-rule        (SigmahqRules: load/filter/remove_id)
                 │   ├── sigmacatch-detection   (DetectionEngine: pipelines + bloom + LogSourceExtractor + resolve_channels)
                 │   ├── sigmacatch-regression  (SigmahqRegression: skip set + data generation)
                 │   ├── sigmacatch-types       (Event, Alert, RegressionHeader, Product, EventProducer, XML parsing)
                 │   └── sigmacatch-repo        (SigmaRepo, grit-lib wrapper)
                 └── serde (JSON serialization of diagnostic output)

sigmacatch-check ──┬── sigmacatch-detection   (DetectionEngine)
                   ├── sigmacatch-rule        (SigmahqRules: load/filter)
                   ├── sigmacatch-regression  (SigmahqRegression)
                   ├── sigmacatch-types       (Event)
                   ├── input-windows-evtx     (parse EVTX → Event)
                   └── linux-audit-parser     (parse auditd records → Event)
```

`sigmacatch-detection` depends on `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`.
The collectors live inside their binary crates and depend only on `sigmacatch-types`
(shared types + logsource mapping tables). `input-windows-evtx` depends on
`sigmacatch-types` + the `evtx` crate. `sigmacatch-check` (regression validation,
cross-platform) assembles `detection` + `rule` + `regression` + `types` with
`input-windows-evtx` (EVTX) and `linux-audit-parser` (auditd) according to each entry's
`LogType`. The diagnostic subcommands (`cli.rs`) parse arguments manually and use `serde`
for their JSON output (always compiled).

## Pipeline (continuous loop)

```text
1. parse_args() + Config::load_with_cli("config.yaml", cli)
2. setup_console() (Windows) ; init_logger(&config, verbose) → tracing (stderr `error` by default, `info` with `-v`, file debug)
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
       └── None (etw, linux) → no channel resolution
9. Ctrl+C handler (watch channel) ; output_base = <sigma_repo_path>/regression_data ;
   clean_partial_artifacts()
10. collector = kind.build(&cycle_channels) → tokio::spawn(collector.run(tx, stop))
    ├── sigmacatch-channel (winevt)  → EventCollector::new(cycle_channels).run(tx, stop)
    ├── sigmacatch-etw (etw) → EventCollector::new().run(tx, stop) (provider→channel routing internal)
    └── sigmacatch-linux (auditd + syslog + sysmon) → MultiCollector (all tails in parallel, rotation detected)
11. Loop: tokio::select!
    ├── shutdown_rx (Ctrl+C or --max-runs reached) → break
    ├── event from rx → engine.put_events(vec![event])
    └── generate_interval (30s) → spawn_blocking(process_and_generate) → upload_regression() if files
12. Final flush: collector stop (10s timeout, abort otherwise) → drain remaining events (5s timeout)
    → process_and_generate() → upload_regression() (per-rule commit) → single push if contrib
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

## Design notes

- **Skip set** = `HashSet<Uuid>` from `SigmahqRegression::get_sigma_id()` (existing info.yml + valid data)
  ∪ `SigmaRepo::pending_regression_rule_ids()` (trees of remote `sigmacatch/*` branches:
  unmerged pending PRs — a fresh VM does not re-capture their data), built once at startup.
  `--all-rules` disables it. After generation a rule is retired and the engine is reloaded in
  one batch (`engine.reload_rules`). Rules whose committed data is invalid (broken EVTX / empty text)
  are excluded from the skip set → regenerated.
- **Output always in the sigma repo**: `<sigma_repo_path>/regression_data/<rule_rel_path>/`
  (`info.yml` + data file `.evtx`/`.log`, optional `.json`), committed to the fork if
  `contrib` (local commits otherwise). Caution: the generation path is hardwired to the
  local `./sigma` checkout — keep `git.sigma_repo_path: "sigma"`; any other value breaks
  the path mirroring and partial-artifact cleanup.
- **Collector observability**: the collector excludes non-existent channels once on
  `ERROR_EVT_CHANNEL_NOT_FOUND` (single `error!`); each live channel logs "initial query OK"
  then a "still alive" heartbeat (60s); `warn!` when events are fetched but dropped at
  render/parse. The Linux collectors detect tail-file rotation (inode change) and re-open
  the file; the builtin syslog collector excludes lines tagged `sysmon` to avoid double
  capture (handled by the dedicated Sysmon-for-Linux collector).
