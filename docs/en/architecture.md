# Architecture

## Cargo workspace

The project is a cargo workspace of 14 packages (3 binary crates + 11 libraries):

```text
sigmacatch/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── sigmacatch-config/        # Config YAML + CLI parsing + custom_channels.yaml + dry-run git diagnostics
│   ├── sigmacatch-logger/        # Two-layer tracing subscriber (stderr info + daily rolling file debug)
│   ├── sigmacatch-rule/          # SigmahqRules: rule loading (parse_sigma_yaml), filter, dedupe, remove_id + SigmaRuleExt (ATT&CK techniques)
│   ├── sigmacatch-detection/     # DetectionEngine wrapper + embedded pipelines (windows.yml, flatten_winevt.yml) + channel_resolver
│   ├── input-windows-channels/   # Multi-channel Winevt collector (cfg(windows))
│   ├── input-windows-etw/        # Direct ETW collector via ferrisetw (18 providers, generic provider→channel routing)
│   ├── input-linux-auditd/       # Auditd collector (tail /var/log/audit/audit.log, event id grouping)
│   ├── sigmacatch-regression/    # SigmahqRegression (get_sigma_id, add, retire), InfoYml, triplet
│   ├── sigmacatch-types/         # Shared types: Event, Alert, RegressionHeader + XML parsing + logsource mapping tables
│   ├── sigmacatch-repo/          # grit-lib wrapper + SigmaRepo + git operations
│   ├── sigmacatch-evtx-writer/   # Pure Rust EVTX writer (no winevt API) + re-parse validation
│   └── input-evtx/               # EVTX file parser → Event
├── sigmacatch/                   # Lib + 3 binaries (continuous loop)
│   └── src/
│       ├── lib.rs                # shared runner (pipeline common to all binaries)
│       ├── runner.rs             # Config + repo init + continuous event loop + process_and_generate + commit/push
│       ├── main_winevt.rs        # bin `sigmacatch-channel`: multi-channel Winevt collector
│       ├── main_etw.rs           # bin `sigmacatch-etw`: direct ETW collector (ferrisetw)
│       └── main_auditd.rs        # bin `sigmacatch-auditd`: auditd tail collector
└── tools/                   # Dev tools (kept out of the main crate)
    └── src/
        ├── check_dry_run.rs      # Git diagnostics (token/fork/API/info-refs/repo state)
        ├── check_channels.rs     # Resolves and lists the collected Windows channels
        ├── list_rules.rs         # Lists loaded rules (techniques, ART link)
        ├── check_filter.rs       # Validates SigmaFilterConfig against real Sigma rules (ground-truth counts)
        ├── check_evtx.rs         # Batch validation of Sigma engine against .evtx regression data
        ├── check_auditd.rs       # Batch validation of Sigma engine against auditd regression data
        ├── get_atomic.rs         # Generates run_atomic.ps (Invoke-AtomicTest) for rules without regression data
        └── coverage.rs           # Rule coverage stats (local + pending branches)
```

## Source tree

```text
sigmacatch/src/
├── lib.rs                # shared runner (pipeline common to all binaries)
├── runner.rs             # run<C: CollectorKind>: config, repo init, event loop, commit/push
├── main_winevt.rs        # bin `sigmacatch-channel`: multi-channel Winevt collector
├── main_etw.rs           # bin `sigmacatch-etw`: direct ETW collector (ferrisetw)
└── main_auditd.rs        # bin `sigmacatch-auditd`: auditd tail collector

tools/src/
├── check_dry_run.rs      # Git diagnostics tool (config.yaml + dry_run_git)
├── check_channels.rs     # Channel resolution tool (config.yaml filter)
├── list_rules.rs         # Rule listing tool (config.yaml filter)
├── check_filter.rs       # Filter validation tool (no CLI args, loads ./sigma itself)
├── check_evtx.rs         # Batch regression validation tool (exit 1 on empty input / no matches)
├── check_auditd.rs       # Batch auditd regression validation tool (exit 1 on empty input / no matches)
├── get_atomic.rs         # run_atomic.ps generation tool (rules without regression data)
└── coverage.rs           # Rule coverage stats tool (local + pending remote branches)
```

## Collectors

Three binaries are produced, each embedding a single collector (cargo features `winevt`/`etw`/`auditd`, `required-features` per binary):

| Binary | Crate | Description |
|---|---|---|
| `sigmacatch-channel` | `input-windows-channels` | Native Winevt API (`EvtQueryW`/`EvtNext`/`EvtRender`), multi-channel, replayable |
| `sigmacatch-etw` | `input-windows-etw` | Direct ETW collection via ferrisetw, 18 providers (9 Sysmon-masquerade + 9 generic), generic provider→channel routing, real EventID preserved |
| `sigmacatch-auditd` | `input-linux-auditd` | Tail of `/var/log/audit/audit.log`, linux-audit-parser parsing, event id grouping (`timestamp:sequence`), logsource `product:linux, service:auditd, provider:auditd` |

The ETW collector covers the same channels as the Winevt collector (Security, Defender, Firewall, Sysmon, …) by resolving provider→channel from a mapping table and keeping the real EventID. For generic providers, `EventData` fields are provided by per-provider field maps (variable fidelity). On non-Windows the ETW collector is a no-op stub with a `warn!`.

There is no `config.rs` / `logger.rs` / `repo.rs` in the binary — those moved to the
`sigmacatch-config`, `sigmacatch-logger`, and `sigmacatch-repo` crates.

## Crate dependency graph

```text
sigmacatch ──┬── sigmacatch-config       (Config, CliArgs, dry-run diagnostics)
              ├── sigmacatch-logger       (tracing init)
              ├── sigmacatch-rule         (SigmahqRules: load/filter/remove_id)
              ├── sigmacatch-detection    (DetectionEngine: pipelines + bloom + LogSourceExtractor + resolve_channels)
              ├── input-windows-channels  (feature winevt, bin `sigmacatch-channel`)
              ├── input-windows-etw       (feature etw, bin `sigmacatch-etw`)
              ├── input-linux-auditd      (feature auditd, bin `sigmacatch-auditd`)
              ├── sigmacatch-regression   (SigmahqRegression: skip set + triplet generation)
              ├── sigmacatch-evtx-writer  (pure Rust EVTX writer + validation)
              ├── sigmacatch-types        (Event, Alert, RegressionHeader, Product, EventProducer, XML parsing)
              └── sigmacatch-repo         (SigmaRepo, grit-lib wrapper)

tools ──┬── sigmacatch-rule         (SigmahqRules + SigmaFilterConfig)
              ├── sigmacatch-detection    (DetectionEngine)
              ├── sigmacatch-regression   (SigmahqRegression)
              ├── input-linux-auditd      (record_to_event, parse_line)
              └── input-evtx              (parse_evtx_bytes)
```

`sigmacatch-detection` depends on `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`.
`input-windows-channels` depends on `sigmacatch-types` for shared types and the logsource
mapping tables. `sigmacatch-regression` depends on `sigmacatch-types`. `sigmacatch-rule`
depends on `rsigma-parser`. `sigmacatch-config` depends on `sigmacatch-repo` + `sigmacatch-rule`.

## Pipeline (continuous loop)

```text
1. parse_args() + Config::load_with_cli("config.yaml", cli)
2. init_logger(verbose) → tracing (stderr `error` by default, `info` with `-v`, file debug)
3. ensure_dirs() → sigma repo dir + logs/
4. SigmaRepo init (remote_url = fork, working branch, token) → init() [clone/fetch] — no-op offline (no `.git` required)
   └── set_git_operations(offline, contrib) → set_working_branch() → check_remote_working_branch() (guard on same-day branch); offline → contrib forced false, all ops no-op
5. SigmahqRegression::new() → loads existing info.yml from ./sigma/regression_data
   └── existing_rules = regression.get_sigma_id() → HashSet<Uuid> (empty with --all-rules)
6. SigmahqRules::new() → load + dedupe; remove_id() per skipped rule
    └── filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size }); 0 rules → bail
7. custom_map = load_custom_channel_mapping("custom_channels.yaml")
8. DetectionEngine::new(&rules)  (pipelines + bloom + LogSourceExtractor)
   └── cycle_channels = engine.resolve_channels(&custom_map); 0 channels → warn + return
9. output_base = <sigma_repo_path>/regression_data; clean_partial_artifacts()
10. runner::run(kind) — the collector is injected by each binary via the `CollectorKind` trait:
    ├── sigmacatch-channel (winevt)  → EventCollector::new(cycle_channels).run(tx, stop)
    ├── sigmacatch-etw (etw) → EventCollector::new().run(tx, stop) (no channels, provider→channel routing internal)
    └── sigmacatch-auditd (auditd) → EventCollector::new().run(tx, stop) (tail audit.log, no channels)
11. Loop: tokio::select!
    ├── shutdown_rx (Ctrl+C) → break
    ├── event from rx → engine.put_events(vec![event])
    └── generate_interval (30s) → process_and_generate() → upload_regression() if files
12. Final flush: drain remaining events → process_and_generate() → upload_regression() (per-rule commit) → single push if contrib
```

`process_and_generate()`:

```text
engine.process_events() → get_alerts()
    ├── alerts empty → return (no "evaluation complete" log)
    ├── log stats (events_processed, matches_found, alerts_count)
    └── per alert: regression.add(&alert) → Option<Vec<String>>
         ├── None if rule already retired / no valid id / info.yml exists
         └── Some(files) → write triplet + regression_tests_path + retire rule
    └── retired rules → rules.remove_id() → engine.reload_rules() (single batch reload)
    ↓
returns batches: Vec<(Uuid, Vec<String>)>   # (rule_id, written files) — empty if no alerts
    ↓
upload_regression() → upload_rule_batches()   # in sigmacatch-repo
     ├── one commit per rule: "🧪 test: add regression data for rule {rule_id}"
    ├── commit/push failure → rollback local branch to pre-batch tip
    └── SINGLE push if git.contrib: true (otherwise local commits only)
```

## Design notes

- **Skip set** = `HashSet<Uuid>` from `SigmahqRegression::get_sigma_id()` (existing info.yml + valid data),
  built once at startup. `--all-rules` disables it. After generation a rule is retired and
  the engine is reloaded in one batch (`engine.reload_rules`). Rules whose committed data is
  invalid (empty EVTX) are excluded from the skip set → regenerated.
- **Output always in the sigma repo**: `<sigma_repo_path>/regression_data/<rule_rel_path>/`
  (triplet `info.yml` + `<rule_id>.json` + `<rule_id>.evtx`), committed to the fork if
  `contrib` (local commits otherwise).
- **Collector observability**: non-existent channels are excluded once on
  `ERROR_EVT_CHANNEL_NOT_FOUND` (single `error!`); live channels log "initial query OK" and
  a "still alive" heartbeat (60s); `warn!` when events are fetched but dropped at render/parse.

> Skip set details and key design decisions are in [`architecture-reference.md`](architecture-reference.md).
