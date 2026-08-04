# Architecture

## Cargo workspace

The project is a cargo workspace of 11 packages (2 binary crates + 9 libraries):

```
sigmacatch/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── sigmacatch-config/        # Config YAML + CLI parsing + custom_channels.yaml + dry-run git diagnostics
│   ├── sigmacatch-logger/        # Two-layer tracing subscriber (stderr info + daily rolling file debug)
│   ├── sigmacatch-rule/          # SigmahqRules: rule loading (parse_sigma_yaml), filter, dedupe, channels()
│   ├── sigmacatch-detection/     # DetectionEngine wrapper + embedded pipelines (windows.yml, flatten_winevt.yml)
│   ├── input-windows-channels/   # Multi-channel Winevt collector (cfg(windows))
│   ├── sigmacatch-regression/    # SigmahqRegression (get_sigma_id, add, retire), InfoYml, triplet
│   ├── sigmacatch-types/         # Shared types: Event, Alert, RegressionHeader + XML parsing + logsource mapping tables
│   ├── sigmacatch-repo/          # grit-lib wrapper + SigmaRepo + git operations
│   └── input-evtx/               # EVTX file parser → Event
├── sigmacatch/                   # Binary + orchestration
│   └── src/
│       └── main.rs               # Config + repo init + continuous event loop + process_and_generate + commit/push
└── localcheck/                   # Dev tools (kept out of the main crate)
    └── src/
        ├── check_filter.rs       # Validates SigmaFilterConfig against real Sigma rules (ground-truth counts)
        └── check_evtx.rs         # Batch validation of Sigma engine against .evtx regression data
```

## Source tree

```
sigmacatch/src/
└── main.rs              # Binary: orchestration, continuous loop, process_and_generate

localcheck/src/
├── check_filter.rs      # Filter validation tool (no CLI args, loads ./sigma itself)
└── check_evtx.rs        # Batch regression validation tool (exit 1 on empty input / no matches)
```

There is no `config.rs` / `logger.rs` / `repo.rs` in the binary — those moved to the
`sigmacatch-config`, `sigmacatch-logger`, and `sigmacatch-repo` crates.

## Crate dependency graph

```
sigmacatch ──┬── sigmacatch-config       (Config, CliArgs, dry-run diagnostics)
             ├── sigmacatch-logger       (tracing init)
             ├── sigmacatch-rule         (SigmahqRules: load/filter/remove_id/channels)
             ├── sigmacatch-detection    (DetectionEngine: pipelines + bloom + LogSourceExtractor)
             ├── input-windows-channels  (EventCollector: multi-channel Winevt)
             ├── sigmacatch-regression   (SigmahqRegression: skip set + triplet generation)
             ├── sigmacatch-types        (Event, Alert, RegressionHeader, Product, EventProducer, XML parsing)
             └── sigmacatch-repo         (SigmaRepo, grit-lib wrapper)

localcheck ──┬── sigmacatch-rule         (SigmahqRules + SigmaFilterConfig)
             ├── sigmacatch-detection    (DetectionEngine)
             ├── sigmacatch-regression   (SigmahqRegression)
             └── input-evtx              (parse_evtx_bytes)
```

`sigmacatch-detection` depends on `sigmacatch-rule` + `sigmacatch-types` + `rsigma-eval`.
`input-windows-channels` depends on `sigmacatch-types` for shared types and the logsource
mapping tables. `sigmacatch-regression` depends on `sigmacatch-types`. `sigmacatch-rule`
depends on `rsigma-parser`. `sigmacatch-config` depends on `sigmacatch-repo` + `sigmacatch-rule`.

## Pipeline (continuous loop)

```
1. parse_args() + Config::load_with_cli("config.yaml", cli)
   └── --dry-run → dry_run_git() (git diagnostics) + exit
2. init_logger() → tracing (stderr info + file debug)
3. ensure_dirs() → sigma repo dir + logs/
4. SigmaRepo init (remote_url = fork, working branch, token) → init() [clone/fetch]
   └── set_working_branch() → check_remote_working_branch() (guard on same-day branch)
5. SigmahqRegression::new() → loads existing info.yml from ./sigma/regression_data
   └── existing_rules = regression.get_sigma_id() → HashSet<Uuid> (empty with --all-rules)
6. SigmahqRules::new() → load + dedupe; remove_id() per skipped rule
    └── filter(SigmaFilterConfig { product, min_status, min_level, author, max_rule_size }); 0 rules → bail
    └── --list-rules → print rules without regression data + exit
7. custom_map = load_custom_channel_mapping("custom_channels.yaml")
   └── cycle_channels = rules.channels(&custom_map); 0 channels → warn + return
8. DetectionEngine::new(&rules)  (pipelines + bloom + LogSourceExtractor)
   └── --channels-only → print channels + exit
9. output_base = <sigma_repo_path>/regression_data; clean_partial_artifacts()
10. EventCollector::new(cycle_channels).run(tx, stop) → tokio task
11. Loop: tokio::select!
    ├── shutdown_rx (Ctrl+C) → break
    ├── event from rx → engine.put_events(vec![event])
    └── generate_interval (30s) → process_and_generate() → upload_regression() if files
12. Final flush: drain remaining events → process_and_generate() → commit → push() fork
```

`process_and_generate()`:

```
engine.process_events() → get_alerts()
    ├── alerts empty → return (no "evaluation complete" log)
    ├── log stats (events_processed, matches_found, alerts_count)
    └── per alert: regression.add(&alert) → Option<Vec<String>>
         ├── None if rule already retired / no valid id / info.yml exists
         └── Some(files) → write triplet + regression_tests_path + retire rule
    └── retired rules → rules.remove_id() → engine.reload_rules() (single batch reload)
```

## Design notes

- **Skip set** = `HashSet<Uuid>` from `SigmahqRegression::get_sigma_id()` (existing info.yml),
  built once at startup. `--all-rules` disables it. After generation a rule is retired and
  the engine is reloaded in one batch (`engine.reload_rules`).
- **Output always in the sigma repo**: `<sigma_repo_path>/regression_data/<rule_rel_path>/`
  (triplet `info.yml` + `<rule_id>.json` + `<rule_id>.evtx`), committed to the fork.
- **Collector observability**: non-existent channels are excluded once on
  `ERROR_EVT_CHANNEL_NOT_FOUND` (single `error!`); live channels log "initial query OK" and
  a "still alive" heartbeat (60s); `warn!` when events are fetched but dropped at render/parse.

> Skip set details and key design decisions are in [`architecture-reference.md`](architecture-reference.md).
