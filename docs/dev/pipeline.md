# Pipeline

The shared `run<C: CollectorKind>()` runner in `runner.rs` drives every
collector — continuous and one-shot alike. Collectors push events into an
mpsc channel; the runner runs the detection engine and the regression
generation off it.

## Pipeline (shared runner)

```text
1. parse_args() + Config::load_with_cli("config.yaml", cli)
   └── -n/--dry-run: lightweight load (no git validation), zero on-disk state (no
       config.yaml, no logs/), exits after validating the rules + the engine
2. setup_console() (Windows) ; runner's logging::init(&config, verbose) → tracing (stderr `error` by default, `info` with `-v`, file debug)
3. ensure_dirs() → sigma repo dir + logs/
4. SigmaRepo init: set_info_user/set_info_http|ssh (+ ensure_ssh_host_config when ssh+network),
   set_signing_key (if ssh_key_path), set_git_operations(offline, contrib),
   set_remote_url(fork) → set_working_branch(<branch>) → check_remote_working_branch()
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
upload_regression() → upload_rule_batches()   # in sigmacatch::repo
     ├── one commit per rule: "🧪 test: add regression data for rule {rule_id}"
     ├── commit/push failure → rollback local branch to pre-batch tip
     └── SINGLE push if git.contrib: true (otherwise local commits only)
```

All generation runs in `spawn_blocking` (the `Pipeline` state is moved out and returned) —
`EvtExportLog` retries never freeze collection (events keep buffering in the mpsc channel).

## One-shot variant: `--evtx`

The `evtx` input (`live_capture() = false`) reuses the shared `run()`
pipeline in one-shot mode: the enumeration of `.evtx` files exhausts
itself (mpsc sender dropped → `rx.recv()` yields `None`), with no
`channels()`, no `generate_interval`, no stop-file poller, and
`--max-runs` ignored. Ctrl+C still aborts the pass: any in-flight cycle is
dropped and the push of what was not yet committed is skipped. The
complete user-facing documentation (usage, flags, semantics) lives in
[cli.md](../user/cli.md#-evtx-one-shot-evtx-input-single-run).
