# Architecture

## Cargo workspace

The project is a cargo workspace of 7 crates:

```
sigmacatch/
├── Cargo.toml           # Workspace root
├── crates/
│   ├── detection-engine/      # Thin wrapper around rsigma-eval for pipelines and rules
│   ├── input-evtx/            # Parse EVTX files into Event objects
│   ├── input-windows-channels/ # Winevt collector (EventProducer) + taxonomy via sigmacatch-types
│   ├── sigma-regression/      # InfoYml, SkipSet, triplet validation (SigmaHQ regression format)
│   └── sigmacatch-types/      # Shared types: Event, Alert, RegressionHeader + XML parsing
└── sigmacatch/          # Binary + pipeline
    └── src/
        ├── main.rs
        ├── bin/evtx_check.rs
        └── ...
```

## Source tree (`sigmacatch/src/`)

```
sigmacatch/src/
├── main.rs              # Binary + pipeline (run_pipeline, Stats, AggregatedRule)
├── lib.rs               # pub mod declarations
├── config.rs            # YAML config (Config, SigmaFilterConfig, MinStatus, MinLevel)
├── logger.rs            # Two-layer tracing subscriber (stderr info + daily rolling file debug)
├── repo.rs              # grit-lib wrapper + SigmaRepo (clone/fetch/push/commit/branch)
├── github/
│   ├── mod.rs           # pub mod commit, fork
│   ├── commit.rs        # Commit workflow with author/email validation
│   └── fork.rs          # Fork detection via GitHub API
└── bin/
    └── evtx_check.rs    # Batch validation tool
```

## Crate dependency graph

```
sigmacatch ──┬── detection-engine        (rsigma-eval wrapper + pipelines + bloom/logsource optimizations)
             ├── input-windows-channels  (Winevt collector + inject_logsource_fields via Event)
             ├── input-evtx              (EVTX file parser → Event + inject_logsource_fields)
             ├── sigmacatch-types        (Event, Alert, RegressionHeader, Product, XML parsing, logsource mapping tables)
             └── sigma-regression        (InfoYml, SkipSet, triplet)
```

`detection-engine` is independent (depends only on `sigmacatch-types` + `rsigma-eval`). `input-windows-channels` depends on `sigmacatch-types` for shared types and mapping tables. `sigmacatch` depends on all 5, plus external crates (`rsigma-eval`, `grit-lib`, `tokio`, `windows`, etc.).

## Pipeline (single run, sequential)

1. Load config (create `config.yaml` with defaults if missing)
2. Create directories: `regression_data/`, `regression_data/rules/`
3. Acquire SigmaHQ rules via `grit-lib` (clone); exit error if no rules found
4. `find_rules_dirs()` scans `sigma/` for `rules` / `rules-*` dirs (excludes `rules-compliance`)
5. Build skip set by scanning `regression_data/rules/` + `sigma/regression_data/` for existing `info.yml` → `HashSet<String>` of rule IDs
6. Load Sigma rules from all `rules*` dirs, **excluding skipped rule IDs**; post-parse filter via `rule.logsource.product` filters non-Windows rules; status/level filter via `config.sigma.min_status`/`min_level` (sole allowed optimization) — a startup rule table is displayed (loaded / skipped / active services). The `RuleIndex` maps each rule ID to its `Product` for product-scoped access.
7. Collect events via collectors (`EventCollector`, `EVTXCollector`) → `Vec<Event>`:
   - Each event carries `event_json: Value` (pre-parsed by collector, `parse_winevt_xml` fallback)
   - Collectors inject `product`, `service`, `category` via `Event::inject_logsource_fields()` before sending
   - The engine uses `LogSourceExtractor` + bloom pre-filter from rsigma-eval to prune incompatible rules
    - Evaluate against **all loaded rules** via FIFO API: `engine.put_events(events) → engine.process_events() → engine.get_alerts()` — **no event lost**
   - Aggregate matches by `rule_id` in `HashMap<String, AggregatedRule>`
8. Generate regression for rules without existing `info.yml` (skip at generate time too)
9. Write: `<output>/<rule_rel_path>/<rule_id>.json` (first matched event) + `<rule_id>.evtx` + `info.yml`; append `regression_tests_path` line to the source rule YAML

> Skip set details, key design decisions, and skip set construction logic are in [`architecture-reference.md`](architecture-reference.md) (Stages 2, 5, 6, 7).
