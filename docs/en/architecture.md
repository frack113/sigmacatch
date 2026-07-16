# Architecture

## Source tree

```
src/
├── main.rs              # Binary + pipeline (run_pipeline, Stats, AggregatedRule)
├── config.rs            # YAML config (serde, Default) with LogConfig
├── logger.rs            # Two-layer tracing subscriber (stderr info + daily rolling file debug)
├── sigma/
│   ├── loader.rs        # gix clone/pull + remote URL update + find_rules_dirs()
│   └── engine.rs        # SigmaEngine: load rules (post-parse filter), evaluate events, rule evaluation
├── collector/
│   ├── mod.rs           # pub mod winevt
│   └── winevt.rs        # WinevtCollector (EvtQueryW, EvtNext, EvtRender)
├── evtx/
│   └── writer.rs        # write_evtx() via EvtExportLog API (→ valid EVTX or .xml fallback)
├── parser/
│   └── mod.rs           # XmlParser (Winevt XML → flat JSON)
└── regression/
    ├── mod.rs           # SkipSet, build_skip_set(), validate_rule_id(), triplet validation
    ├── generator.rs     # RegressionData: aggregate + write output
    └── info_yml.rs      # InfoYml struct (rule_metadata, regression_tests_info)
```

## Pipeline (single run, sequential)

1. Load config (create `config.yaml` with defaults if missing)
2. Create directories: `regression_data/`, `regression_data/rules/`
3. Acquire SigmaHQ rules via `gix` (clone); exit error if no rules found
4. `find_rules_dirs()` scans `sigma/` for `rules` / `rules-*` dirs (excludes `rules-compliance`)
5. Build skip set by scanning `regression_data/rules/` + `sigma/regression_data/` for existing `info.yml` → `HashSet<String>` of rule IDs
6. Load Sigma rules from all `rules*` dirs, **excluding skipped rule IDs**; post-parse filter via `rule.logsource.product` filters non-Windows rules (sole allowed optimization)
7. Collect events via `WinevtCollector` (channels from config) → `Vec<WinevtEvent>`:
   - Each event carries `event_json: Option<Value>` (pre-parsed by collector, XmlParser fallback if None)
   - Each event's `LogSource` is derived from the **channel** via `resolve_logsource` (channel → service > provider → service > default)
   - Evaluate against **all loaded rules** via `evaluate_event_with_logsource(event, logsource)` — **no event lost**
   - Aggregate matches by `rule_id` in `HashMap<String, AggregatedRule>`
8. Generate regression for rules without existing `info.yml` (skip at generate time too)
9. Write: `<output>/<rule_rel_path>/<rule_id>.json` (first matched event) + `<rule_id>.evtx` + `info.yml`; append `regression_tests_path` line to the source rule YAML

## Architectural invariants (non-negotiable foundations)

- 100% sequential pipeline: acquire rules → load engine → collect events → match → generate
- All in RAM: in-memory aggregation before writing (no intermediate DB)
- One run = complete cycle (no "just collect" or "just generate" mode)
- Windows collection via **Winevt API** (`windows` crate, `EvtQueryW`/`EvtNext`/`EvtRender`) — no ETW, no ferrisetw
- Output = `regression_data/<rule_rel_path>/` (triplet: `<rule_id>.json` + `<rule_id>.evtx` + `info.yml` SigmaHQ format)
- **Real-time engine**: `rsigma-eval` loaded once with all non-skipped rules; every event is evaluated against all loaded rules. No event lost. Skip-at-load is the only optimization.
- **LogSource derived from channel ETW** (`resolve_logsource`), with provider as fallback.
  - Priority: channel → service > provider → service > default
  - See `# INVARIANT:` comment in `src/sigma/mapping/mod.rs`
- **EVTX via `EvtExportLog`**: re-queries the event by RecordID from the live log. On success → binary `.evtx`. On failure (event rotated out of retention) or non-Windows → `.xml` fallback (raw XML, not invalid binary).
  - **Known limitation**: race condition with log retention — if the event has been purged between collection and export, `EvtExportLog` fails silently (`ERROR_EVT_QUERY_RESULT_STALE`).

> Skip set details, key design decisions, and skip set construction logic are in [`architecture-reference.md`](architecture-reference.md) (Stages 2, 5, 6, 7).
