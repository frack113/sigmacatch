# Codebase organization plan

Goal: finish properly organizing the sigmacatch codebase. Build on the existing
crate split; close remaining gaps; lock structure in so it does not regress.

This is a plan, not a record of work done. Numbers below are measured on this
checkout; items marked "inferred" are judgments, not verified facts.

## 1. Current state (measured)

- Single Cargo workspace, `resolver = "2"`, edition 2024, **20 members**.
  Shared `[workspace.package]`, `[workspace.dependencies]`, `[workspace.lints]`
  (`missing_docs = warn`; clippy `correctness`/`suspicious = deny`,
  `style`/`complexity`/`perf = warn`). Version `0.8.0`, MIT.
- Top-level layout mirrors the product's building blocks:
  - `sigmacatch/` — binary `sigmacatch` + second artifact
    `regressiondata-check`. `lib.rs` re-exports `sigmacatch-core`, the runner,
    `pub mod orchestrators`, `pub mod output_factory`, optional `ebpf_common`.
    `main.rs` dispatches runtime inputs.
    - `src/orchestrators/` is **binary orchestration**: `mod.rs` aliases the
      real collector crates, `windows.rs`/`linux.rs` are OS fan-in/fan-out.
    - `src/output_factory/` builds the compiled-in output sink.
  - `common/core/` — package `sigmacatch-core`: the shared data models that
    cross autonomous boundaries (`exchange`: `Event`, `Alert`, `Product`,
    channel tables, `ChannelResolver`, `RegressionHeader`, `DataFormat`), plus
    `config`, `cli`, `logging`, `rule`, `regression` seams, `evtx_reader`,
    `audit_reader`, `util`, and a re-export of `sigmacatch-repo` as `repo`.
  - `detection/` — package `sigmacatch-detection`: the Sigma engine (rsigma
    compile/evaluate), pipelines, indexed events, channel resolution.
  - `runner/` — package `sigmacatch-runner`: `CollectorKind`, the
    continuous/one-shot loop, `Pipeline`, `process_and_generate`.
  - `collector/*` — one crate per source (packages `sigmacatch-input-*`):
    `auditd`, `ebpf` (largest), `etw-common`, `etw`, `etw-driver`, `evtx`,
    `macos`, `syslog`, `sysmon`, `tail`, `winevt`. Each owns its
    `feature × target_os` gates; the bin `lib.rs` stays gate-free.
  - `persist/*` — packages `sigmacatch-output-evtx` and
    `sigmacatch-output-regression`; the EVTX writer and the SigmaHQ regression
    sink.
  - `sigmacatch/repo/` — package `sigmacatch-repo`, git via grit-lib + system
    `ssh`, pending-PR tracking.
  - `sigmacatch/sigma-regression/` — package `sigma-regression`, `info.yml`.
  - `sigmacatch/driver/protocol/` — package `sigmacatch-driver-protocol`,
    shared with the standalone driver workspace by path.
  - `sigmacatch/ebpf` excluded; nightly + bpf-linker, built separately.
  - `sigmacatch/driver` — standalone KMDF workspace (Windows).
- Cargo **features** of `sigmacatch` select which collector crates link in:
  `winevt` (default), `evtx`, `etw`, `driver`, `auditd`, `builtin`
  (= `sigmacatch-input-syslog` + `sigmacatch-input-tail`), `sysmon`
  (= `builtin` + `sigmacatch-input-sysmon`), `ebpf`, `macos`. `builtin` is a
  feature, not a workspace crate.
- Wiring: collectors build a producer (`EventProducer`), persist crates build a
  sink (`RegressionSink`), and `sigmacatch_runner::run<C: CollectorKind>` is the
  single shared pipeline. No `TODO`/`FIXME`/`todo!` in `sigmacatch`.
- SPDX header convention on new source/header files; `missing_docs` on.

## 2. Naming: package vs directory (gap)

Package names are clean (`sigmacatch-core`, `sigmacatch-repo`,
`sigma-regression`, `sigmacatch-output-*`, `sigmacatch-driver-protocol`), but
they are nested under `sigmacatch/`, e.g. `sigmacatch/core`, not top-level
`sigmacatch-core/`. Two naming systems coexist; `AGENTS.md` currently blurs
them.

`AGENTS.md` "Where things are" block is stale (verified 2026-11-22 but wrong
now): it lists `sigmacatch-core/`, `sigmacatch-repo/`, `sigma-regression/` as
top-level members; actual member paths are `sigmacatch/core`,
`sigmacatch/repo`, `sigmacatch/sigma-regression`. (`docs/dev/layout.md`
correctly says 18 crates; it references package names.)

## 3. Structural invariants to make explicit (already true; document + enforce)

- One crate = one responsibility; inputs implement `CollectorKind`; outputs
  implement `RegressionSink`; core never depends on a concrete input/output.
- `sigmacatch-core` owns the **shared data models** that cross autonomous
  boundaries:
  - `input → detection engine` (`Event`, `Alert`, logsource injection,
    channel/service/category tables);
  - `detection engine → output` (`Alert`, `RegressionHeader`, `DataFormat`).
  No autonomous block exposes its internals to another block.
- **Detection is autonomous**: `detection/` depends only on `sigmacatch-core`
  (`config`, `rule`, `exchange`, `util`) plus `rsigma-eval`/`rsigma-parser`.
  It has no knowledge of collectors, outputs, repo, or regression sinks.
- **The runner is autonomous**: `runner/` depends on `sigmacatch-core` and
  `sigmacatch-detection`; it does not depend on any collector or persist crate.
- **Collectors never depend on the concrete engine**: `CollectorKind::channels`
  takes `&dyn ChannelResolver`; the engine implements that trait. Collectors
  depend on `sigmacatch-core` (data model) and `sigmacatch-runner` (contract)
  only.
- `sigmacatch` bin crate stays thin; `lib.rs` gate-free; feature `× target_os`
  gating lives in each collector crate, not in `sigmacatch/src`.
- Git only through `sigmacatch-repo`; no hand-rolled parsers; no tokens.
- New source/header files start with the two SPDX lines.
- `ebpf` probe excluded; `driver` separate workspace sharing `protocol`.

## 4. Public API surface of the `sigmacatch` crate

The binary crate exposes more than `main`:

- `pub mod orchestrators` — re-exports the real collector crates + hosts the
  two OS fan-in/fan-out orchestrators. Consumed by integration tests and
  `main.rs` dispatch.
- `pub mod output_factory` — re-exports `sigmacatch_output_regression` as
  `regression` + provides `regression_sink_factory()`.
- `pub mod regression` — re-exports core + output-regression types.
- `pub mod runner` — re-export of `sigmacatch-runner`, plus top-level re-exports
  of `CollectorKind`, `run`, and `bootstrap_repo_regression`.
- Re-exports of `sigmacatch-core` (config, cli, rule, types, repo,
  evtx_reader, audit_reader, logging).

The old names `sigmacatch::inputs` and `sigmacatch::outputs` were renamed to
`sigmacatch::orchestrators` and `sigmacatch::output_factory`; the concrete
crates now live under `collector/` and `persist/`. This is a breaking change
for any external consumer of those paths; internal tests were migrated
atomically.

## 5. Naming collisions worth cleaning (resolved)

- ✅ `sigmacatch/src/inputs/` vs `sigmacatch/inputs/` — renamed to
  `sigmacatch/src/orchestrators/`.
- ✅ `sigmacatch/src/outputs/` vs `sigmacatch/outputs/` — renamed to
  `sigmacatch/src/output_factory/`.
- Package name `sigmacatch-repo` vs re-exported module `sigmacatch::repo`.
  Left as-is: documented in `AGENTS.md` as an explicit re-export.

## 6. Plan (sequenced; each step independently shippable, one concern per commit)

### Phase 0 — freeze & verify baseline
- [ ] Confirm 18 members, no name collisions in `cargo metadata`, `cargo
      fmt --check`, `cargo clippy --all-targets --all-features`, `cargo test`
      green. (No code change; safety net.)

### Phase 1 — fix stale/incorrect docs (cheap, high value)
- [x] `AGENTS.md` layout block: correct member paths
      (`sigmacatch/core`, `sigmacatch/repo`, `sigmacatch/sigma-regression`),
      keep package names; reconcile `sigmacatch-output-*` names; keep
      18-member count; keep `driver/protocol` path. Then re-verify.
      Done 2026-11-27; refreshed bmad date.
- [x] Remove the erroneous `builtin`-as-crate implication (§1 documents it is
      a `sigmacatch` feature, not a workspace crate); state it clearly. Done.
- [x] `docs/dev/layout.md`: cross-check package vs directory names; no change
      needed if already correct. Verified.
- [x] Document that `sigmacatch/src/inputs/` is **binary orchestration** of the
      real input crates; the real input implementations live under
      `sigmacatch/inputs/`. Done in `AGENTS.md`.
- [x] Link `docs/roadmap.md` "Codebase organization" item to this plan file. Done.

### Phase 2 — move input/output code out of the bin crate (DONE)
These were the only real "input code still in src" leaks found.

#### 2a. Orchestrator naming ✅
Renamed to remove ambiguity with the real input/output crates:
- `sigmacatch/src/inputs/` → `sigmacatch/src/orchestrators/`
- `sigmacatch/src/outputs/` → `sigmacatch/src/output_factory/`
- Updated `lib.rs`, `main.rs`, orchestrator internals, all integration tests
  in `sigmacatch/tests/*.rs`, and `regressiondata-check.rs`.

Decision taken: big-bang rename + migrate internal tests atomically; no
public deprecation layer since this is pre-1.0 and the paths were primarily
consumed by the project's own tests.

#### 2b. Audit parser ✅
Extracted the inline Linux audit parser from `regressiondata-check.rs` into
`sigmacatch-core::audit_reader` (`sigmacatch/core/src/audit_reader.rs`):
- `parse_auditd_lines(raw: &[u8]) -> (Vec<Event>, usize)`
- `value_to_json(value: &linux_audit_parser::Value<'_>) -> Option<JsonValue>`

Moved the `linux-audit-parser` dependency from `sigmacatch/Cargo.toml` to
`sigmacatch/core/Cargo.toml`. `regressiondata-check` now delegates to
`sigmacatch_core::audit_reader::parse_auditd_lines`.

This removes an input-format dependency from the binary package and aligns
with "no hand-rolled parsers".

### Phase 3 — codify + enforce structure (prevent regressions)
- [ ] Write concise structure rules in `AGENTS.md` + `docs/dev/layout.md`
      (§3 invariants, especially detection autonomy).
- [ ] CI guardrails (small scripts / CI steps):
  - fail if any `*.rs` lacks the two SPDX lines;
  - fail if `cargo metadata` workspace-member set changes without intent
    (explicit allowlist);
  - fail if `sigmacatch/Cargo.toml` acquires an input-only dependency that is
    not also used by a core crate or the regression validator;
  - `cargo deny --all-features check` already enforces dep graph; keep;
  - keep clippy `-W warnings` ratchet at zero.
- [ ] Keep `docs/dev/layout.md` diagrams (`repository-layout`,
      `module-dependency-graph`) regenerated when membership changes; re-run
      the docs Archify pipeline per repo rules.

### Phase 4 — optional further cleanup (not required now)
- [ ] Consider renaming the `src/inputs` module inside `sigmacatch/inputs/`
      crates if `mod.rs` names still collide in conversation. Default: leave.
- [ ] Re-evaluate `sigmacatch/src/output_factory/mod.rs` if a second output
      backend appears. Default: leave.

### Phase 5 — conditional extraction (only on measured pressure; NOT proposed now)
- [ ] Split `sigmacatch-core` further **only** if a sub-module becomes
      independently reusable or a file/module grows unmanageable. Candidates
      to watch: `types` (~2.3k), `detection`, `rule`, `regression`. No
      extraction without a concrete consumer. (inferred; current size OK.)
- [ ] `ebpf` / `driver` already excluded; keep.

## 7. Recommended next concrete slice

Smallest useful first move: **Phase 1** — fix `AGENTS.md` layout accuracy
(paths + `builtin` feature + `sigmacatch-output-*` names) and link this plan
from the roadmap. No Rust changes, reversible, immediate clarity. Then Phase 3
guardrails.

## 8. Verification (for any change)

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -W warnings`
- `cargo test --locked`
- `cargo xwin build --release --target x86_64-pc-windows-msvc`
- macOS clippy/test on `--no-default-features --features macos`
- `cargo deny --all-features check advisories sources licenses bans`
- Docs-only changes: markdownlint-cli2, `typos`, `zensical build --clean`,
  re-gen affected Archify viewers per `AGENTS.md` diagram rules.
- One concern per commit; docs/changelog never mixed with code/refactor.

## 9. Non-goals

- Not forcing a re-layout; the 18-crate split (#164) is sound.
- Not extracting `sigmacatch-core` further without a concrete consumer.
- `CHANGELOG.md` moved to `docs/changelog.md` as part of Phase 1.
- Not touching `sigma/`, `site/`, generated `docs/media`, or BMAD `.opencode`
  commands.

## 10. Proposal — autonomous `detection_engine` module/crate

### 10.1 Goal

Make the detection engine a first-class, autonomous boundary in the workspace.
`sigmacatch-core` defines all data models that cross autonomous boundaries:

- `input → detection engine`
- `detection engine → output`

The detection engine exposes a clean API that depends only on `sigmacatch-core`
data models, not on rule-discovery, repository handling, or regression-output
concerns. Inputs link only to `sigmacatch-core`; the runner wires the rest.

### 10.2 Current coupling (measured)

`sigrmacatch/core/src/detection/` (~2.3k LOC including YAML pipelines):
- `detection/mod.rs` imports `crate::config::EngineConfig`, `crate::rule::SigmahqRules`,
  `crate::types::{Alert, Event}`, `crate::util::to_hex`.
- `channel_resolver.rs` imports `crate::types::{CATEGORY_CHANNELS, SERVICE_CHANNELS}`.
- It owns the HIR cache, pipeline parsing/loading, `CompiledRule` management,
  and event evaluation.

`sigrmacatch/core/src/types.rs` (~2.3k LOC):
- Defines `Event`, `Alert`, `EventProducer`, `ProducerError`, `Product`,
  channel/service/category tables, and Winevt XML parsing.
- `EventProducer` is an async trait used by **inputs**, not by the detection
  engine itself.

`sigrmacatch/core/src/runner.rs`:
- Imports both `detection::DetectionEngine` and `rule::SigmahqRules`, plus
  `repo::SigmaRepo` and `regression::{RegressionSink, RegressionSinkFactory}`.
- The `CollectorKind` trait has a `channels(&self, &DetectionEngine, ...)` method,
  which ties collector metadata to the detection engine type.

### 10.3 Desired responsibilities

| Layer | Responsibility | Public types |
|-------|----------------|--------------|
| `sigmacatch-core::exchange` | Data models crossing autonomous boundaries. | `Event`, `Alert`, `Product`, channel/service/category tables, logsource injection helpers, `RegressionHeader`, `DataFormat` |
| `sigmacatch-core::detection_engine` | Compile Sigma rules, apply pipelines, evaluate `Event`s, produce `Alert`s. | `DetectionEngine`, `EngineConfig`, `RuleProvider` trait, `PipelineSet`, `ChannelResolver` |
| `sigmacatch-core::rule` (kept) | Discover, parse, filter, and fingerprint the Sigma rule corpus. | `SigmahqRules`, `RuleSet`, filtering/threshold logic |
| `sigmacatch-core::runner` (kept) | Wire producer → detection engine → sink, orchestrate continuous run. | `run<C: CollectorKind>`, `CollectorKind` |
| Inputs (`sigmacatch-input-*`) | Build `Event` values using `exchange` types, send them to the runner. | `impl EventProducer` |
| Outputs (`sigmacatch-output-*`) | Consume `Alert`s and `RegressionHeader` to write regression data. | `RegressionSink`, `RegressionSinkFactory` |

### 10.4 Two possible scopes

#### Option A — crate `sigmacatch-detection-engine`
- New workspace member: `sigmacatch/detection-engine/`.
- Package name `sigmacatch-detection-engine`.
- Depends only on `sigmacatch-core` for the `exchange` subset, plus
  `rsigma-eval`, `rsigma-parser`, `rayon`, `serde_json`, `thiserror`, `uuid`, `sha1`.
- `sigmacatch-core` re-exports it so existing call sites keep working
  (`sigmacatch_core::detection_engine`).
- More ceremony (new `Cargo.toml`, workspace member update, diagrams) but
  strongest boundary.

#### Option B — module `sigmacatch-core::detection_engine`
- Move `sigmacatch/core/src/detection/*` to `sigmacatch/core/src/detection_engine/*`.
- Split out `sigmacatch/core/src/exchange.rs` for `Event`, `Alert`, `Product`,
  channel tables, and logsource injection.
- `sigmacatch/core/src/lib.rs` re-exports:
  - `pub mod exchange`
  - `pub mod detection_engine`
- Less churn; keeps the workspace at 18 members. The boundary is logical,
  not physical.

**Recommendation:** start with **Option B** unless a concrete external consumer
of `detection_engine` appears. It gives 90% of the architectural benefit for a
fraction of the workspace churn.

### 10.5 Data model (`exchange` subset)

Extract from `types.rs` the elements that are part of the input↔detection
contract:

- `Event` (raw/detection JSON views, raw bytes, grouped records).
- `Alert` (rule metadata + shared event payload).
- `Product` enum (`Windows`, `Linux`, `Macos`).
- `inject_logsource_fields` helpers and channel/service/category tables.

Extract from `regression` the elements that are part of the detection↔output
contract:

- `RegressionHeader` (minimal rule metadata for the sink).
- `DataFormat` (EVTX, Log, Json — tells the sink how to write).

These belong to `exchange` because they cross an autonomous boundary: the
engine produces values, the output consumes them, neither owns the other's
implementation.

Leave in `types.rs` / move elsewhere:
- `EventProducer` and `ProducerError` — these belong to the **runner/input**
  contract, not the input↔detection contract. Keep them in `sigmacatch-core::types`.

### 10.6 Decoupling `DetectionEngine` from `SigmahqRules`

This is the hard part. Options:

1. **RuleProvider trait**
   ```rust
   pub trait RuleProvider {
       fn rules(&self) -> Vec<&SigmaRule>;
       fn pipeline_files(&self) -> Vec<&[u8]>;
       fn cache_key(&self) -> String;
   }
   ```
   `SigmahqRules` implements `RuleProvider`. `DetectionEngine` takes
   `&dyn RuleProvider` instead of `&SigmahqRules`.

2. **RuleSet builder API**
   ```rust
   let mut engine = DetectionEngine::new(config)?;
   engine.load_rules(rules.iter().map(|r| (r, &hir_cache)))?;
   ```
   The engine owns the `CompiledRule` storage; the caller decides how to feed it.

3. **Hybrid: trait + loader helper**
   `DetectionEngine::new(provider: &dyn RuleProvider, config: &EngineConfig)`
   for the common path, plus `DetectionEngine::new_empty(config)` for tests and
   exotic consumers.

**Recommendation:** Option 3. It preserves the simple constructor for the
runner while making the engine independently testable.

### 10.7 `CollectorKind` dependency on `DetectionEngine`

Currently:
```rust
fn channels(&self, engine: &DetectionEngine, custom_map: &HashMap<String, String>) -> Option<Vec<String>>;
```

This forces the runner module to know both `CollectorKind` and `DetectionEngine`.
Options:

1. Replace `&DetectionEngine` with a smaller trait:
   ```rust
   pub trait ChannelResolver {
       fn resolve_channels(&self, custom_map: &HashMap<String, String>) -> Vec<String>;
   }
   impl ChannelResolver for DetectionEngine { ... }
   ```
2. Move `CollectorKind` into the `exchange` or `runner` layer and let it take a
   callback `Fn(&HashMap<String, String>) -> Vec<String>`.

**Recommendation:** Option 1. It removes the last direct dependency from the
runner/input boundary onto the concrete `DetectionEngine`.

### 10.8 HIR cache ownership

The HIR cache file (`HIR_CACHE_VERSION`, cache-key derivation, save/load) lives
inside `detection/mod.rs`. It should move with the engine. However, the cache
key currently depends on the rule-set fingerprint, which is computed in
`rule`. If `DetectionEngine` receives a pre-computed cache key from the caller,
the cache logic stays fully inside `detection_engine`.

### 10.9 Pipeline ownership

The four pipeline YAML files (`1_win_logsource.yml`, `2_win_field_name.yml`,
`3_lnx_logsource.yml`, `4_lnx_field_name.yml`) are part of the detection
semantics. They move with `detection_engine`.

The `channel_resolver.rs` logic resolves channel → service → category using
static tables from `types.rs`. After the `exchange` split, the tables move to
`exchange`; the resolver stays in `detection_engine` and imports them.

### 10.10 Migration plan (phased, reversible)

#### Step 1 — Extract `exchange`
- Create `sigmacatch/core/src/exchange.rs`.
- Move `Event`, `Alert`, `Product`, channel/service/category tables, logsource
  injection from `types.rs`.
- Update `types.rs` to `pub use exchange::*` where appropriate.
- Update every internal import.
- Run full test/clippy.

#### Step 2 — Introduce `RuleProvider` and decouple `DetectionEngine`
- Define `RuleProvider` in `detection_engine::provider`.
- `SigmahqRules` implements `RuleProvider`.
- Change `DetectionEngine::new(&SigmahqRules)` to
  `DetectionEngine::new(&dyn RuleProvider)`.
- Add `DetectionEngine::new_empty` for tests.

#### Step 3 — Rename `detection` → `detection_engine`
- Move files from `sigmacatch/core/src/detection/` to
  `sigmacatch/core/src/detection_engine/`.
- Update `lib.rs`, `runner.rs`, tests.
- Keep `pub mod detection` as a deprecated re-export if desired (pre-1.0).

#### Step 4 — Decouple `CollectorKind` from `DetectionEngine`
- Introduce `ChannelResolver` trait.
- Update `CollectorKind::channels` signature.
- Update `WindowsCollector::channels` and call sites.

#### Step 5 — Optionally promote to standalone crate
- Only if a concrete consumer outside `sigmacatch-core` appears.

### 10.11 Verification (same as any change)

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -W warnings`
- `cargo test --locked`
- `cargo xwin build --release --target x86_64-pc-windows-msvc`
- `cargo deny --all-features check advisories sources licenses bans`

### 10.12 Decision needed

1. **Scope:** Option A (new crate) or Option B (module in core)?
2. **Rule feeding API:** RuleProvider trait, builder, or hybrid?
3. **Deprecated re-exports:** Keep `sigmacatch_core::detection` as alias?
4. **Exchange name:** `exchange`, `event_model`, `detection_api`, or other?
5. **Timing:** Do this now, or commit Phase 2 first and tackle this in a
   separate change?

Recommendation: Option B, hybrid RuleProvider API, no deprecation layer yet,
name `exchange`, commit Phase 2 first.

## 11. Applied architecture (2026-11-27)

The proposal above was executed in four commits:

1. `🏗️ refactor: move sigmacatch-core to common/core`
2. `🏗️ refactor: extract detection engine and runner into standalone crates`
3. `🏗️ refactor: move input crates to collector/ and output crates to persist/`
4. CI/path-comment cleanup

Final layout (20 workspace members):

```
sigmacatch/            bin: main, orchestrators/, output_factory/
common/core/           sigmacatch-core: exchange, config, rule, repo re-export,
                       regression seams, evtx_reader, audit_reader, util
detection/             sigmacatch-detection: engine, pipelines, channel resolver
runner/                sigmacatch-runner: CollectorKind, run loop, Pipeline
collector/*/           11 collector crates (sigmacatch-input-*)
persist/*/             sigmacatch-output-evtx, sigmacatch-output-regression
sigmacatch/repo/       sigmacatch-repo
sigmacatch/sigma-regression/
sigmacatch/driver/protocol/
```

Decisions actually taken:

- **Physical crates, not modules.** `detection` and `runner` are autonomous
  workspace members. `runner` had to be a crate (not bin code) because collector
  crates call `sigmacatch_runner::run`.
- **`ChannelResolver` implemented.** `CollectorKind::channels` now takes
  `&dyn ChannelResolver`; collectors depend on `sigmacatch-core` +
  `sigmacatch-runner`, never on `sigmacatch-detection`.
- **Package names unchanged** (`sigmacatch-input-*`, `sigmacatch-output-*`).
  Only directories moved; every `use` stayed stable.
- **`to_hex` made public** in `sigmacatch-core::util`, shared by rule
  fingerprinting and the engine.
- **Not done: `RuleProvider`.** The engine still constructs from
  `sigmacatch_core::rule::SigmahqRules`. Since `rule` now lives in the common
  crate, this is a service dependency inside the common layer rather than a
  cross-block leak. Revisit only if the engine must be fed rules from outside
  the SigmaHQ corpus model.
- **`config::apply_collector_product_default` made public** so the runner can
  apply collector defaults.

