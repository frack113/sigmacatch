# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.2] - 2026-09-26

### Changed

- CI workflow optimizations: combined `regressiondata-check` builds with base flavors using `--all-targets` to eliminate redundant compilations; added cache keys with `Cargo.lock` hashes for better cache reuse; made `regression-check` depend on `linux` job to reuse built artifacts
- Dependency updates: `evtx 0.12.3`, `thiserror 2.0.21`, `zerocopy 0.8.59`, `pest 2.9.2`, removed unused `base64`/`multiversion` transitive deps
- Supply-chain: removed stale `cargo-deny` skip entries for `base64 0.22.1` and `foldhash 0.1.5`

## [0.6.1]

### Added

- Configurable working branch: `--branch` flag and `git.working_branch` config option control which git branch regression commits target (#89)
- Configuration reference (FR + EN) in the docs: every `config.yaml` field, defaults, and validation rules

### Changed

- Restore the standalone Linux `regressiondata-check` release asset for direct download by CI workflows (#87)
- README `Releases` section deduplicated against CHANGELOG (release process kept, version history centralized in CHANGELOG); version dates corrected
- Documentation: factual/grammar drift corrected across FR/EN, cross-language links repaired; CLI/Workspace content deduped into docs
- CI: anti-regression coverage gate added, and the coverage-gate flag corrected to `--fail-under-lines`
- Broad test-coverage additions (runner pipeline loop, detection-engine error/HIR branches, repo plumbing + EVTX input, logging init); signing test key is now generated at runtime instead of a committed private key

### Fixed

- auditd regression data: per-record NDJSON fidelity preserved (#88)
- Bare `check-filter` / `list-rules` invocations now run in human mode instead of printing help
- Quality fixes: unwrap-free live interval, empty-alerts guard, unreachable invariant (Q2.1/Q2.4)

## [0.6.0] - 2026-09-11

### Added

- Single-package architecture: the multi-crate workspace (15 crates) folds into one package `sigmacatch` — one library plus two binaries (`sigmacatch`, `regressiondata-check`); inputs are cargo features (`winevt` default, `evtx`, `auditd`, `builtin`, `sysmon`, `ebpf`), runtime dispatch in `main.rs`/`inputs::mod.rs` (#84, #85)
- One-shot EVTX input routed through the shared pipeline: `--evtx <PATH>` runs the EVTX writer as a `CollectorKind` with `live_capture() = false` and exits once the directory is drained; the pure-Rust writer emits proper TemplateInstance records (parse-identical in the Rust reader and Velocidex evtx) (#83, #85)
- Deterministic tail startup for tests: one-shot READY barrier and injectable poll interval
- Committed sigma regression fixture in the repo, guarded by a CI job covering the happy path, the empty/negative path and `--fix`
- Release pipeline: per-flavour archives (Linux `sigmacatch-linux`/`-sysmon`/`-ebpf`, Windows `sigmacatch-winevt.exe`/`-evtx.exe`, plus `regressiondata-check`), per-platform `SHA256SUMS` and Sigstore keyless cosign signing
- Absolute `sigma_repo_path` accepted in config and all binaries
- Offline mode allows empty author/email in config validation

### Changed

- rsigma 0.21 → 0.22 (`rsigma-parser`, `rsigma-eval`, `rsigma-ir`, daachorse 3 → 5); MSRV 1.95.0
- Optimized evaluation pipeline over rsigma-eval: single-pass `EvtRender`, persistent `EvtQuery`, structural EVTX validation
- Shared Linux tail driver (`tail.rs`): rotation detection, partial-line buffering, per-collector `LineHandler`
- `regressiondata-check` keeps the trailing newline when replaying auditd `.log` regression data
- ETW collector removed (`ferrisetw`) and ETW references dropped from docs and CI (#80)
- CI: jobs bounded with `timeout-minutes: 15`; Linux matrix gains a `regressiondata-check` flavour; pinned GitHub Action versions refreshed

### Fixed

- eBPF CI leg embeds a real probe (nightly + bpf-linker, fail-fast)
- `cargo deny` warnings eliminated — stale `skip` entries (windows 0.57, zerocopy 0.7.35, foldhash 0.1.5, num-derive 0.3.3, windows-result 0.1.2) purged

### Security

- Release archives signed with Sigstore keyless signing (`cosign verify-blob --bundle <archive>.bundle <archive>`)

## [0.5.4] - 2026-09-04

### Added

- `DetectionEngine::new_lenient()` — compiles rules but logs failures instead of erroring; suitable for validation tools
- JSONL (JSON Lines) support for auxiliary `.json` files in `regressiondata-check`
- Explicit validation for empty/missing `regression_tests_info` in `info.yml`
- CLI help note about JSONL support
- Workspace dependencies for `tracing` and `tracing-subscriber`

### Changed

- `regressiondata-check` now uses `DetectionEngine::new_lenient()` to allow validation past bad rules
- Tracing subscriber writes to stderr with default filter `warn,regressiondata_check=info` for cleaner `--json` output
- Empty JSON files are now rejected in auxiliary validation
- Error message for empty `regression_tests_info` now says "empty or missing"

### Fixed

- `new_lenient` now returns failed rules programmatically for caller inspection
- Added test coverage for `new_lenient` behavior

## [0.5.3] - 2026-09-02

### Added

- Standalone `regressiondata-check` binary for SigmaHQ regression data validation
- `--fix` mode for normalizing JSON trailing newlines and YAML indentation
- `--json` output for machine-readable results
- `--ignore` flag to skip invalid entries

### Changed

- Renamed `sigmacatch-check` to `regressiondata-check`

### Fixed

- Various validation edge cases

---

*See git history for earlier versions.*
