# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - Unreleased

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

## [0.5.3] - 2026-08-XX

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
