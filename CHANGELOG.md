# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
