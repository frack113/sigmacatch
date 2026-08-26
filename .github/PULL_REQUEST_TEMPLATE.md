## Overview

2-3 sentences describing **what** changed and **why** it is needed. No implementation details.

## What's new

Group by crate / module / subsystem. Use backticks for filenames and feature names.

### `<crate>` (new / modified)
- Key point 1
- Key point 2

### `<crate>` — `<sub-module>`
- Key point

### CI / quality
- What changed in CI, gates added, lints ratcheted

## Changed files (<N>)

Grouped by category. Do not list every file — use `git diff --stat` for the full list.
- `crates/<new>/` — new
- `sigmacatch-lnx/Cargo.toml` — reason
- `.github/workflows/<f>` — reason

## Testing

What is covered (inline tests, e2e, cross-compile).

Required checks for code changes:

- `cargo fmt --check` — passed
- `cargo clippy --all-targets -- -W warnings` — passed
- `cargo test --locked` — passed
- `cargo xwin build --release --target x86_64-pc-windows-msvc` — passed
- `uvx typos .` / `uvx zizmor .` / `markdownlint` — passed (if applicable)

## How to build / run

Reproducible commands for the binaries or features touched.

```bash
<commands>
```

## Checklist

- [ ] Follows the commit conventions in `CONTRIBUTING.md`
- [ ] No dead code; no unpinned GitHub Actions; no `persist-credentials: true`
- [ ] Architectural invariants preserved (see `AGENTS.md`)
