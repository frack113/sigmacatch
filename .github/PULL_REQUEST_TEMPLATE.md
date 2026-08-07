## Summary

1-2 sentences describing the change and why it is needed.

## Changes

- ✨ feat: description (commit hash)
- 🐛 fix: description (commit hash)

One bullet per commit, grouped by type with the corresponding emoji.

## Tests

Result of the required checks (obligatory for code changes):

- `cargo fmt --check` — passed
- `cargo clippy --all-targets -- -W warnings` — passed
- `cargo test --locked` — passed
- `cargo xwin build --release --target x86_64-pc-windows-msvc` — passed
- `uvx typos .` / `uvx zizmor .` / `markdownlint` — passed (if applicable)

## Files

- `path/to/file` — reason

## Checklist

- [ ] Follows the commit conventions in `CONTRIBUTING.md`
- [ ] No dead code; no unpinned GitHub Actions; no `persist-credentials: true`
- [ ] Architectural invariants preserved (see `AGENTS.md`)
