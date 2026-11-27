# Roadmap

Planned evolutions for sigmacatch. Items are listed in no strict order; each
becomes a tracked change when picked up. The project is WIP, so this list is
not a commitment, just the current intent.

## Correctness

- **[#129] Rules with an unresolved `|expand` placeholder are silently never matched.**
  A SigmaHQ rule that filters on a placeholder never fires in sigmacatch and
  nothing is logged. sigmacatch hands such rules to rsigma-eval without
  resolving the placeholder; rsigma then fills it from the event at match time
  (`%known_cdcs%` becomes the event field `known_cdcs`, or `""` when absent, and
  `contains ""` is true for any value, so `not filter` hides every hit). The
  [Sigma specification](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/specification/sigma-rules-specification.md#L597)
  says placeholders must be handled appropriately, or the rule must be rejected.
  Options are: reject/skip the rule with a warning (spec-conformant), treat
  unresolved placeholders as literals (what SigmaHQ CI validates against), or
  add a `value_placeholders` transformation with `vars:` in a pipeline.
  [#129]: https://github.com/frack113/sigmacatch/issues/129

## CI/CD

- Improve CI/CD. Current required checks are documented in
  [Contributing](https://github.com/frack113/sigmacatch/blob/main/CONTRIBUTING.md):
  `cargo fmt --check`, `cargo clippy --all-targets -W warnings`, `cargo test`,
  the macOS clippy/test pass, the Windows cross-build
  (`cargo xwin build --release --target x86_64-pc-windows-msvc`), plus
  `typos`, `zizmor`, markdownlint and `cargo deny`. Scope and concrete
  improvements still to define.

## Codebase organization

- Review codebase organization. The project is a single Cargo workspace with
  18 members after the split in #164; layout is documented in
  [Dev Layout](dev/layout.md) and the current plan lives in
  [`.opencode/org_codebase.md`](https://github.com/frack113/sigmacatch/blob/main/.opencode/org_codebase.md).
  Further structure changes still to define.

## Documentation

- Keep changelog and roadmap in `docs/`, not at the repository root. Roadmap
  lives at `docs/roadmap.md`; changelog lives at `docs/changelog.md`.
  The release workflow now writes `docs/changelog.md` via git-cliff.
