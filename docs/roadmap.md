# Roadmap

Planned evolutions for sigmacatch. Items are listed in no strict order; each
becomes a tracked change when picked up. The project is WIP, so this list is
not a commitment, just the current intent.

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
  20 members after the layered reorganisation: `common/` (shared data models and
  services), `detection/` (Sigma engine), `runner/` (orchestration),
  `collector/*` (adapters in) and `persist/*` (adapters out), plus the binary.
  Layout is documented in [Dev Layout](dev/layout.md); the execution record and
  remaining guardrails live in
  [`.opencode/org_codebase.md`](https://github.com/frack113/sigmacatch/blob/main/.opencode/org_codebase.md).
  Further structure changes still to define.

## Documentation

- Keep changelog and roadmap in `docs/`, not at the repository root. Roadmap
  lives at `docs/roadmap.md`; changelog lives at `docs/changelog.md`.
  The release workflow now writes `docs/changelog.md` via git-cliff.
