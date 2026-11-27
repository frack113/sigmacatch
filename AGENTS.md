<!-- bmad:context -->
<!-- Verified 2026-11-27 against current checkout. Managed by bmad-project-context; edits inside this block are replaced on refresh. Keep anything you want preserved outside the markers. -->

## sigmacatch

A Rust (2024 edition, one cargo workspace with 20 members) real-time Sigma matcher: captures OS events on Windows (Winevt, native ETW, kernel driver), Linux (auditd, syslog, Sysmon tail, eBPF) and macOS (Endpoint Security), matches them against a clone of SigmaHQ rules in `sigma/`, and writes SigmaHQ-format regression data. Documentation lives in `docs/` (English only). `sigma/` is a gitignored clone of SigmaHQ/sigma, not project source.

## Where things are

- Workspace members (all paths are relative to the repo root):
  - `sigmacatch/` — binary crate: one bin `sigmacatch` + second artifact `regressiondata-check`; `orchestrators/` and `output_factory/` live here.
  - `common/core/` — package `sigmacatch-core`: shared data models (`exchange`), config, CLI, rule management, regression vocabulary, `evtx_reader`, `audit_reader`, `util`, re-exports `sigmacatch-repo` as `repo`.
  - `detection/` — package `sigmacatch-detection`: Sigma engine, pipelines, indexed events, channel resolution.
  - `runner/` — package `sigmacatch-runner`: `CollectorKind`, continuous/one-shot loop, `Pipeline`.
  - `collector/*/` — one crate per input (package `sigmacatch-input-*`): `auditd`, `ebpf`, `etw-common`, `etw`, `etw-driver`, `evtx`, `macos`, `syslog`, `sysmon`, `tail`, `winevt`.
  - `persist/*/` — packages `sigmacatch-output-evtx` and `sigmacatch-output-regression`.
  - `sigmacatch/repo/` — package `sigmacatch-repo`: git operations, transport, pending-PR tracking.
  - `sigmacatch/sigma-regression/` — package `sigma-regression`: `info.yml` schema.
  - `driver/windows/protocol/` — package `sigmacatch-driver-protocol`, shared with the standalone KMDF driver workspace.
- `sigmacatch` cargo **features** select which collector crates link in: `winevt` (default), `evtx`, `etw`, `driver`, `auditd`, `builtin`, `sysmon`, `ebpf`, `macos`. `builtin` and `sysmon` are **feature combinations**, not workspace crates (`builtin` = `sigmacatch-input-syslog` + `sigmacatch-input-tail`; `sysmon` = `builtin` + `sigmacatch-input-sysmon`).
- `sigmacatch/src/orchestrators/` is binary **orchestration** (re-exports of the real collector crates + Windows/Linux fan-in/fan-out orchestrators); the real collector implementations live in `collector/*/`. Each collector crate owns its `feature × target_os` gates; keep the main crate's `lib.rs` gate-free.
- `sigmacatch/src/output_factory/` builds the compiled-in output sink and injects it into the runner.
- Runtime dispatch in `sigmacatch/src/main.rs`; writer `--evtx` is routed via `sigmacatch::config::parse_args()` (`CliArgs.evtx_path`) — never re-scan `argv` ad hoc.
- Shared collector pipeline: `runner/src/lib.rs` (`run<C: CollectorKind>`). Collectors depend on `sigmacatch-core` + `sigmacatch-runner`, never on `sigmacatch-detection`; `CollectorKind::channels` takes `&dyn ChannelResolver`.
- Standalone regression validator (no collector): `sigmacatch/src/bin/regressiondata-check.rs` — run it to validate `sigma/regression_data`.
- Commit conventions (emoji types, `🧪 test:` for regression data) and PR requirements: `CONTRIBUTING.md`.
- Codebase organization plan (evolution in progress): `.opencode/org_codebase.md`.

## Running and verifying

- This is a Linux host: the Windows inputs are gated out here (their crates are empty shells off Windows), so build/test here cannot validate Windows-only code — the real check is `cargo xwin build --release --target x86_64-pc-windows-msvc -p sigmacatch` (required before every PR).
- `driver/ebpf` is excluded from the workspace and compiles only on nightly with bpf-linker — it will not build under stable cargo.
- `cargo build --release -p sigmacatch` builds the default `winevt` input; Linux inputs need explicit `--no-default-features --features auditd,builtin[,sysmon|,ebpf]`, macOS needs a macOS host with `--no-default-features --features macos`, and `ebpf` needs root/CAP_BPF+CAP_PERFMON at runtime.

## Conventions that differ from defaults

- Every new source/header file starts with two SPDX lines — `// SPDX-License-Identifier: MIT` then `// SPDX-FileCopyrightText: 2026 sigmacatch contributors` (first two lines, before any doc comment); nothing in CI enforces it.

## Known pitfalls

- Keep the local docs venv at the repo root (`.venv-docs/`), never under `docs/` — a venv inside `docs_dir` is scanned as documentation content and can cause build failures, spurious assets, or slow builds.

<!-- /bmad:context -->

## Local tooling notes

- Docs build: venv lives at repo root `.venv-docs` (from `docs/requirements.txt`); build with `.venv-docs/bin/zensical build --clean` from the repo root. The venv must stay OUT of `docs/` (`docs_dir`) — a venv inside it is scanned as documentation content and can cause build failures, spurious assets, or slow builds (CI never hits this because it has no venv there).
- Chromium (flatpak `org.chromium.Chromium`) headless screenshots — e.g. for archify browser-checks — fail with sandbox errors unless the flatpak gets both host filesystems it needs: `--filesystem=home` (for `file://` pages) and `--filesystem=/tmp` (for Chrome's `--user-data-dir`). Working wrapper, kept at `/tmp/opencode/chromium-flatpak.sh`:
  ```sh
  #!/bin/sh
  exec flatpak run --filesystem=home --filesystem=/tmp --command=chromium-browser org.chromium.Chromium "$@"
  ```
  Point `ARCHIFY_CHROME` (or any `--screenshot` consumer) at that wrapper.
- The bmad block above was manually refreshed on 2026-11-27 to reflect the layered layout (`common/`, `detection/`, `runner/`, `collector/`, `persist/`) and the 20-member workspace; a `bmad-project-context` refresh must preserve those crate paths.
- Windows kernel-driver dev VM `sigmacatch-dev` (QEMU clone of the test VM, not a validation box — it HAS a toolchain): build the KMDF driver locally with `scripts/dev_win_build.sh` (syncs `driver/` + `driver/protocol/` → build with CI settings → `target/sigmacatch-dev/sigmacatch_driver.dll`). See `docs/dev/windows/vm.md`; CI's `Driver` workflow stays the gate and must not drift (WDK 10.0.22621 / LLVM 17.0.6 pinned in both places).


## Documentation diagrams

The docs are one English tree in `docs/` (groups `user/`, `regression_data/`, `dev/`, with `dev/collectors/` and `dev/windows/`), one topic per page, nav in `mkdocs.yaml`. Diagrams are **interactive Archify viewers embedded as iframes**, not exported images: Archify's SVG export is a frozen snapshot (the keyframes are inlined, but no `animation:` rule applies them; the motion lives in the viewer's JS). The delivered HTML is the artifact.

1. Author the candidate under `.archify/<type>-<slug>-<timestamp>/candidate.json` (gitignored), using the `archify` skill. Types used so far: `tree` (docs map, repo layout), `dataflow` (Windows telemetry, event's life, event pipeline), `workflow` (run pipeline), `architecture` (module dependency graph). Repository-backed diagrams need `meta.repository` (SSH origin → `link_mode: "local-only"` + 40-char revision) and `sources` on nodes (repo-relative path + lines), and must pass `--repo-root "$PWD"`.
2. Finalize:
   ```sh
   node /home/papa/.agents/skills/archify/bin/archify.mjs finalize <type> \
     .archify/<dir>/candidate.json .archify/<dir>/<slug>.html \
     --repo-root "$PWD" --quality showcase --json
   ```
   In this environment the `browser-check` gate fails; when it runs it reports `viewer/viewport-overflow` and `viewer/chrome-stage-clearance` for the shipped viewers too, so compare its diagnostics with their `.archify/*/*.browser-check.json` receipts before treating it as a new defect. `validate`, `deliver` and `check` passing is the bar — never claim browser-check passed. The `?embed=1` iframe hides the chrome that triggers the clearance check. A rerun after that gate needs `--out-dir <dir>/review-<n>`.
3. Embed:
   - copy the delivered HTML to `docs/media/interactive/<slug>.html`;
   - **`?embed=1` parks the ambient motion** (the viewer passes `data-embed` to `renderAmbient` and excludes it in the ambient CSS). Keep it for the chrome-free layout, then patch the copy: drop `html.hasAttribute('data-embed') ||` from the `renderAmbient(...)` call and remove `:not([data-embed])` from the ambient selectors (7 occurrences in the current build);
   - inject `<script>try{localStorage.setItem('archify-motion','live')}catch(e){}</script>` in `<head>` before the theme script, unconditionally — the viewer defaults to Still and stores that choice per site; the framed copies always start Live;
   - take the aspect ratio from the viewer `<svg viewBox="0 0 W H">` and add, with source-relative paths (`../media/...` from `docs/dev/*.md`, `media/...` from `docs/index.md`):
     ```html
     <!-- markdownlint-disable MD033 -->
     <iframe src="../media/interactive/<slug>.html?embed=1" loading="lazy"
             title="<what it shows>, interactive (Flow + Live)"
             style="display:block;width:100%;aspect-ratio:W/H;border:0;margin:0 auto"></iframe>
     <!-- markdownlint-enable MD033 -->
     ```
   `?embed=1` hides the viewer chrome (title, Export, Route, Lens), so only the diagram shows; MkDocs rewrites the relative path for directory URLs.
4. If a static SVG is unavoidable, `scripts/animate-svg.py docs/media/*.svg` injects a dashed-flow CSS animation into Archify exports; rerun it after every re-export. Do not commit the exported SVG unless the page needs a static fallback.
5. Verify: `zensical build --clean`, `npx markdownlint-cli2@0.24.1 "docs/**/*.md" "*.md"`, `typos .`, no broken relative links, and every embedded viewer answers 200.

Caveats worth repeating in reviews: each inlined viewer is ~850 KB (the whole viewer travels with the diagram), the iframe follows the system theme rather than the docs light/dark toggle, and print/PDF does not render iframes.


Current viewers in `docs/media/interactive/`: `docs-map-user`, `docs-map-dev`, `docs-map` (linked from Home), `event-life` (Architecture), `repository-layout` + `module-dependency-graph` (Layout), `windows-telemetry` (Windows overview), `run-pipeline` + `shared-runner` + `process-and-generate` (Pipeline), `event-pipeline` (Design Notes).

