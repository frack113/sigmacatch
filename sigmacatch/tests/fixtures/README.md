# Test fixtures

## EVTX writer fixtures

The canonical binary EVTX fixtures live in `common/core/tests/fixtures/`;
`sigmacatch-core/tests/fixtures/README.md` documents their provenance,
consumers and regeneration.

## Regression-data fixtures

- `sigma/` — the single committed minimal Sigma root consumed by the
  regression check steps of the `linux` CI job (see `sigma/README.md`). The
  `.gitignore` negations (`sigmacatch/tests/fixtures/**/regression_data/`,
  `**/*.log`) keep it tracked despite the repo-wide ignore rules.

  The `linux` job derives the negative and malformed variants in
  `$RUNNER_TEMP` from this tree: it removes the Windows rule for the negative
  case, and strips the JSON trailing newline plus the canonical `info.yml`
  indentation for the `--fix` case. No duplicate trees are committed.
