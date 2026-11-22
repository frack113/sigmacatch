# Test fixtures

## EVTX writer fixtures

The golden EVTX fixtures now live in `sigmacatch/core/tests/fixtures/`, with a
second copy of `sample.evtx` in `sigmacatch/inputs/evtx/tests/fixtures/`.
`core/tests/fixtures/README.md` documents their provenance and regeneration.

## Regression-data fixtures

- `sigma/`, `sigma_negative/`, `sigma_malformed/`, `sigma_malformed_reference/`
  — minimal committed Sigma roots consumed by the regression check steps of
  the `linux` CI job
  (see `sigma/README.md`). The `.gitignore` negations
  (`sigmacatch/tests/fixtures/**/regression_data/`, `**/*.log`) keep them
  tracked despite the repo-wide ignore rules.
