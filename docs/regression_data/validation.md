# Validation

What makes a set valid — and what
[`regressiondata-check`](../user/cli.md#regressiondata-check-regression-validation-cross-platform)
enforces when it replays every stored event through the detection engine.

## rule_id consistency

The same UUID must appear in `rule_metadata[0].id` of `info.yml` and in the
name of every present data file. If these values diverge, the set is
inconsistent.

## Completeness

A set is **complete** if:

- `info.yml` exists
- the data file referenced by `regression_tests_info[0].path` exists and is valid (EVTX magic / non-empty text, size ≤ 64 MiB)

For an EVTX/log data set, an auxiliary `.json` is not part of the validity
check. For eBPF, the `.json` named by `path` is the data file and must be
valid.

## `type` must describe the data file

`regression_tests_info[0].type` qualifies the file named by
`regression_tests_info[0].path` — nothing else. Accepted values are `evtx`,
`log`, `json`, `ndjson` and `raw`. `json` means one JSON document; `ndjson`
means one compact JSON object per line.

For EVTX/log data, enabling `regression.add_json_output` never changes
`type`. `type: ndjson` over an `.evtx` path is not a valid combination and is
resolved from the data-file extension. `type: ndjson` over a `.json` path is
the normal multi-record eBPF layout.

> **SigmaHQ spec vs sigmacatch extensions.** The upstream regression spec
> defines only four `type` values — `evtx`, `json`, `ndjson` and `jsonl` — and
> its runner skips every other value as an unknown test type. `log` and
> `raw` are sigmacatch extensions: entries declaring them validate and replay
> with `regressiondata-check`, but the upstream runner cannot read them.
> `regressiondata-check` reports the gap without failing the run, one line
> per distinct type:
>
> ```text
> [WARN] 12 test(s) declare type 'log', a sigmacatch extension outside the SigmaHQ regression spec (evtx/json/ndjson/jsonl); the upstream runner skips them
> ```

When `type` is unrecognised, readers infer the format from the data file's
extension rather than defaulting, so already-committed sets survive a bad
`type`. A `type` that is recognised but disagrees with the extension on disk
is reported as a warning.

## info.yml format validation

For an `info.yml` to be valid:

1. The file must be UTF-8 (BOM allowed)
2. The `rule_metadata` field must be a non-empty sequence
3. `rule_metadata[0].id` must be a parseable UUID; a hard error is raised only on unparsable values. Non-v4 or non-lowercase-canonical (`8-4-4-4-12`) ids are accepted with a warning — upstream SigmaHQ ships such ids and their regression entries must not be dropped
4. The root `id` in the YAML (instance ID) is ignored for rule_id validation

Unparsable `info.yml` files are skipped with a warning (never silently) so
they cannot fall out of the skip set unnoticed.

## Naming validation

- The parent directory name is **never** validated against the rule_id
- Data files must be named exactly `<rule_id>.<ext>`
- Hidden files (starting with `.`) are ignored
