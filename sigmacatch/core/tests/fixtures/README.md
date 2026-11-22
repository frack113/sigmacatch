# Core EVTX fixtures

Copies of the writer fixtures in `../../tests/fixtures/` so `sigmacatch-core`
owns the data its unit tests embed via `include_str!`/`include_bytes!` and
`CARGO_MANIFEST_DIR`. The `sigmacatch-input-evtx` adapter keeps its own copy of
`sample.evtx` too; regenerate all three copies together when the encoder byte
layout changes.
