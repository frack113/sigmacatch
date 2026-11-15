# One-shot EVTX input

The `evtx` input (feature `evtx`) is a `CollectorKind` with
`live_capture() = false`: it runs through the same shared `run()` pipeline as
the continuous collectors, in one-shot mode — enumerate `.evtx` files, parse
each event (`evtx_reader`), feed the `DetectionEngine`, then reuse the shared
`SigmahqRegression` + `SigmaRepo` machinery to write `DataFormat::Evtx`
regression data (always via the pure-Rust EVTX writer, never `EvtExportLog`)
and commit/push it to the fork.

Because `EventProducer::run()` returns when all files are exhausted, the
process self-terminates. It has no `channels()`, no interval, and no stop-file
poller. Its `EventRecordID` field is stripped per event (Event 4688 requires
absence to trigger the imaging rule). Because it is pure Rust it also builds
and runs on Linux.

The user-facing semantics (flags, commit/push, dry-run) are in
[CLI — `--evtx`](../../user/cli.md#-evtx-one-shot-evtx-input-single-run).
