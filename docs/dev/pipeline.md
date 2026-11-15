# Pipeline

The shared `run<C: CollectorKind>()` runner in `runner.rs` drives every
collector — continuous and one-shot alike. Collectors push events into an
mpsc channel; the runner runs the detection engine and the regression
generation off it.

<!-- markdownlint-disable MD033 -->
<iframe src="../media/interactive/run-pipeline.html?embed=1" loading="lazy"
        title="The run pipeline, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:846/652;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*Startup → one collector → the event loop → the 30-second generation cycle.*

## Pipeline (shared runner)

<!-- markdownlint-disable MD033 -->
<iframe src="../media/interactive/shared-runner.html?embed=1" loading="lazy"
        title="The shared runner, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:920/748;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*Startup, then one Event at a time, then the final flush — calls in order.*

Behaviour the diagram cannot show: `--dry-run` stops after building the engine
(no repo, no logs); an empty resolved channel list warns and returns; the stop
file is polled every 500 ms; `--evtx` has no 30-second interval and no
stop-file poller.

## The 30-second cycle

<!-- markdownlint-disable MD033 -->
<iframe src="../media/interactive/process-and-generate.html?embed=1" loading="lazy"
        title="process_and_generate: from alerts to one commit per rule, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:903/652;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*Alerts → write (or skip) → batches → one commit per rule; a failed commit or
push resets the branch to its pre-batch tip.*

All generation runs in `spawn_blocking` (the `Pipeline` state is moved out and returned) —
`EvtExportLog` retries never freeze collection (events keep buffering in the mpsc channel).

## One-shot variant: `--evtx`

The `evtx` input (`live_capture() = false`) reuses the shared `run()`
pipeline in one-shot mode: the enumeration of `.evtx` files exhausts
itself (mpsc sender dropped → `rx.recv()` yields `None`), with no
`channels()`, no `generate_interval`, no stop-file poller, and
`--max-runs` ignored. Ctrl+C still aborts the pass: any in-flight cycle is
dropped and the push of what was not yet committed is skipped. The
complete user-facing documentation (usage, flags, semantics) lives in
[cli.md](../user/cli.md#-evtx-one-shot-evtx-input-single-run).
