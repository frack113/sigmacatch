# Design Notes

The "why" behind the moving parts: graceful shutdown, the skip set, output
layout, collector observability and the memory model.

## Stop file

`config.stop_file` (default `.sigmacatch.stop`) is polled every 500 ms;
when the file exists, collection stops gracefully (drain + flush + commit of the
in-flight cycle) — the signal used to end a continuous (`-r 0`) run without a hard
kill that would lose the cycle's regression data.

## Skip set

**Skip set** = `HashSet<Uuid>` from `SigmahqRegression::get_sigma_id()` (existing info.yml + valid data)
∪ `SigmaRepo::pending_regression_rule_ids()` (trees of remote `sigmacatch/*` branches:
unmerged pending PRs — a fresh VM does not re-capture their data), built once at startup.
`--all-rules` disables it. After generation a rule is retired and the engine is reloaded in
one batch (`engine.reload_rules`). Rules whose committed data is invalid (broken EVTX / empty text)
are excluded from the skip set → regenerated.

## Output always in the sigma repo

`<sigma_repo_path>/regression_data/<rule_rel_path>/`
(`info.yml` + data file `.evtx`/`.log`/`.json`; `.json` is optional only for EVTX/log data),
committed to the fork if
`contrib` (local commits otherwise). The rule's repo path is mirrored relative to the
configured `sigma_repo_path` (absolute or relative) — the per-rule commit also carries the
rule yaml updated with `regression_tests_path: regression_data/<rule_rel_path>/info.yml`.
The full set format is specified in
[Regression data](../regression_data/index.md).

## Collector observability

The collector excludes non-existent channels once on
`ERROR_EVT_CHANNEL_NOT_FOUND` (single `error!`); each live channel logs "initial query OK"
then a "still alive" heartbeat (60s); `warn!` when events are fetched but dropped at
render/parse. The Linux collectors detect tail-file rotation (inode change) and re-open
the file; the builtin syslog collector excludes lines tagged `sysmon` to avoid double
capture (handled by the dedicated Sysmon-for-Linux collector).

## Memory: `Arc`-shared payloads + single-pass parse

The payload fields of
`Event` and `Alert` (`event_json_raw`, `event_json`, `event_raw`,
`event_json_raw_all`) are `Arc`-shared — cloning an event (per rule match in
the detection engine, per channel hand-off) is a reference-count bump, not a
deep copy of the JSON tree. `parse_winevt_xml_both` parses the Winevt XML once
(raw view for regression + transformed view for detection), and
`Event::from_xml_injected`/`new_injected` inject the logsource fields
(`product`/`service`/`category`) into the detection view **before** the
payload is `Arc`-shared: the per-event path pays for one parse and no deep
clone of the transformed tree. Measured on a constant-volume live stream:
−47 % working set on Windows (247→130 MB) and −19 % RSS on Linux
(~204→164 MB). Diagram:
[event-pipeline.webm](../media/event-pipeline.webm) (animation)
and [event-pipeline-dark.svg](../media/event-pipeline-dark.svg)
(static, dark theme).
