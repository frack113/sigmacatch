# Collectors

The per-input behaviour of every collector and the shared machinery they
build on. The input table and the module map are in
[Architecture](architecture.md#collectors).

## Windows logsource and PowerShell categories

Windows rules are constrained by the `1_win_logsource.yml` pipeline (`add_condition` on
EventIDs + `change_logsource` to the service): the PowerShell categories are bounded to
their EventIDs — `ps_module` (4103), `ps_script` (4104) → `service: powershell`;
`ps_classic_start` (400), `ps_classic_provider_start` (600) and `ps_classic_script` (800) →
`service: powershell-classic`. Without a `category` field injected on the event, rsigma's
`LogSourceExtractor` evaluates every event fail-open against all rules.

Classic PowerShell events (400/600/800 …) emit `<Data>` elements **without** a `Name`
attribute: the parser exposes them under positional keys (`Data0`, `Data1`, …), and
`inject_logsource_fields_for` surfaces the `EventData` content under the generic Sigma
`Data` field so `Data|contains` matching works (rsigma has no dedicated `powershell_classic`
field mapping).

## The Linux collectors

Each guarded by its source; no source available → bail:

- **auditd** — when `/var/log/audit/audit.log` exists: tail, linux-audit-parser parsing,
  grouping by event id `timestamp:sequence`, logsource `product:linux, service:auditd`.
- **builtin syslog** — tails every existing file among central (`/var/log/messages`,
  `/var/log/syslog`), authpriv (`/var/log/secure`, `/var/log/auth.log`) and cron
  (`/var/log/cron`, `/var/log/cron.log`): RFC3164 lines, service derived from the program
  tag (fallback per file group: authpriv → `auth`, cron → `cron`). Lines tagged `sysmon`
  are excluded (handled by the dedicated collector).

The `sysmon` and `ebpf` features add a dedicated collector:

- **Sysmon eBPF (feature `ebpf`)** — embedded Aya probes
  (`sigmacatch/ebpf`, nightly+bpf-linker, excluded from workspace). Coverage includes
  process creation/termination (EID 1/5), writes (EID 2, regular files only), network
  connect/accept/listen (EID 3/500), image load (EID 6), process access (EID 10), file
  create/delete (EID 11/23), pipe creation (EID 17), DNS query/response (EID 22/508),
  process tampering (EID 25), and extensions 501-507 for credential/capability changes,
  rename/chmod/chown/truncate and module unload. Events are rendered as nested
  Sysmon-shaped JSON, mapped through the Linux field pipeline and injected via the same
  engine. Fork lineage, `accept(NULL)`, `recvfrom(NULL)` and `execveat(AT_EMPTY_PATH)` are
  handled explicitly. Runtime requirements: root or CAP_BPF+CAP_PERFMON (refuses to start
  otherwise — `linux.rs` bails) + kernel with BTF. SHA256 hashing of images is calculated
  userspace with cache (path,mtime). The probe embeds an `EVENTS_ABI_V2` marker; a prebuilt
  `SIGMACATCH_EBPF_OBJECT` without it is rejected. A failed probe load at runtime warns and
  continues **without** any sysmon source; only a build with both `ebpf` and `sysmon`
  features falls back to the Sysmon-for-Linux syslog tail.
- **Sysmon-for-Linux tail (feature `sysmon`)** — central syslog
  lines tagged `sysmon` whose body is winevt XML (`parse_winevt_xml`/`_raw`) → logsource
  `product:linux, service:sysmon` via channel `Linux-Sysmon/Operational`. Read-only, no
  Aya dependency.

## `CollectorKind`

Each input defines its own `CollectorKind`
(`name()`/`mode()`/`channels()`/`build()`/`regression_format()`/`live_capture()`); the Linux
inputs share a single `LinuxCollector` defined in `linux.rs`. The regression format comes
from `regression_format()`: `DataFormat::Evtx` for the winevt/evtx inputs,
`DataFormat::Log` for Linux auditd/syslog/Sysmon-tail data, and `DataFormat::Json` for the
eBPF collector. The runner refines the format per alert, so auditd events keep `.log` even
when eBPF is active in the same binary. JSON data is a single pretty document (`type: json`)
or NDJSON for several records (`type: ndjson`). `name()` is `sigmacatch` for every input.

`live_capture()` is an intrinsic property of the collector, not a CLI flag: it defaults to
`true` and is overridden only by the `evtx` input (`false`). Continuous collectors run an
endless loop gated by the stop-file; a one-shot collector lets its `EventProducer::run()`
return, the mpsc sender drops, and `run()` exits when `rx.recv()` returns `None`.

## Shared tail driver

`tail.rs` is the shared tail driver for the Linux file collectors (auditd, builtin syslog,
sysmon): it owns the file handle, the 100 ms poll loop, rotation detection (dev/ino change →
re-open from offset 0) and the channel, and drives a pure `LineHandler` per collector. Each
`LineHandler` turns whole lines into events (`auditd` groups records by event id and flushes
on sequence change or idle poll; `syslog` emits one event per RFC3164 line, excluding `sysmon`
lines; `sysmon` parses XML bodies, skipping truncated ones). Gated on the tailling features.

## One-shot EVTX input

The `evtx` input (feature `evtx`) is a `CollectorKind` with `live_capture() = false`: it runs
through the same shared `run()` pipeline as the continuous collectors, in one-shot mode —
enumerate `.evtx` files, parse each event (`evtx_reader`), feed the `DetectionEngine`,
then reuse the shared `SigmahqRegression` + `SigmaRepo` machinery to write `DataFormat::Evtx`
regression data (always via the pure-Rust EVTX writer, never `EvtExportLog`) and commit/push
it to the fork. Because `EventProducer::run()` returns when all files are exhausted, the
process self-terminates. It has no `channels()`, no interval, and no stop-file poller. Its
`EventRecordID` field is stripped per event (Event 4688 requires absence to trigger the
imaging rule). Because it is pure Rust it also builds and runs on Linux.
