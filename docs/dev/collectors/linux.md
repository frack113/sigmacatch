# Linux collectors

Each collector is guarded by its source; no source available → the collector
bails at startup.

- **auditd** — when `/var/log/audit/audit.log` exists: tail,
  linux-audit-parser parsing, grouping by event id `timestamp:sequence`,
  logsource `product:linux, service:auditd`.
- **builtin syslog** — tails every existing file among central
  (`/var/log/messages`, `/var/log/syslog`), authpriv (`/var/log/secure`,
  `/var/log/auth.log`) and cron (`/var/log/cron`, `/var/log/cron.log`):
  RFC3164 lines, service derived from the program tag (fallback per file group:
  authpriv → `auth`, cron → `cron`). Lines tagged `sysmon` are excluded
  (handled by the dedicated collector).

The `sysmon` and `ebpf` features add a dedicated collector:

- **Sysmon eBPF (feature `ebpf`)** — embedded Aya probes
  (`driver/ebpf`, nightly+bpf-linker, excluded from workspace). Coverage includes
  process creation/termination (EID 1/5), writes (EID 2, regular files only), network
  connect/accept/listen (EID 3/500), image load (EID 6), process access (EID 10), file
  create/delete (EID 11/23), pipe creation (EID 17), DNS query/response (EID 22/508),
  process tampering (EID 25), and extensions 501-507 for credential/capability changes,
  rename/chmod/chown/truncate and module unload. Events are rendered as nested
  Sysmon-shaped JSON, mapped through the Linux field pipeline and injected via the same
  engine. Fork lineage, `accept(NULL)`, `recvfrom(NULL)` and `execveat(AT_EMPTY_PATH)` are
  handled explicitly. Runtime requirements: root or CAP_BPF+CAP_PERFMON (refuses to start
  otherwise — `sigmacatch/src/orchestrators/linux.rs` bails) + kernel with BTF. SHA256 hashing of images is calculated
  userspace with cache (path,mtime). The probe embeds an `EVENTS_ABI_V2` marker; a prebuilt
  `SIGMACATCH_EBPF_OBJECT` without it is rejected. A failed probe load at runtime warns and
  continues **without** any sysmon source; only a build with both `ebpf` and `sysmon`
  features falls back to the Sysmon-for-Linux syslog tail.
- **Sysmon-for-Linux tail (feature `sysmon`)** — central syslog
  lines tagged `sysmon` whose body is winevt XML (`parse_winevt_xml`/`_raw`) → logsource
  `product:linux, service:sysmon` via channel `Linux-Sysmon/Operational`. Read-only, no
  Aya dependency.

## Shared tail driver

The `sigmacatch-input-tail` crate (`collector/tail/src/lib.rs`) is the
shared tail driver for the Linux file collectors (auditd, builtin syslog,
sysmon): it owns the file handle, the 100 ms poll loop, rotation
detection (dev/ino change → re-open from offset 0) and the channel, and drives a
pure `LineHandler` per collector. Each `LineHandler` turns whole lines into
events (`auditd` groups records by event id and flushes on sequence change or
idle poll; `syslog` emits one event per RFC3164 line, excluding `sysmon` lines;
`sysmon` parses XML bodies, skipping truncated ones). Gated on the tailing
features.
