# Linux telemetry

sigmacatch captures four independent Linux event streams and matches each of
them against the same SigmaHQ ruleset as Windows and macOS. None of them needs
a driver or a signed binary: auditd and syslog are tailed from files, and the
Sysmon-shaped sources come either from eBPF probes or from a Sysmon-for-Linux
syslog tail.

| Source | Feature | Read from | Regression format |
|---|---|---|---|
| auditd | `auditd` | `/var/log/audit/audit.log` | `.log` |
| builtin syslog | `builtin` | central, authpriv and cron log files | `.log` |
| Sysmon eBPF | `ebpf` | kernel probes (Aya) | `.json` |
| Sysmon-for-Linux tail | `sysmon` | syslog lines tagged `sysmon`, winevt XML bodies | `.log` |

Each collector is guarded by its source: a missing log file, or a failed eBPF
probe load, leaves that source out instead of failing startup. The full
specification — tailed paths, guards, parsing, field mapping and the eBPF
coverage list — is in [Linux collectors](../collectors/linux.md).

## Where the code lives

- `sigmacatch/src/orchestrators/linux.rs` holds `LinuxCollector`, the shared
  orchestrator; `sigmacatch/src/orchestrators/mod.rs` aliases the leaf crates.
- `sigmacatch-input-auditd`, `sigmacatch-input-syslog` and
  `sigmacatch-input-sysmon` parse their respective streams;
  `sigmacatch-input-tail` is the shared 100 ms poll/rotate tail driver.
- The eBPF probe lives in `sensor/ebpf` (nightly + bpf-linker, excluded from
  the workspace). It needs root or `CAP_BPF`+`CAP_PERFMON` and a kernel with
  BTF; a prebuilt object without the `EVENTS_ABI_V2` marker is rejected.

The collector contract shared by all inputs is in
[Collectors](../collectors/index.md); the pipeline that consumes these
producers is the same for every input; see [Pipeline](../pipeline.md).

## Validation

The AlmaLinux 10 test VM is the box where real auditd events, rule loading and
regression output get checked end to end — the Linux analogue of the
[Windows](../windows/vm.md) and [macOS](../macos/vm.md) dev VMs. See
[Linux dev VM](vm.md) for what is on it and how a validation run goes.

The committed regression fixtures include one real auditd EXECVE capture of
`passwd -S` made on that VM; its origin and regeneration steps are documented
in `sigmacatch/tests/fixtures/sigma/README.md`.

Build commands for the Linux features are in [Build — Linux](../build.md#linux).
