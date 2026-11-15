# Linux collection

Capture-source problems specific to Linux. Back to [run and git failures](run.md).

## No capture source (Linux)

**Symptom:** startup bail when no compiled input has a source available.

**Cause:** each Linux collector is guarded by its source — the auditd
collector needs `/var/log/audit/audit.log`, the builtin syslog collector
needs one of the central/authpriv/cron files, the Sysmon tail needs
`sysmon`-tagged lines in central syslog.

**Fix:** start the source (auditd, syslog) or compile a feature whose
source exists. The eBPF collector additionally needs root or
`CAP_BPF`+`CAP_PERFMON` and a kernel with BTF — it refuses to start
otherwise. A build with both `ebpf` and `sysmon` falls back to the
Sysmon-for-Linux syslog tail when the probe fails to load; a build without
`sysmon` then runs auditd/syslog with no sysmon source.
