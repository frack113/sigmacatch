# Troubleshooting

Symptom → cause → fix, for the failures a run actually hits. The binary
reports each of these itself — the log line quotes the exact cause.

Start with the page that matches where the run stopped:

| Page | Covers |
|---|---|
| [Run and git failures](troubleshooting/run.md) | first run, `https://` and SSH, slow clone, pull failure, skip set, config rejected |
| [Windows collection](troubleshooting/windows.md) | kernel driver not used, ETW without elevation, missing channel, dropped events |
| [Linux collection](troubleshooting/linux.md) | no capture source (auditd, syslog, eBPF) |
