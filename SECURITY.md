<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# Security policy

Sigmacatch is a pre-1.0 security tool: it runs next to privileged telemetry
sources (ETW, auditd/syslog) and ships a test-signed Windows kernel driver.
The collector binaries, the kernel driver and the eBPF probes are the
sensitive surface.

## Supported versions

Only the latest release receives fixes. There is no long-term support branch
before 1.0.

## Report a vulnerability

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/frack113/sigmacatch/security/advisories/new)**
(repository → *Security* → *Advisories*). Do not open a public issue or a pull
request for an unfixed vulnerability.

Please include:

- the affected version, commit and platform;
- the input or feature involved (`winevt`, `etw`, `driver`, `auditd`,
  `builtin`, `sysmon`, `ebpf`, `evtx`, the git transport, the config loader);
- the impact and, when safe, a minimal reproduction or proof of concept.

Do not attach live credentials, private keys or third-party event data.

## Scope

In scope:

- the `sigmacatch` and `regressiondata-check` binaries;
- the kernel driver (`sensor/windows/`) and the eBPF probes
  (`sensor/ebpf/`);
- parsing of untrusted input (EVTX files, event XML, syslog lines, audit
  records);
- the SSH-only git transport and the `config.yaml` loader.

Out of scope:

- the content of SigmaHQ rules — report those to
  [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma);
- the Windows test VM or the local QEMU setup;
- vulnerabilities that require an already-compromised host or an
  administrator-level attacker.

## Response

Reports are handled on a best-effort basis: acknowledgement within 7 days,
then a fix or a mitigation plan. There is no bug bounty.
