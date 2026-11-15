<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: 2026 sigmacatch contributors -->

# Sigmacatch

> ⚠️ **WIP** — under active development. APIs, config and output formats may change without notice. Not production-ready.

Real-time Sigma matcher: it captures Windows (Event Log, native ETW, kernel
driver) and Linux (auditd, syslog, Sysmon, eBPF) events, evaluates SigmaHQ
rules, and writes regression data ready for SigmaHQ pull requests.

## Documentation

**https://frack113.github.io/sigmacatch/** — source in [`docs/`](docs/).

- [Getting started](docs/getting-started.md) — build and first run
- [CLI](docs/user/cli.md), [configuration](docs/user/config.md),
  [`regressiondata-check`](docs/user/regressiondata-check.md),
  [troubleshooting](docs/user/troubleshooting.md)
- [Regression data](docs/regression_data/index.md)
- [Architecture](docs/dev/architecture.md),
  [Windows telemetry without Sysmon](docs/dev/windows/index.md),
  [Sysmon coverage](docs/dev/windows/coverage.md),
  [Build](docs/dev/build.md)

## Credits

- [SigmaHQ](https://github.com/SigmaHQ/sigma) — the rule corpus.
- [EDR Telemetry](https://www.edr-telemetry.com/) — the telemetry categories
  behind the Windows coverage comparison.
- [Archify](https://github.com/tt-a1i/archify) — the interactive diagrams.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

## License

MIT.

Version history in [CHANGELOG.md](CHANGELOG.md).
