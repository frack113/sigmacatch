# CLI

`sigmacatch` is the collector binary: it captures live events (the Windows
Event Log channels next to one process source — the kernel driver when loaded,
native ETW otherwise — or every compiled Linux input in parallel) and writes
SigmaHQ regression data. The one-shot EVTX pass is the `--evtx` flag below.

The standalone validator has its own page:
[`regressiondata-check`](regressiondata-check.md). The diagnostic subcommands
(`check-filter`, `list-rules`) are in [Diagnostic subcommands](diagnostics.md).

The settings come from a single `config.yaml` in the working directory — there
is no `--config` flag. See [Configuration](config.md).

## Flags of the collector binary

```text
sigmacatch [OPTIONS]

  -a, --all-rules    Load all rules (ignore existing regression data)
  -c, --contrib      Enable push to the remote fork (neutralized by --offline)
  -o, --offline      No git operations at all (on-disk files as-is, no commit/push)
  -r, --max-runs <N> Exit after N collection cycles (0 = unlimited)
  -v, --verbose      Info-level logging on stderr
  -n, --dry-run      Read-only check: load the ./sigma rules and build the engine —
                     no data written, no git/network operation
      --author <NAME> Override the git author from config.yaml for this run
      --branch <NAME> Working branch name (default: sigmacatch/<YYYYMMDD>)
       --evtx <PATH>  Directory of EVTX files to process (one-shot evtx input;
                      fails if the `evtx` feature is not compiled in)
      --hir-cache <PATH> Persistent HIR cache file (warm-start: skip rule
                      recompilation on next run; empty = compile every run)
  --help, -h         Print help and exit
```

`--dry-run` runs **before** logger init: it creates neither `config.yaml`
nor `logs/`, skips git validation (author/email/SSH key) and only loads the
rules from `./sigma` + builds the detection engine.

## `--evtx` — one-shot EVTX input (single run)

Feature `evtx`: a `CollectorKind` with `live_capture() = false` that runs
through the **same** `run()` pipeline as the continuous collectors. It
recursively scans a directory for `.evtx` files, parses each event in pure
Rust, pushes them through the detection engine, writes SigmaHQ regression
data for every matched rule (pure-Rust EVTX writer — never `EvtExportLog`,
since static events are not in the live Event Log), then commits and pushes
per rule to the configured working branch (default `sigmacatch/<YYYYMMDD>`) on
the configured fork. Because `EventProducer::run()` returns once every file
is drained, the sender drops and the shared loop exits — one pass: read →
detect → generate → commit/push, no collection loop. A failed final upload
exits with a non-zero status.

**Usage:**

```text
sigmacatch --evtx <EVTX_PATH> [OPTIONS]

       --evtx <EVTX_PATH>  Directory of .evtx files, scanned recursively
   -v, --verbose        Info-level logging on stderr
   -h, --help           Print help and exit
```

It supports the common flags (`-a`, `-c`, `-o`, `-v`, `-n`, `--author`,
`--branch`); `-r/--max-runs` is accepted but ignored (self-terminating), and
`-n/--dry-run` keeps its read-only semantics.

The sigma repository and the regression output come from the config
(`git.sigma_repo_path`, relative paths resolved against the config file's
directory); regression data is written under
`<sigma_repo_path>/regression_data`.

## Windows: which sources run

There is no flag for this — the build and the machine decide:

| Build | Sources |
|---|---|
| `winevt` (default) | Event Log channels only |
| `winevt,etw` | Event Log channels + native ETW, no Sysmon needed |
| `winevt,etw,driver` | Event Log channels + the kernel driver when it is loaded, else native ETW |

The kernel driver (`sigmacatch/driver`, a separate test-signed build) is
detected at startup by opening `\\.\sigmacatch`, and only one process source
runs at a time so nothing is reported twice. The driver owns process, file,
image, pipe, thread and registry-rename events; the ETW main session still
supplies what only user mode can observe (network connections, DNS, WMI,
registry create/set/delete, image/driver unload).

ETW needs an **elevated token** (`SeSystemProfilePrivilege`): without it the
ETW sessions fail, the failure is logged as a warning and the Event Log
channels keep running. The Sysmon-schema events are published under the
`sigmacatch` provider / `sigmacatch/Operational` channel, so stock Sysmon
rules (`service: sysmon`) match unchanged — the coverage comparison is
[Sysmon vs sigmacatch](../dev/windows/coverage.md), the implementation
notes are [Windows without Sysmon](../dev/windows/index.md).
