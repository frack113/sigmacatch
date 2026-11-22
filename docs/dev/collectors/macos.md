# macOS collector

`MacosEsCollector` (`sigmacatch-input-macos`, aliased as
`sigmacatch::inputs::macos_es`) is the live macOS collector: the sole macOS
input, selected by `sigmacatch/src/main.rs` on macOS when the `macos` cargo
feature is built in. It implements `CollectorKind` and `EventProducer` and
runs through the [shared runner](../pipeline.md) like every other
collector. The platform context (why Endpoint Security, the entitlement
problem) is in [macOS support](../macos/index.md).

## Compilation gates

- Feature `macos` in `sigmacatch/Cargo.toml` enables the
  `sigmacatch-input-macos` crate; its `endpoint-sec` + `libc` dependencies are
  macOS-gated in that crate's `Cargo.toml`.
- `sigmacatch/src/inputs/mod.rs` exposes the crate on `feature = "macos"` —
  **not** `target_os`, because the platform-independent event model (the
  `eslogger` NDJSON parser and the field mapping) must compile and be testable
  on Linux. The ES client layer itself is `#[cfg(target_os = "macos")]` inside
  the crate.
- `main.rs::dispatch_collector()` has one arm per platform; on a given build
  exactly one platform arm is live.

## Notification kinds

| Kind | ES event | `EventType` | Sigma `category` |
|---|---|---|---|
| `Exec` | `NOTIFY_EXEC` | `exec` | `process_creation` |
| `Create` | `NOTIFY_CREATE` | `create` | `file_event` |
| `Open` | `NOTIFY_OPEN` | `open` | `file_event` |
| `Write` | `NOTIFY_WRITE` | `write` | `file_event` |
| `Rename` | `NOTIFY_RENAME` | `rename` | `file_rename` |
| `Unlink` | `NOTIFY_UNLINK` | `unlink` | `file_event` |
| `Setuid` | `NOTIFY_SETUID` | `setuid` | — (fails open) |
| `Sudo` | `NOTIFY_SUDO` | `sudo` | — (fails open) |
| `KextLoad` | `NOTIFY_KEXTLOAD` | `kextload` | `driver_load` |
| `Login` | `NOTIFY_LOGIN_LOGIN` | `login` | — (fails open) |

`Open` and `Write` are absent from `DEFAULT_KINDS`: on a live macOS system
they fire thousands of times per second and would drown the runner channel.
They stay available through `MacosEsCollector::with_kinds` for targeted
captures. Kinds without a taxonomy category stay category-less so the engine
fails open instead of pruning rules that might match them.

## Backends

| Backend | Source | When it works |
|---|---|---|
| `Native` | sigmacatch's own `endpoint-sec` client | the binary holds the Apple-granted entitlement (vendor build) |
| `Eslogger` | Apple's `/usr/bin/eslogger` (itself entitled, runs as root) | any stock machine, SIP on |
| `Auto` (default) | native first, `eslogger` fallback | a locally signed binary: AMFI kills the native client, the fallback takes over with a warning |

A native failure for any reason other than the missing entitlement is fatal
(`NativeOutcome::Fatal`) — no fallback.

## Event model

Each notification becomes a `RawNotification` (owned, built by the
macOS-only ES layer, converted to an `Event` in platform-independent code so
the field mapping is testable on any host):

| `RawNotification` field | Sigma field |
|---|---|
| `image` | `Image` |
| `command_line` | `CommandLine` |
| `parent_image` | `ParentImage` — pre-exec image of the exec'ing process (the shell that spawned the new image in a fork+exec) |
| `process_id` / `parent_process_id` | `ProcessId` / `ParentProcessId` |
| `user` / `user_id` | `User` / `UserId` |
| `target_filename` | `TargetFilename` |
| `source_filename` | `SourceFilename` (rename) |
| `driver_name` | `DriverName` (kext load) |
| `timestamp` | `UtcTime` (RFC 3339) |

The `eslogger` backend parses one NDJSON object per notification with
`RawNotification::from_eslogger_json` (pure, cross-platform). The `process`
block is the acting (pre-exec) process; typed fields per kind:

- **exec** — `event.exec.target.executable.path` → `Image`, joined
  `event.exec.args` → `CommandLine`, target audit tokens →
  `ProcessId`/`UserId`, `process.executable.path` → `ParentImage`,
  `process.audit_token.pid` → `ParentProcessId`.
- **create** — `event.create.destination` (`existing_file.path` or
  `new_path.dir.path` + `new_path.filename`) → `TargetFilename`.
- **open / write / unlink** — the target file path → `TargetFilename`.
- **rename** — `source.path` → `SourceFilename`, destination →
  `TargetFilename`.
- **setuid** — `uid` → `UserId`; **sudo** — `to_username`/`to_uid` →
  `User`/`UserId`, `command` → `CommandLine`; **kextload** —
  `identifier` → `DriverName`; **login_login** — `username`/`uid` →
  `User`/`UserId`.

When the typed payload carries no process id, uid or image, the acting
process values are used as fallback. `User` is resolved from `UserId` when
the source supplied no account name (`fill_user_from_id`, shared by both
backends).

## Regression output

- `regression_format() = DataFormat::Json`, `rule_product() = "macos"`,
  `channels() = None` (Endpoint Security has no channel resolution).
- Provider `sigmacatch-endpoint-security`, written to `info.yml`; one JSON
  document per matched event — no binary container.
- The detection view carries `product: macos` plus the `category` when the
  taxonomy has one; the raw view stays logsource-free for regression data.
- Upstream SigmaHQ has no `regression_data/rules/macos/` directory yet;
  captured sets create it.
