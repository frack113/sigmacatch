# Windows collection

Capture-source problems specific to Windows: the kernel driver, ETW and the Event Log channels. Back to [run and git failures](run.md).

## Windows: the kernel driver is not used

**Symptom:** a build with the `driver` feature behaves like `etw` alone.

**Cause:** the driver is opened at startup on `\\.\sigmacatch`. When that fails
or the version does not match, the collector logs it and falls back — the
warnings are explicit:

- `kernel sensor not loaded — driver path disabled` (info): the device is absent,
  the `sigmacatch` service is not running;
- `kernel sensor protocol mismatch (driver <version>, collector <version>) —
  driver path disabled` (warn): driver and collector come from different
  builds.

**Fix:** load (or restart) the driver service, and rebuild driver + collector
together — the wire protocol is versioned, never mixed.

## Windows: only Event Log events, no ETW telemetry

**Symptom:** the Sysmon-schema events (EID 1/3/11/…) never appear, the channels
keep working.

**Cause:** the ETW sessions need an **elevated** token; a filtered UAC token is
refused with a clear message. A second `sigmacatch` process also owns the
session names (`sigmacatch-process`, `sigmacatch-main`) — only one instance can
run at a time.

**Fix:** start from an elevated prompt (`SeSystemProfilePrivilege`); stop the
other instance before starting a new one.

## Windows: channel not found

**Symptom:** one `error!` per missing channel, then collection continues on
the remaining channels.

**Cause:** the channel does not exist on this machine (for example no
Sysmon channel without Sysmon installed). Expected on partial installs —
nothing to fix.

## Events dropped at render/parse

**Symptom:** `warn!` lines while events are being fetched.

**Cause:** the event was fetched from the channel but could not be rendered
or parsed — typically rotated out between query and render. The event is
dropped; the run continues.
