# User-mode ETW collector

Feature `etw`, Windows only. Two realtime trace sessions feed
`etw_event::decode`, and the decoded records are rendered as Sysmon-schema
events (`etw_sysmon`) and injected into the normal Windows pipeline. No Sysmon,
no driver.

```text
sigmacatch/inputs/etw/src/         # sigmacatch-input-etw
└── lib.rs            # sessions + callback loop (the ebpf.rs analogue)

sigmacatch/inputs/etw-common/src/  # sigmacatch-input-etw-common
├── etw_event.rs      # TDH property → typed fields
├── etw_process.rs    # live-process facts (CommandLine, User, parent, creation)
├── etw_registry.rs   # Kernel-Registry handle → path cache
├── etw_sysmon.rs     # Sysmon-schema rendering (provider/channel `sigmacatch`)
├── registry_format.rs / wmi_format.rs / pe_format.rs
└── nt_file.rs / signature.rs / version_info.rs

sigmacatch/src/inputs/windows.rs   # orchestrator: channels + one process source
```

- **Rendering**: unlike eBPF (nested JSON, Linux), produce Sysmon-shaped data
  and feed the existing Windows pipeline through `Event::from_xml_injected` —
  the whole Windows path (`1_win_logsource.yml`, `parse_winevt_xml`) is already
  built around winevt XML.
- **Regression format**: `DataFormat::Evtx` (these are Windows events), reusing
  the pure-Rust EVTX writer — not `Json` as eBPF uses.
- **Dispatch**: `main.rs` sends Windows to `inputs::windows`, which runs the
  orchestrator (channels + exactly one process source).
- **Privileges**: requires an elevated token (`ensure_privileges`); without it
  the ETW source fails with a clear message and the channels keep running.

The driver client (`sigmacatch-input-etw-driver`), the shared helpers in
`sigmacatch-input-etw-common` and the kernel crate are in
[Kernel driver](driver.md).

## Session design

From Rustinel's findings (each a numbered regression in their repo), adapted to
our mission:

- **Two sessions**: a low-latency Kernel-Process session and a burst-tolerant
  main session (both 256 KiB buffers with an explicit pool: 128/256 and 40/160 in
  `SessionConfig::PROCESS` / `MAIN`). The split exists because a large buffer
  delays delivery past a short-lived process's exit (#349); for regression data
  the same race costs us *complete* command lines, not just real-time alerts.
- **No per-processor buffering**: event order is load-bearing (path pairing).

## Inherited invariants (encode as tests)

Each is a bug Rustinel fixed the hard way; our `etw.rs` encodes it as a test:

1. **Buffer sizing** (#312): `ferrisetw`'s defaults lost 12-60 % of process
   starts under a fork tree. We set buffer size/count explicitly.
2. **Process-session latency** (#349): small buffers or command-line back-fill
   misses short processes.
3. **Registry keywords** (#279): off-by-a-nibble keywords subscribe to reads
   and silently miss every value write. Verify each keyword against the
   manifest.
4. **`IntegrityLevel`** (#294): not a Kernel-Process property; it is the
   `MandatoryLabel` SID on ProcessStart.
5. **Command-line truncation** (#306): the process flusher is required, else
   short-lived capture falls to ~16 %.

## Provider behaviour

Measured on the test VM (full measurements in
[Measurements](evidence.md#etw-provider-measurements)). Four findings
shape the code:

- **Registry paths are not NT paths.** `RelativeName` is a full NT path only
  when the base object is a root; otherwise it is relative to the base key and
  must be rebuilt through the `BaseObject`/`KeyObject` chain. Emit
  `TargetObject` only when the chain resolves to a root, never as a guessed
  `HKLM\...` mapping.
- **The classic kernel logger needs the system-logger bit.** `EVENT_TRACE_REAL_TIME_MODE`
  alone starts the session, delivers its configuration events and then goes
  silent; `EVENT_TRACE_SYSTEM_LOGGER_MODE` makes live process events flow.
- **TDH does not decode classic (MOF) kernel events.** They arrive with the
  Process MOF provider GUID and `EventID 0`; `TdhGetEventInformation` returns
  the `MSNT_SystemTrace` generic template, not the `CommandLine` fields
  `tracerpt` shows. Command lines and SIDs therefore need a hand-written MOF
  parser or the live-process PEB back-fill.
- **Keyword filtering suppresses the events we need.** Enabling
  `Microsoft-Windows-Kernel-Process` with its manifest keywords (`0x10 | 0x40`)
  delivers `ImageLoad` but **no** `ProcessStart`; only a keyword-less
  subscription (level `Verbose`) delivers the process lifecycle. DNS-Client
  behaves the same way: 3006/3008 carry keyword `0`, so the
  Operational-channel mask never receives them.

**Process creation (EID 1) does not come from ETW.** In realtime mode,
`ProcessStart`/`ProcessStop` are delivered for long-lived processes only: five
`cmd /c ping` runs produced zero `ProcessStart` records in a 20 s window, while
a concurrent `logman` file-mode session on the same provider captured 34/34.
EID 1 is therefore built from the **live process**, which is also the only
source of `CommandLine` and `User`:

- `QueryFullProcessImageNameW` → `Image`;
- `NtQueryInformationProcess(ProcessCommandLineInformation)` → `CommandLine`;
- `NtQueryInformationProcess(ProcessBasicInformation)` → `ParentProcessId`;
- `GetProcessTimes` → `UtcTime` (the real creation time, not our observation
  time);
- the process token → `User`, `UserSid`, `IntegrityLevel`.

The trigger is a 50 ms Toolhelp snapshot with ETW events from an unknown PID as
the fast path; a process is only reported when its creation time falls inside
the capture, so nothing pre-existing is invented. Sysmon-only enrichments that
cannot be sourced exactly (`ProcessGuid`, `LogonGuid`, `Hashes`, ...) are
omitted rather than approximated.

Events the sessions produce (routing, registry, WMI) are in [ETW events](etw-events.md).
