# ETW events: network, DNS, registry, WMI, unloads

What the user-mode sessions map to, and how. The sessions themselves are in
[ETW](etw.md); the ids the driver owns are in [Driver events](driver-events.md).

## Routing the main session (EID 3, 22, 500)

The main ETW session is subscribed to `Kernel-Network`, `Kernel-File`,
`Kernel-Registry`, `DNS-Client`, `WMI-Activity` and `Kernel-Process` (unload
only). It routes what the driver cannot produce, and it runs **alongside** the
driver (`EventCollector::main_only`).

| Sysmon EID | ETW source | Mapping |
| --- | --- | --- |
| 3 | `Kernel-Network` 12 (TCP connect), 42 (UDP send) | `saddr`/`sport` → source, `daddr`/`dport` → destination, `Protocol` from the id |
| 22 | `DNS-Client` 3008 | `QueryName`, `QueryStatus`, `QueryResults` |
| 500 | `Kernel-Network` 15 (accept) | `saddr`/`sport` as the listening endpoint, `Initiated=false` |
| 507 | `Kernel-Process` 6 (`ImageUnload`) | `ImageName` → `ModuleName` |
| 25 | `Kernel-Process` 6, same record as 507 | emitted when the unloaded image is the process's *own* and it is still running |
| 511 | `Kernel-Process` 6, record with `ProcessID=0` | driver unload, `ModuleName` |

Two findings worth keeping:

- **The IPv4 decoder reversed the octets.** TDH hands the four bytes over in
  network order; reading them as a little-endian `u32` and formatting that as
  big-endian turned `192.168.122.157` into `157.122.168.192`. Every address in
  the committed data would have been wrong.
- **`DestinationHostname` is filled from the DNS answers** the same session
  already carries: 3008 results are cached per `(pid, address)` and looked up
  when a connection to that address is seen, which is what Sysmon does with
  its own cache. `Image` comes from the shared `ProcessTracker`, enriched on
  demand (`image_of`) so a pid first seen by a network event still resolves.

`Kernel-File` stays subscribed but unrouted: the driver covers files. Routing
happens **before** TDH decoding — the session carries dense providers whose
records are dropped, and decoding each of them was pure cost.

The image notify routine the driver registers only fires on **load**, so EID
507 comes from `Kernel-Process` `ImageUnload` (event 6, keyword `0x40`) instead;
that provider is enabled a second time on the main session for it alone. The
same record yields **EID 25** when the unloaded image is the process's own and
the process is still running (hollowing). Two filters keep the teardown out,
because ETW does not order `ProcessStop` before the unloads it explains: the
pid must not be in the exit set *and* `GetExitCodeProcess` must still report
`STILL_ACTIVE`. Measured: unmapping the image of a suspended `cmd.exe` produced
exactly one EID 25 and zero false positives across 214 unloads; without the
liveness check, four exiting processes were misreported.

A kernel image unloads with **no process** behind it (`ProcessID=0`), which is
what separates EID 511 (driver unload) from 507 (module unload); measured by
unloading the `bindflt` minifilter. Sysmon has no id for a driver unload either.

`Image` and path comparison use `GetFinalPathNameByHandleW(VOLUME_NAME_NT)`:
mapping drive letters with `QueryDosDevice` by hand silently failed, which is
what the first version did (0 detections).

## Registry (EID 12/13/14)

`Microsoft-Windows-Kernel-Registry` delivers `SetValueKey`, `DeleteValueKey`
and `DeleteKey` with an **empty `KeyName`**; only `CreateKey`/`OpenKey` carry a
path (`RelativeName`, keyed by the `KeyObject` handle) and `CloseKey` releases
it. `inputs/etw_registry.rs` keeps that handle → path cache, and
`inputs/registry_format.rs` turns the native path into the `TargetObject`
spelling rules use (`\REGISTRY\MACHINE\…` → `HKLM\…`, `\REGISTRY\USER\…` →
`HKU\…`; both spellings of the prefix appear on the wire).

`Details` on EID 13 is the value **data**, not the value name: the provider
declares `CapturedData` but delivers it empty unless the enablement carries an
`EVENT_FILTER_DESCRIPTOR` whose four-byte payload has bit `0x2` set (undocumented
— it is how Sysmon-compatible collectors get the payload, and the ~180 SigmaHQ
rules that match `Details` are written against it). `TraceSession::enable_provider`
re-enables the registry provider with that descriptor; the failure is non-fatal
and only costs `Details`.

EID 14 (rename key) has no ETW source at all: `Kernel-Registry` publishes no
rename record, and Windows exposes no user-mode rename API. It comes from the
driver's `CmRegisterCallbackEx` (`RegNtPreRenameKey`) — see
[Driver events](driver-events.md#registry-key-rename-eid-14).

Measured in the VM (`reg add` SZ/DWORD/BINARY, `reg delete /v`, `reg delete /f`):

```text
12 CreateKey    HKU\S-1-5-…\Software\sigmacatch-probe
13 SetValue     …\sigmacatch-probe\test   Details: hello world
13 SetValue     …\sigmacatch-probe\num    Details: DWORD (0x0000002A)
13 SetValue     …\sigmacatch-probe\bin    Details: Binary Data
13 DeleteValue  …\sigmacatch-probe\test
12 DeleteKey    HKU\S-1-5-…\Software\sigmacatch-probe
```

End-to-end in the VM, with the driver **and** the main session running
(`mode: windows winevt+driver+etw`): three local probe rules — one on
`registry_set` requiring both `TargetObject|contains: 'sigmacatch-e2e'` and
`Details|contains: 'cmd.exe /c calc'`, one on `network_connection` port 80,
one on `dns_query` for `www.github.com` — each matched (`match_count: 1`) and
wrote its EVTX under `sigma/regression_data`. The `Details` predicate is what
makes the registry case meaningful: a name-only field would not have matched.

**Known gap:** `Image` is resolved from the live process, so a writer that has
already exited when the record is delivered (a one-shot `reg.exe`) leaves it
absent. The fix is the pid → image cache shared with the driver, which learns
the path at process start; until then the field is missing rather than wrong.

## WMI subscriptions (EID 19/20/21)

`Microsoft-Windows-WMI-Activity` publishes the subscription traffic under the
Operational keyword (`0x4000_0000_0000_0000`). Its `5858` record carries one
free-form string:

```text
Start IWbemServices::PutInstance - root\subscription : __EventFilter.Name="probe"
```

`inputs/wmi_format.rs` parses it (method, namespace, class, `Name="…"`) and
classifies like Sysmon: `__EventFilter` → 19, any `*EventConsumer` → 20,
`__FilterToConsumerBinding` → 21, with `Created`/`Deleted` event types. A
binding exposes the `Consumer="…"` and `Filter="…"` members the WMI object path
spells. The query text and the consumer command line are **not** in the record;
they stay absent rather than being reconstructed.

Measured: creating a filter + `CommandLineEventConsumer` + binding produced 19,
20 and 21 with `Name`, `EventNamespace`, `User`, `Image` and `ProcessId`.
