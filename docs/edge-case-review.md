# Edge Case Review: Continuous Collection Refactor

## Summary

Review of the refactor that converts sigmacatch from a batched cycle model
(load → collect → process → generate → sleep) to a continuous event loop
(spawn collector → select! on events/timer/shutdown → final flush).

**Severity Legend:**
- CRITICAL: Data loss, incorrect behavior, resource exhaustion, security
- HIGH: Performance degradation, resource leaks, silent failures
- MEDIUM: Suboptimal behavior, edge case gaps
- LOW: Cosmetic, minor robustness

---

## CRITICAL Issues

### 1. `Alert::record_id()` reads non-existent field `EventRecordID_num`

**File:** `crates/sigmacatch-types/src/lib.rs:512-516`

`Alert::record_id()` reads from `event_json.get("EventRecordID_num")`, but:
- The XML parser (`parse_winevt_xml`) produces `Event.System.EventRecordID` (as a number via `node_to_value`).
- The `flatten_winevt.yml` pipeline maps `EventID` → `Event.System.EventID` but does **not** add any `EventRecordID_num` field.
- The `windows.yml` pipeline does **not** add `EventRecordID_num` either.

**Result:** `Alert::record_id()` **always returns `None`**. This means:
- `evtx.rs:write_evtx` always receives `None` for `record_id`.
- `EvtExportLog` (binary EVTX export) is **never used** — always falls back to writing raw XML as `.xml`.
- Valid binary `.evtx` files are never produced on Windows.

**Fix:** Change `Alert::record_id()` to read from `Event.System.EventRecordID` (same path as `Event::record_id()`), or add a pipeline transformation that creates `EventRecordID_num`.

### 2. `EvtNext` failure causes CPU spin (no backoff)

**File:** `crates/input-windows-channels/src/collector.rs:110-116`

When `EvtNext` returns `Err`, the inner loop breaks, the query handle is closed, and the outer loop **immediately** re-queries. If `EvtNext` persistently fails (e.g., channel deleted, permission revoked, log corrupted), this creates a **tight CPU spin** with no delay.

**Scenario:** A channel like `"Microsoft-Windows-Sysmon/Operational"` is deleted or becomes inaccessible. The collector task for that channel will spin at 100% CPU indefinitely.

**Fix:** Add a delay (e.g., `std::thread::sleep(5s)`) before re-querying after an `EvtNext` error, or break out of the outer loop entirely on persistent errors.

### 3. No `MAX_EVENTS` cap — unbounded initial drain

**File:** `crates/input-windows-channels/src/collector.rs:91-99`

The old code had `MAX_EVENTS: usize = 100_000` to cap initial collection. The new code removed this cap. On startup with `last_record_id == 0`, the query is `*`, which fetches **all** events from the channel.

**Scenario:** On a production server, the "Security" channel may have millions of events. The initial `*` query will attempt to drain all of them into a 100,000-capacity mpsc channel. The `blocking_send` will block the collector thread when the channel is full, but the engine may not be able to keep up, causing:
- Multi-minute startup delay
- 100,000 events buffered in memory
- Potential OOM if the XML is large

**Fix:** Re-introduce a cap on initial drain, or use a bounded approach (e.g., limit initial query to last N events).

---

## HIGH Issues

### 4. `process_and_generate` blocks the async runtime

**File:** `sigmacatch/src/main.rs:279-326`

`process_and_generate` is called from within the `tokio::select!` loop. It performs synchronous file I/O (writing JSON, EVTX, info.yml) and git operations (committing). These are **blocking operations** that will stall the async event loop.

**Scenario:** During a 30-second generate cycle, if 500 rules match and each requires writing 3 files + a git commit, the event loop is blocked for the duration. Events arriving during this time are buffered in the 100,000-capacity channel. If the buffer fills, the collector blocks.

**Impact:** Event processing latency increases during generation. If generation takes >5s (the EvtNext timeout), events may be missed (channel fills, collector blocks, EvtNext times out on the next cycle).

**Fix:** Run `process_and_generate` in a `tokio::task::spawn_blocking` to avoid blocking the runtime, or use async file I/O.

### 5. `shutdown_rx.changed()` doesn't read the value

**File:** `sigmacatch/src/main.rs:226-229`

```rust
_ = shutdown_rx.changed() => {
    info!("Shutting down…");
    break;
}
```

`watch::Receiver::changed()` returns `Ok(())` when the value changes, but doesn't read the new value. If the `send` fails (e.g., all receivers dropped), `changed()` returns an error, but the `_` pattern ignores it.

**More importantly:** `changed()` completes when the value changes from the receiver's last-seen value. If `stx.send(true)` is called before the receiver's first `changed()` call, the receiver will see the change immediately. But if `changed()` is polled multiple times, it only completes once per change.

**Scenario:** If Ctrl+C is pressed but the select loop is busy processing events, the shutdown signal is queued. When the select next polls `shutdown_rx.changed()`, it completes. This is correct behavior.

**However:** If the shutdown signal is sent but no branch is ready in the select, the select will wait for the next ready branch. If events are flowing continuously, `rx.recv()` is always ready, and the shutdown might be delayed.

**Fix:** This is mostly correct but could use explicit value checking: `if *shutdown_rx.borrow() { break; }`.

### 6. `clean_partial_artifacts` called on every generate cycle

**File:** `sigmacatch/src/main.rs:312` (inside `process_and_generate`)

`sigmacatch_regression::clean_partial_artifacts(output_base)` is called every 30 seconds. This recursively scans the entire `regression_data/` directory tree and deletes partial artifacts.

**Scenario:** With thousands of regression directories, this full recursive scan every 30 seconds is expensive and blocks the async runtime (see issue #4).

**Fix:** Only call `clean_partial_artifacts` once at startup, not on every generate cycle.

### 7. Events buffered in engine pile between generate cycles

**File:** `sigmacatch/src/main.rs:206-208`

```rust
Some(event) = rx.recv() => {
    engine.put_events(vec![event]);
}
```

Events are accumulated in `engine.events` (a `Vec<Event>`) between generate cycles (every 30 seconds). If events arrive at a high rate (e.g., 10,000 events/second), the engine's internal pile grows unbounded between cycles.

**Scenario:** 300,000 events arrive in 30 seconds. They're all buffered in `engine.events`. When `process_events()` is called, it processes all 300,000 at once, which could take seconds and block the async runtime.

**Fix:** Consider processing events in batches (e.g., every 1000 events) rather than waiting for the 30-second timer.

---

## MEDIUM Issues

### 8. Initial `*` query floods all channels simultaneously

**File:** `crates/input-windows-channels/src/collector.rs:95-96`

When `last_record_id == 0`, the query is `*`. With 95 channels, all 95 collector tasks start with `*` queries simultaneously on startup. This creates a massive burst of event collection.

**Scenario:** 95 channels × 10,000 events each = 950,000 events in the initial burst. The 100,000-capacity channel fills immediately, and all collector tasks block on `blocking_send`.

**Fix:** Stagger the initial queries, or use a sliding window (e.g., only collect events from the last N minutes on startup).

### 9. `Event::record_id()` returns `None` for string EventRecordID

**File:** `crates/sigmacatch-types/src/lib.rs:117-124`

`Event::record_id()` uses `as_u64()`, which returns `None` if `EventRecordID` is a string. The XML parser's `node_to_value` tries `parse::<u64>()` first, so Winevt XML should produce a number. But test fixtures show `"EventRecordID": "54321"` as a string.

**Scenario:** If an event comes from a source that produces `EventRecordID` as a string (e.g., some evtx crate output), `record_id()` returns `None`, and the collector's `last_record_id` is not updated. This means the collector will re-query with `*` on the next cycle, re-fetching all events.

**Fix:** Add a `as_str().and_then(|s| s.parse::<u64>().ok())` fallback in `record_id()`.

### 10. `resolve_channels_from_collection` — category-only rules trigger all-channels fallback

**File:** `crates/sigmacatch-rule/src/channel_resolver.rs:255-257`

When a rule has `category` but no `service` (i.e., `(None, Some(category))`), the match arm `(None, _)` sets `any_without_service = true`, triggering the all-channels fallback.

**Scenario:** A Sigma rule with `logsource: { product: windows, category: process_creation }` (no `service`) will cause ALL 95 channels to be collected, even though `process_creation` only maps to the Sysmon channel.

**Fix:** Add a `(None, Some(category))` arm that tries to resolve channels from the category alone, using `build_logsource_to_channels` to find channels that match the category.

### 11. `resolve_channels_from_collection` — `product` field case sensitivity

**File:** `crates/sigmacatch-rule/src/channel_resolver.rs:235`

```rust
if rule.logsource.product.as_deref() != Some("windows") {
    continue;
}
```

This is a case-sensitive comparison. If a rule has `product: Windows` (capitalized), it's skipped.

**Scenario:** A malformed Sigma rule with `product: Windows` is silently excluded from channel resolution, potentially causing events to be missed.

**Fix:** Use `eq_ignore_ascii_case` or normalize to lowercase.

### 12. `fork_config` unused in `process_and_generate`

**File:** `sigmacatch/src/main.rs:284-285`

`_branch_name` and `_config` parameters in `process_and_generate` are unused. The `fork_config.branch_name` is passed but not used inside the function. This suggests dead code or incomplete refactoring.

**Fix:** Remove unused parameters.

### 13. `SigmaFilterConfig.product` is `Product` enum, not `String`

**File:** `sigmacatch/src/main.rs:122`

```rust
let filter = sigmacatch_rule::LoadFilter {
    product: config.sigma.product.as_str().to_string(),
    ...
};
```

The config uses `Product` enum (via `sigmacatch_config::Product` re-export), and `as_str()` converts it to a string. The `LoadFilter` then compares with `rule.logsource.product.as_deref()`. This is correct but adds an unnecessary string allocation.

**Not a bug**, just a minor inefficiency.

### 14. `generate_interval` first tick skipped but timer starts late

**File:** `sigmacatch/src/main.rs:197-198`

```rust
let mut generate_interval = tokio::time::interval(std::time::Duration::from_secs(30));
generate_interval.tick().await; // skip immediate first tick
```

The first `tick()` completes immediately (within microseconds), but the comment says "skip immediate first tick." The actual first generation happens 30 seconds after startup. This is intentional but worth noting — no regression data is generated for the first 30 seconds.

### 15. `collector_handle.await` error silently ignored

**File:** `sigmacatch/src/main.rs:236`

```rust
let _ = collector_handle.await;
```

If the collector task panics, the error is silently ignored. The final flush still runs, but any events that were in-flight in the collector are lost.

**Fix:** Log the error if `collector_handle.await` fails.

### 16. `EventCollector::run` returns `Ok(())` even when all channels fail

**File:** `crates/input-windows-channels/src/collector.rs:49-57`

The `run` method waits for all spawned tasks to complete and logs warnings for failures, but returns `Ok(())`. The caller in `main.rs:190` logs the error if `collector.run(tx).await` fails, but since it always returns `Ok`, the error is never logged.

**Fix:** Return an error if all channels failed to collect.

---

## LOW Issues

### 17. `str_to_wide` allocates on every query cycle

**File:** `crates/input-windows-channels/src/collector.rs:94-99`

```rust
let channel_wide = str_to_wide(channel);
let query_wide = if last_record_id == 0 {
    str_to_wide("*")
} else {
    str_to_wide(&format!("*[System[EventRecordID > {}]]", last_record_id))
};
```

`str_to_wide` allocates a new `Vec<u16>` on every iteration of the outer loop. The `channel_wide` is constant and could be computed once outside the loop. The `query_wide` changes only when `last_record_id` changes.

**Fix:** Move `channel_wide` outside the loop. Cache `query_wide` and only rebuild when `last_record_id` changes.

### 18. `event_handles` array re-allocated on every query cycle

**File:** `crates/input-windows-channels/src/collector.rs:109`

```rust
let mut event_handles: Vec<isize> = vec![0; 32];
```

A new 32-element `Vec` is allocated on every outer loop iteration. This could be moved outside the loop and reused.

### 19. `generate_interval` uses `tick()` which can drift

**File:** `sigmacatch/src/main.rs:197`

`tokio::time::interval` with `tick()` has a drift correction feature, but if the select loop is blocked (see issue #4), the interval can drift significantly.

### 20. No graceful shutdown of `process_and_generate` in progress

**File:** `sigmacatch/src/main.rs:204-231`

If Ctrl+C is received while `process_and_generate` is running (in the timer branch), the shutdown is delayed until `process_and_generate` completes. There's no cancellation mechanism.

### 21. `SigmaRule.logsource.product` comparison uses `as_deref()`

**File:** `crates/sigmacatch-rule/src/channel_resolver.rs:235`

```rust
if rule.logsource.product.as_deref() != Some("windows") {
```

This is correct but `Some("windows")` creates a `&str` comparison. If `product` is `Some("Windows")`, this would fail. This is the same issue as #11.

### 22. `Event::record_id()` uses `as_u64()` which fails for `i64` overflow

`as_u64()` returns `None` for negative numbers or numbers that don't fit in `u64`. Since `EventRecordID` should always be positive, this is not a practical issue.

### 23. `build_logsource_to_channels` — `unwrap_or_default()` for missing category

**File:** `crates/sigmacatch-rule/src/channel_resolver.rs:159-162`

```rust
CHANNEL_EVENT_TO_CATEGORY
    .get(key)
    .copied()
    .unwrap_or_default()
```

If a subcategory key exists in `CHANNEL_EVENT_TO_SUBCATEGORY` but not in `CHANNEL_EVENT_TO_CATEGORY`, `unwrap_or_default()` returns `""` (empty string). This creates a parent key like `"sysmon:"` which won't match anything in the `merged` map. The subcategory's channels are still added to `category_targets` under the `subcat_key`, but the parent entry is silently lost.

**Scenario:** A future subcategory entry without a corresponding category entry would create a malformed parent key.

### 24. Non-Windows stub `collect_channel` silently does nothing

**File:** `crates/input-windows-channels/src/collector.rs:275-278`

On non-Windows, `collect_channel` is a no-op. The `EventCollector::run` method spawns tasks that immediately return. The 30-second generate timer fires with no events, and `process_and_generate` returns an empty vec. This is correct but means the tool is non-functional on Linux/macOS.

### 25. `EventCollector::new` doesn't validate channels

**File:** `crates/input-windows-channels/src/collector.rs:28-30`

No validation of channel names. Invalid channel names will fail at `EvtQuery` time, which is handled (warning + return). This is acceptable.

---

## Race Conditions & Concurrency

### 26. Race between `rx.recv()` and `drop(rx)` on shutdown

**File:** `sigmacatch/src/main.rs:233-236`

```rust
drop(rx);
let _ = collector_handle.await;
```

When `rx` is dropped, the collector's `tx.blocking_send()` will fail. But if an event was already in the channel buffer, it might be lost (the `rx.recv()` in the select loop was broken out of, so any events remaining in the channel are dropped when `rx` is dropped).

**Scenario:** Event arrives in the channel just before Ctrl+C. The select breaks on `shutdown_rx.changed()`. The event remains in the channel buffer. `drop(rx)` drops the receiver without processing the event. The event is lost.

**Impact:** At most a few events are lost during shutdown. This is acceptable for a continuous monitoring tool.

### 27. `engine` shared state between select and `process_and_generate`

The `engine` is borrowed mutably by `process_and_generate`. The select loop borrows it mutably for `engine.put_events()`. Since `process_and_generate` is called synchronously (not concurrently), there's no data race. The select loop is not running while `process_and_generate` executes (it's in the same branch).

**This is correct.**

### 28. `shutdown_tx` dropped before `shutdown_rx` in some paths

**File:** `sigmacatch/src/main.rs:173-174`

```rust
let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
let stx = shutdown_tx.clone();
```

`shutdown_tx` is kept alive in the main function scope. `stx` (a clone) is moved into the Ctrl+C handler. When the main function exits, `shutdown_tx` is dropped. But `stx` is still alive in the spawned task. The `watch` channel stays alive until all senders are dropped.

**This is correct** — the channel stays alive until the Ctrl+C handler completes.

---

## Resource Leaks

### 29. Event handles leaked on `EvtRender` failure in `render_event`

**File:** `crates/input-windows-channels/src/collector.rs:222-272`

In `render_event`, if the first `EvtRender` call fails (not `ERROR_INSUFFICIENT_BUFFER`), the function returns `None`. But the event handle passed to `render_event` is closed by the caller:

```rust
unsafe {
    let _ = EvtClose(event_handle);
}
```

This is correct — the caller always closes the event handle. Good.

### 30. Query handle leak on `EvtQuery` failure

**File:** `crates/input-windows-channels/src/collector.rs:101-107`

If `EvtQuery` fails, the function returns immediately. No query handle was created, so no leak. Good.

### 31. Query handle closed but inner loop might not close all event handles

**File:** `crates/input-windows-channels/src/collector.rs:145-157`

When `tx.blocking_send` fails:
```rust
if tx.blocking_send(event).is_err() {
    unsafe {
        let _ = EvtClose(event_handle);
        let _ = EvtClose(query_handle);
    }
    return;
}
```

The current event handle and query handle are closed. But event handles at indices `i+1..events_fetched` are **not closed** — they're still open. The `return` exits the function, and these handles are leaked.

**Scenario:** 32 events fetched, 5th event's `blocking_send` fails. Events 6-32 (27 handles) are leaked.

**Fix:** Close all remaining event handles before returning.

### 32. COM guard drops after `return` in `collect_continuous`

**File:** `crates/input-windows-channels/src/collector.rs:83-89`

The `ComGuard` is created at the start of `collect_continuous`. When the function returns (for any reason), the guard is dropped, calling `CoUninitialize`. This is correct.

---

## XPath Safety

### 33. XPath query uses `format!` with `u64` — safe from injection

**File:** `crates/input-windows-channels/src/collector.rs:98`

```rust
str_to_wide(&format!("*[System[EventRecordID > {}]]", last_record_id))
```

`last_record_id` is a `u64`, which can only produce valid numeric strings. No XPath injection risk. Good.

### 34. `write_evtx` XPath also uses `u64` — safe

**File:** `crates/sigmacatch-regression/src/evtx.rs:30`

```rust
let query = format!("*[System[EventRecordID={}]]", rid);
```

`rid` is `u64`. Safe from injection. Good.

---

## Summary Table

| # | Issue | Severity | File |
|---|-------|----------|------|
| 1 | `Alert::record_id()` reads non-existent `EventRecordID_num` field | CRITICAL | sigmacatch-types/src/lib.rs:512 |
| 2 | `EvtNext` failure causes CPU spin (no backoff) | CRITICAL | collector.rs:110-116 |
| 3 | No `MAX_EVENTS` cap — unbounded initial drain | CRITICAL | collector.rs:91-99 |
| 4 | `process_and_generate` blocks async runtime | HIGH | main.rs:279-326 |
| 5 | `shutdown_rx.changed()` doesn't check value | HIGH | main.rs:226-229 |
| 6 | `clean_partial_artifacts` on every generate cycle | HIGH | main.rs:312 |
| 7 | Unbounded event buffering in engine pile | HIGH | main.rs:206-208 |
| 8 | Initial `*` query floods all 95 channels | MEDIUM | collector.rs:95-96 |
| 9 | `Event::record_id()` fails for string EventRecordID | MEDIUM | sigmacatch-types/src/lib.rs:117 |
| 10 | Category-only rules trigger all-channels fallback | MEDIUM | channel_resolver.rs:255 |
| 11 | Case-sensitive `product` comparison | MEDIUM | channel_resolver.rs:235 |
| 12 | Unused `fork_config` params in `process_and_generate` | MEDIUM | main.rs:284-285 |
| 31 | Event handles leaked on `blocking_send` failure | CRITICAL | collector.rs:136-141 |
| 26 | Events lost on shutdown (channel buffer dropped) | LOW | main.rs:233-236 |
