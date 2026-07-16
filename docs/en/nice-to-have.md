# Nice-to-have — Future Features

Features identified as useful but out of current scope. No timeline — documented for reference.

---

## 1. Offline Mode

**Status:** not implemented. App always clones/fetches from GitHub on startup.

**What's missing:**
- `--offline` flag to use existing sigma/ repo without network fetch
- Bundled SigmaHQ rules shipped with the binary (via `include_bytes!` or shipped file)
- Zero network dependency — binary works on air-gapped machines

**Use case:** classified/isolated environments, network-less CI, reproducible builds.

---

## 2. No-Contrib Mode

**Status:** contrib is now **always active** — fork detection, branch, commit, push run every cycle. The `contrib` option has been removed from config.

**What's missing:**
- `--no-contrib` flag or config option to disable contrib workflow (local upstream clone only)
- `regression_tests_path` is still appended to rule YAML files — could be optional

**Use case:** internal usage, rule auditing, data generation without contributing upstream.

---

## 3. Linux Support

**Status:** collector is a stub (empty `Vec`) — pipeline runs end-to-end for testing but collects nothing.

**What's missing:**
- Linux event collector: `journald` (systemd), `syslog`, or `auditd`
- Sigma logsource → Linux channel mapping (SigmaHQ rules have `logsource.product: linux`)
- Engine already evaluates Linux rules, but without events they never match
- Possible correlation with tools like `osquery`, `auditd`, or `falco`

**Use case:** Linux servers, containers, cloud environments.

---

## 4. Sigma Correlation V2

**Status:** `rsigma-eval` engine supports V2 correlation rules, but the pipeline doesn't handle them explicitly.

**What's missing:**
- Correlation rules (`correlation` type in Sigma V2) require keeping multiple events in memory before deciding
- Current pipeline evaluates each event individually — no temporal buffer
- Need a stateful evaluator that accumulates events per `correlation_rule` and triggers when conditions are met
- Time window (`timespan`) and threshold (`field` count) management

**Use case:** multi-step attack detection, brute force, behavioral anomalies.
