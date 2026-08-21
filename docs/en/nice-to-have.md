# Nice-to-have — Future Features

Features identified as useful but out of current scope. No timeline — documented for reference.

---

## 3. Linux Support

**Status:** ✅ done — `sigmacatch-auditd` collector operational (tail `/var/log/audit/audit.log`, `linux-audit-parser` parsing, event id grouping, logsource `product:linux, service:auditd, provider:auditd`). Regression data `.log` + `.json` validated on AlmaLinux VM with Atomic RedTeam.

---

## 4. Sigma Correlation V2

**Status:** `rsigma-eval` engine supports V2 correlation rules, but the pipeline doesn't handle them explicitly.

**What's missing:**

- Correlation rules (`correlation` type in Sigma V2) require keeping multiple events in memory before deciding
- Current pipeline evaluates each event individually — no temporal buffer
- Need a stateful evaluator that accumulates events per `correlation_rule` and triggers when conditions are met
- Time window (`timespan`) and threshold (`field` count) management

**Use case:** multi-step attack detection, brute force, behavioral anomalies.
