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

---

## 5. Optimize DetectionEngine

**Status:** current engine loads all rules into `rsigma-eval` `Engine`, then evaluates each event against the full rule set in a single loop.

**What's missing:**
- Index rules by `logsource` (product, service, category) to avoid loading non-relevant rules
- Per-event: only push events whose logsource matches at least one loaded rule's `logsource` — skip evaluation entirely for irrelevant rules
- Rule pre-filtering: build a fast lookup table from rule metadata → logsource keys before engine creation
- `rsigma-eval` V2 pipeline: `rsigma-eval 0.30` supports `set_pipeline` to switch pipelines dynamically — could route events to specialized engines (e.g. Sysmon-only, network-only)
- Parallel evaluation: `rayon` or `crossbeam` to spread events across multiple engine instances during `process_events`
- Rule compilation caching: avoid recompiling the same rule for every event — use `rsigma-eval`'s internal caching

**Use case:** faster evaluation cycles with hundreds of Sigma rules, reduced memory footprint by avoiding unnecessary rule loading.

---

## 6. Git SSH Transport

**Status:** ✅ implemented. Configurable via `config.yaml` → `git.transport` (`http` or `ssh`).

**Implementation:**
- `GitTransport` enum: `Http` (default) or `Ssh`
- `GitConfig` struct: `transport` + `ssh_key_path: Option<String>`
- `get_ssh_shell_command()` resolves SSH command with priority: `GIT_SSH_COMMAND` env > `GIT_SSH` env > `ssh_key_path` config > default `ssh`
- `get_ssh_command()` builds `ssh -i <key>` when a key path is provided
- `fetch_remote_ssh()`: creates `SshTransport::with_shell_command()`, fetches via `grit_lib::fetch::fetch_remote()`
- `push_branch_ssh()`: pushes via `SshTransport::with_shell_command()` with `grit_lib::push::push_remote()`
- `https_to_ssh_url()`: converts `https://github.com/user/sigma.git` → `git@github.com:user/sigma.git`
- `git_clone_ssh()`, `git_pull_ssh()`, `git_push_ssh()` in `repo.rs` dispatch SSH operations
- `SigmaRepo` carries `git_config` and dispatches clone/fetch/push based on `GitTransport`
- `github_token` is **optional** when `transport: ssh` — validation skipped in `Config::validate()`
- `~/.ssh/config` should have `IdentityFile` for `github.com` for seamless key resolution

**Limitations:**
- `push_remote` via SSH is limited to protocol v0/v1 (GitHub supports this for forks)
- No `known_hosts` management — relies on `ssh -o StrictHostKeyChecking` or default SSH behavior
- `git config --global user.name` and `user.email` must be set for commits
- Fork detection still uses HTTP HEAD to check fork existence

**Example config:**
```yaml
git:
  transport: ssh
  ssh_key_path: "/home/user/.ssh/id_sigmacatch"
```


