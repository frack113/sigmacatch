# Fixture sigma — regression sample

Minimal committed Sigma root used by the regression check steps of the
`linux` CI job
(`.github/workflows/build.yml`) to validate `regressiondata-check` without
cloning SigmaHQ (`sigma/` is gitignored).

Contains two real regression entries, one per supported data format:

| Rule | Data file | Origin |
| ---- | --------- | ------ |
| `rules/windows/builtin/win_alert_mimikatz_keywords.yml` (06d71506-…) | `…/win_alert_mimikatz_keywords/06d71506-…evtx` + `.json` | Real Sysmon EventID 1 capture of the mimikatz atomic run on the Win11 rig VM (`SigmaCatchVm`), 2026-08-12 |
| `rules/linux/auditd/lnx_auditd_password_policy_discovery.yml` (ca94a6db-…) | `…/lnx_auditd_password_policy_discovery/ca94a6db-…log` + `.json` | Real auditd EXECVE capture of `passwd -S` on the AlmaLinux rig VM, 2026-09-11 |

## Scrub policy

Usernames are neutralized to `siguser1` (length-stable replacement so the
binary `.evtx` stays byte-valid); the Linux `info.yml` `author` field is set
to `sigmacatch`, the Windows one keeps its captured `siguser1`. Hostnames
(`SigmaCatchVm`) and raw event data are kept
byte-for-byte : the data is detection-valid only if it replays unchanged.

Rules are upstream SigmaHQ copies with their `regression_tests_path` pointing
at the entry `info.yml` below `regression_data/`.

## Regenerating

The `.log` entry is regenerable on the AlmaLinux rig with
`sigmacatch --no-default-features --features auditd,builtin`, filter config
pointing at the rule, then `passwd -S` and a graceful stop
(`touch .sigmacatch.stop`). The `.evtx` entry comes from the Win11 rig via
the `--evtx` writer.

## Derived variants

The `linux` CI job (`.github/workflows/build.yml`) copies this tree into
`$RUNNER_TEMP` and derives the negative and malformed cases there, so no
duplicate trees are committed:

- negative — the mimikatz `rules/` file is removed from the copy ; the job
  asserts non-zero exit, with and without `--ignore`.
- malformed — the mimikatz `.json` loses its trailing newline and its
  `info.yml` is reindented to 2 spaces ; the job asserts `--fix` restores
  this canonical tree byte-for-byte and leaves the committed tree untouched.