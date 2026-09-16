# Changelog

All notable changes to box-audit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — entries are
grouped by kind, not by PR, and are written for the person deciding
whether to upgrade.

## [0.7.0] - unreleased

### Added

- **Property-test suite** (`test/properties/`, issue #16, part of the
  #14 three-tier test model). One bash test file per check family — the
  ten families named in the issue: `resources.disk_high`,
  `resources.swap_high`, `resources.load_high`, `security.ssh_fails`,
  `security.new_port`, `system.failed_units`, `updates.upgradable`,
  `maintenance.apt_cache_stale`, `maintenance.timer_drift`,
  `integrity.change`. Each asserts a real invariant: schema membership,
  delta semantics over the script's actual `--replay --diff` path
  (added/removed/presence-based stability), or fixture-corpus integrity.
  Shared `assert.sh` helpers (`assert_eq`, `assert_grep`, `assert_exit`)
  mirror the smoke suite's style; `run.sh` orchestrates and exits
  non-zero on aggregate failure. Plain bash + python3 only — no new
  interpreter, no `jq`, no `bats`.
- `test/properties/live/audit-agreement.sh` — opt-in suite that runs one
  full `--json` audit and asserts its findings agree with independently
  sampled ground truth (threshold iff-and-only-if per family, severity
  classes, non-root integrity degradation). Excluded from `run.sh`
  because a single audit costs ~7s on a box with broad NOPASSWD sudo —
  over the suite's 5-second budget. T03's seeded container is expected
  to promote this to fixture-driven CI.
- **Fixture corpus** under `test/fixtures/` — one file per external tool
  the script parses: `fail2ban-status.txt`,
  `journalctl-ssh-auth-fail.txt` (plus empty variant), `ss-tln.txt`,
  `df-output.txt`, `loadavg.txt` (plus high variant), `swap.txt` (plus
  high variant), `apt-update-stamp-fresh`/`-stale`,
  `systemctl-failed-units.txt`, `crontab-empty.txt`,
  `crontab-with-entries.txt`, `integrity-baseline.json`,
  `integrity-changed.json`. All real tool-output shapes; all IPs are
  documentation ranges. `test/fixtures/README.md` documents each fixture,
  its regeneration command, and the record-once/freeze-forever policy.
- `test/fixtures/snapshot-fixtures.py` — records a live box's
  external-tool outputs into the corpus (root; `--dry-run` to preview).
  Lands in this PR as the documented regeneration path; T03 exercises it
  on the seeded container.
- `test/smoke.sh` — one new assertion: the property suite runs green and
  under 5 seconds (33 total). The existing shellcheck assertion now also
  covers the property-suite files.
- **Tier 2 seeded-container integration** (`.github/workflows/integration-seeded.yml`,
  issue #17, third vertical slice of the #14 three-tier test model). A
  privileged container on top of the existing
  `test/install-docker/Dockerfile` base adds fail2ban + docker.io +
  rsyslog + cron + sudo + iproute2 and seeds eight specific conditions:
  stale apt cache stamp, unexpected cron drop-in, root crontab entry,
  failed systemd unit, banned SSH IP, sixteen auth-fail journal entries,
  non-allowlisted listening port, and a baseline-integrity diff.
  `test/install-seeded.sh` (driver) builds the seeded image, boots the
  container, runs `install.sh --ci`, then captures `box-audit --json`
  and pipes it through `test/install-seeded/assert-json.py` which
  asserts the expected `check_id`s appear with the expected severities.
  `integrity.change` is allowed to appear more than once because the
  audit legitimately emits one finding per changed crown-jewel path
  plus an aggregate `info` summary when ≥2 paths changed. A second
  workflow job, `integration-seeded-regression`, sed-mutates one
  seeded condition in a throwaway build context and inverts the
  resulting driver failure into a pass — proving the gate has teeth.
  Catches regressions that tier 1 cannot (no filesystem state to
  exercise on ephemeral runners).
- `test/smoke.sh` — shellcheck glob extended to cover the two install
  drivers (`test/install.sh`, `test/install-seeded.sh`); the matching
  `SC2015 disable=…` comment is added to `test/install.sh`'s cleanup
  trap to match the one already in the seeded driver.
- **Tier 3 local pre-merge script** (`test/local-integration.sh`,
  issue #18 — closes #18, third vertical slice of the #14 three-tier
  test model). Author's local pre-merge net: privileged systemd
  container, `install.sh --ci`, then `box-audit --json` and the
  four-key contract assertion plus the `+replay` version-suffix
  invariant on the installed binary. Hard budget: 60 seconds;
  observed ~8s on a 2026-era x86 host. Skips itself with
  `skipped: requires privileged Docker` and exits 0 on hosts that
  can't grant `--privileged`, so `test/all.sh` records a skip rather
  than a failure when the gate can't run.
- **Single local entry point** (`test/all.sh`, issue #18). Runs the
  four tiers in sequence — smoke, install (positive), install-seeded,
  local-integration — fail-fast on the cheapest first. Each tier owns
  its own skip logic; the orchestrator is dumb. Final summary line
  reads `all: 4 passed` (tier 3 ran and passed) or
  `all: 3 passed, 1 skipped` (tier 3 skipped). Aggregate exit 0 only
  if every tier that ran passed.

### Changed

- Nothing. The audit script itself is untouched: every input path it
  reads (CONFIG_DIR, HISTORY_DIR, /proc/loadavg, journalctl, ss, apt,
  the apt stamp, integrity baseline) has no env-var override, so the
  property tests assert on the script's seam-less surfaces (schema,
  replay deltas) and document the gaps for T03 rather than patching
  around them.

## [0.6.0] - 2026-09-15

### Added

- **`box-audit --replay [DIR]`** (issue #15). Treat DIR as a self-contained
  history root: read-only against the live `/var/log/box-audit/history/`,
  never writes a snapshot there. The "today" snapshot is the
  lex-sorted last file; with `--diff [N]`, the comparison is against the
  file N positions earlier in that same dir (mirrors `--diff`'s live
  semantics). An empty dir prints `box-audit: replay directory is empty`
  on stdout and exits 0. Lets you triage historical runs (or fixtures)
  without ever touching live state.
- `box-audit --version` now appends `+replay` when the replay mode is
  present in this build. The suffix is built at runtime from a constant
  in the script — the `VERSION` file remains the bare `0.6.0` single
  source of truth.
- `test/fixtures/replay/` — three snapshot fixtures
  (`2026-09-13.json` baseline, `2026-09-14.json` one finding,
  `2026-09-15.json` "today" with the deliberate added/gone delta) that
  exercise `--diff 1` and `--diff 2` deterministically. Byte-compatible
  with `--json` output; no new fields.
- `test/smoke.sh` — 13 new assertions covering the empty-dir contract,
  corpus exit codes, `--diff 1` / `--diff 2` determinism (two
  consecutive runs diffed), and the version suffix. Existing 19
  assertions unchanged.

### Changed

- `history_diff` now accepts an optional directory override (and an
  explicit today/baseline file pair) so the replay path reuses the
  exact same comparison logic instead of forking a replay-specific
  function. Live `--diff` behavior is unchanged.

## [0.5.0] - 2026-09-15

### Fixed

- `--tail` and `--diff` never worked: the CLI dispatch called the
  history functions before bash had read their definitions, so every
  invocation died with `command not found` and exit 0. Functions now
  precede the dispatch.
- `--tail` with no argument crashed under `set -u` (unbound `$2`), and
  `--diff` with no argument errored despite docs advertising a default
  of 1. Both now take the documented optional `[N]`.
- **Delta mode now actually fires.** The counts sidecar extracted
  yesterday's numbers by regex-matching leading digits from finding
  messages — which never matched, because every message starts with a
  label (`SUID: 37 ...`). The sidecar now reads the structured `count`
  field on `security.outbound_remote_count`, `security.suid_count`,
  and `updates.security_pending`. SUID-DELTA, OUTBOUND-DELTA, and
  SECURITY-DELTA are functional for the first time since PR 3.
- USER-CRON finding no longer renders "in ''s crontab" under the root
  systemd unit (`$USER` is empty there).
- Timer self-exemption is exact (`box-audit.timer`,
  `healthcheck.timer`) — a substring match would also have exempted an
  attacker timer named `box-audit-helper.timer`.
- History snapshots are written 0600 instead of inheriting the process
  umask (0644 under the root unit). They contain host info, findings,
  and IP samples.

### Changed

- **BREAKING (JSON consumers):** finding field `id` → `check_id`.
- **Findings-first pipeline.** Checks push structured findings to a
  file-backed collector; the text report and the `--json` document are
  both renderings of that one list. Adding a check is now one
  `json_push` call instead of edits in 3–4 places (report function,
  emoji case map, schema, docs). Output shape is unchanged: same
  emojis, labels, severities, exit codes, `raw_output`, `status`.
- cron.d allowlist and SUID threshold moved from hardcoded values to
  per-box config (`/var/lib/box-audit/cron-d-allowlist.txt`,
  `suid-threshold.conf`), seeded by `--init`, with built-in fallbacks.
  The `--init` seed now reflects the box's actual /etc/cron.d/ contents.
- USER-CRON message wording is tool-neutral ("verify you created it")
  instead of assuming the author's Hermes-specific scheduling.

### Added

- `test/smoke.sh` — 19-assertion CLI contract suite, CI-safe (non-root,
  bare runner). Asserts exit codes, JSON shape, schema/check_id
  agreement, and shellcheck cleanliness across all three scripts.

## [0.4.0] - 2026-09-15

### Added

- Per-box config for ports, timers, and outbound threshold (PR 2). The
  hardcoded `known_ports` list, custom-timer allowlist, and outbound
  threshold of 25 all moved from the script to `/var/lib/box-audit/`.
  Each gets a small built-in fallback when the file is missing (with a
  one-time stderr note pointing at `--init`). The NucBox-specific ports
  are gone from the script — no longer bleed into other boxes via
  yesterday's README example.
- `box-audit --init` snapshots the live box into the three config files.
  Idempotent.
- `box-audit --accept-port N` appends a port to `ports-allowlist.txt`.
- `box-audit --accept-timer NAME` appends a timer to
  `timers-baseline.txt`. Accepts both `name` and `name.timer`.
- `box-audit --outbound-threshold N` writes the threshold integer.
- `install.sh` seeds the three config files on FRESH install only.
- `skills/box-audit/references/cli.md` — full CLI reference.
- Skill `§ 5. CLI summary` — quick table.
- **Delta mode** (PR 3). Each `--json` run writes today's snapshot to
  `/var/log/box-audit/history/YYYY-MM-DD.json`. The next day's run
  reads yesterday's snapshot and fires delta findings
  (`OUTBOUND-DELTA`, `SUID-DELTA`, `SECURITY-DELTA`) when today's
  count exceeds 2× AND is ≥5 absolute above yesterday. Day 1 (no
  prior snapshot) is silent; absolute-threshold findings still fire.
- **`box-audit --tail [N]`** (default 7). Read-only summary of the
  last N daily snapshots — `date status findings_count` per file.
  Doesn't touch state.
- **`box-audit --diff [N]`** (default 1). Read-only diff: shows the
  findings added today that weren't in the snapshot N days ago
  (and vice versa). Useful for "what changed since Tuesday?"
- **History retention** (30 days). Each `--json` run deletes
  `history/` snapshots older than 30 days right after writing today's.
  This is the box-audit equivalent of a logrotate policy — it lives in
  the script because logrotate's rename-and-compress would break
  `--diff`, which looks snapshots up by exact filename. `latest.json`
  and the counts sidecar are overwritten in place every run and need
  no rotation.
- **Stable `check_id` field** in JSON output. Previously the JSON `id`
  field was a heuristic word-trigram derived from the message text,
  so any reword silently renamed the id. Now each finding maps to a
  stable string (`security.outbound_remote_count`,
  `updates.security_pending`, `integrity.change`, etc.). Downstream
  tooling can branch on this without parsing free text. The heuristic
  id is gone — the table replaces it.
- `box-audit --print-schema` (PR 4). Emits the severity + check_id
  mapping as JSON, so downstream tooling (Hermes cron, Discord relay,
  etc.) doesn't have to parse human text or hardcode the table.

### Changed

- Arg validation in manage flags runs BEFORE the root check, so a
  non-root user invoking `--accept-port foo` sees "invalid integer"
  instead of "needs root." Permission gate is no longer a syntax gate.
- The script's JSON output structure carries the same fields as before;
  the `id` values changed (now stable strings vs. heuristic word-
  trigrams) but consumers reading human `message` or `severity` are
  unaffected.
- **Agent-facing skill** (PR 4). `skills/box-audit/SKILL.md`:
  - § 1 Step 0 is now a freshness check (read the snapshot timestamp
    before reporting findings).
  - New `## 2b. Don't` section — explicit guard against agents
    restarting services, re-running the script, modifying baselines,
    or treating "0 findings with degraded" as a clean pass.
  - § 5 CLI summary expanded with `--tail`, `--diff`, `--print-schema`.

## [0.4.0] - 2026-09-15

### Added

- Outbound-connection check now extracts and classifies IPv6 remotes
  (bracketed hex, zone ids stripped) — on a dual-stack box, a process
  phoning home over IPv6 was invisible to the C2 check.
- `install.sh`: one command for fresh install and upgrade. Sanity-checks
  the script before anything lands on the box, byte-compares targets so
  re-runs only touch changed files, preserves a customized
  `OnCalendar=`, and ends on a verify gate (service success,
  `latest.json` parses, timer active with a real next-run time).
- `--version` flag: answers "what's deployed here?" standalone, printed
  as `box-audit X.Y.Z`.
- Optional webhook push delivery (`scripts/notify-webhook.sh`): POSTs
  `latest.json` to `$BOX_AUDIT_WEBHOOK_URL`, wired in via an
  `ExecStartPost=` drop-in. Pull stays the default.

### Changed

- Skill consolidated to one `skills/box-audit/SKILL.md` per the
  agentskills.io layout; `references/install.md` is a procedure again,
  not a competing skill with its own frontmatter.
- README: "Getting the report off the box" section (pull-by-default
  rationale, optional push, Hermes cron recipe); `install.sh` is now the
  primary install path with the manual steps as fallback.

### Fixed

- Each sudo-gated check (fail2ban, docker, apt priming, needrestart)
  now probes its own command instead of sharing one fail2ban canary —
  under scoped sudoers, permission for one command says nothing about
  the others. `python3` joins the checked binaries; it was an
  unverified hard dependency.
- File-integrity check on a non-root run skips with a `degraded`
  finding instead of poisoning the baseline (partial snapshot → phantom
  removals → phantom additions on the next root run).
- Degraded findings survive subshells (collected via temp file) and are
  classified as `degraded` severity in `--json` output — previously
  `--json`, the mode the systemd timer uses, reported an empty
  `findings[]` while checks were silently skipped. `raw_output` now
  carries real newlines, not literal `\n` pairs.
- Integrity baseline is written 0600 (dir 0700, pre-existing
  world-readable baselines repaired) — it hashes `/etc/shadow` and
  `/etc/gshadow`, so a world-readable baseline was an offline
  password-guessing oracle.
- Timer persistence check no longer flags box-audit's own timer — it
  self-reported on every run, training the reader to ignore the exact
  alarm that matters when an attacker adds a timer.
- Unattended-upgrades check accepts `Initial whitelist` lines as
  steady state; a run captured mid-flight is normal, not an anomaly.
- apt cache priming actually runs `apt-get` — a double-duration bug
  made `timeout` execute a command named `30` (rc 127, stderr
  swallowed), so every run reported a bogus "priming failed". The
  degraded message now distinguishes a slow mirror (counts still
  usable) from a real apt failure.
- `install.sh` no longer reads `VERSION` before defining `REPO_ROOT`
  (crashed every invocation under `set -u`).
- Webhook wiring is `ExecStartPost=`, not a piped `ExecStart=` — the
  pipe ate the run's output and truncated `latest.json` to nothing —
  and the installer ships the notifier to `/usr/local/bin`, where all
  the docs said it would be.

## 0.3.x and prior

Earlier versions predate this changelog; see git history.

[unreleased]: https://github.com/ManningWorks/box-audit/compare/v0.6.0...HEAD
[0.4.0]: https://github.com/ManningWorks/box-audit/releases/tag/v0.4.0
[0.5.0]: https://github.com/ManningWorks/box-audit/releases/tag/v0.5.0
[0.6.0]: https://github.com/ManningWorks/box-audit/releases/tag/v0.6.0
