# Changelog

All notable changes to box-audit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — entries are
grouped by kind, not by PR, and are written for the person deciding
whether to upgrade.

## [Unreleased]

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

[unreleased]: https://github.com/ManningWorks/box-audit/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ManningWorks/box-audit/releases/tag/v0.4.0
