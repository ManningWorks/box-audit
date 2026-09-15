# Changelog

All notable changes to box-audit are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — entries are
grouped by kind, not by PR, and are written for the person deciding
whether to upgrade.

## [Unreleased]

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
