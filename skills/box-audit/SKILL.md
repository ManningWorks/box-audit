---
name: box-audit
version: 0.7.1
description: Run and interpret box-audit, a daily security + health audit for Linux boxes. Use when asked to check box health/security, run or schedule box-audit, install or upgrade it, read its latest.json report, triage its findings, or repair its timer/baseline. Installation is one command (install.sh), covered in references/install.md.
---

<!-- version kept in sync by hand with ../VERSION (single source of truth for the script and installer); the skill ships separately, so install.sh does not auto-edit this file. -->

# box-audit operator

box-audit answers one question daily: what changed on this box since the
last run? It observes; it never remediates. Every finding is a pointer for
a human decision, not a trigger for action.

The script lives at `/usr/local/bin/box-audit`. Output: text report
(default) or JSON (`--json`). Latest JSON snapshot:
`/var/log/box-audit/latest.json`. Exit codes: 0 = clear, 1 = findings,
2 = bad flag. `--json` always exits 0; branch on the `status` field
instead (`ok` vs `findings`).

Not installed yet, or upgrading? That's one command — `sudo ./install.sh`
from a repo checkout. Prerequisites, the verify gate, and pitfalls are in
`references/install.md`. Everything below assumes the daily timer exists.

CLI flags are summarized in `references/cli.md` (manage flags live
there); for programmatic consumption, `box-audit --print-schema` emits
the severity + `check_id` mapping as JSON.

## 1. Run or read

**0. Check freshness first.** `latest.json` is overwritten on each daily
run — stale data and fresh data look identical. Read the timestamp
before doing anything else:

```bash
python3 -c "import json;d=json.load(open('/var/log/box-audit/latest.json'));print(d['timestamp'],d['status'],len(d['findings']))"
```

If the timestamp is more than ~26 hours old, the daily run is overdue.
Say so to the user *before* reporting findings. Triggering a fresh run
is a user decision (`sudo systemctl start box-audit.service` or wait
for the next timer fire), not yours.

Fresh check, right now (only on user request):

```bash
sudo box-audit            # text, exit 1 when findings exist
sudo box-audit --json     # machine-readable, always exit 0
```

The daily run has usually already happened. Read
`/var/log/box-audit/latest.json` instead of re-running when the question
is "how is the box this morning".

**Done when:** you have either a fresh run's output or today's snapshot,
and you know which one you're looking at. `latest.json` is overwritten on
each run — stale data and fresh data look identical, so check the
timestamp against the timer's last-fire time
(`systemctl show box-audit.timer -p LastTriggerUSec`).

## 2. Read the findings

Each JSON finding carries `severity`, `check_id`, `message`:

| severity | meaning | your move |
|---|---|---|
| `degraded` | a check couldn't run, so this run is partially blind | fix the named cause before trusting "no findings" |
| `alert` | active security signal (🚨) | look now |
| `warn` | deviation from baseline or above threshold (🔒 🛡️ 🔴 ⚠️ etc.) | look today |
| `info` | routine state worth knowing (📦 🔄 etc.) | skim |

Severity is assigned from the report line's leading emoji, so the table
above is the full contract — there are no hidden levels.

Check `degraded` first, always. "0 findings" from a run where the
integrity check was skipped is not a clean bill; it's a blind spot. A
`degraded.check` finding names the cause (missing binary, no root, no
NOPASSWD sudo).

**Done when:** you can state the finding count, the highest severity
present, and — if any `degraded` finding exists — what it blinds.

## 2b. Don't

box-audit observes; it doesn't remediate. Agents handling this skill's
output have a strong reflex to *do something* about findings — resist.
Specifically:

- **Don't restart services** that `needrestart` flags (`sshd`,
  `fail2ban`, etc.). The user decides the maintenance window.
- **Don't run `apt upgrade` or trigger unattended-upgrades by hand.**
  Same reason.
- **Don't modify `/var/lib/box-audit/` baselines** directly. If a
  port/timer/threshold needs updating, suggest the matching manage
  flag (`--accept-port`, `--accept-timer`, `--outbound-threshold`) as
  a discrete step for the user, don't run it yourself.
- **Don't re-run the script to "verify" a finding.** The flock-guarded
  daily timer is the canonical run; you read its output. Re-running
  changes the snapshot timestamp, which makes "what changed since
  yesterday?" diffs unreliable.
- **Don't open firewall rules, kill processes, edit configs, or delete
  files** based on a finding's hint. The finding surfaces the question;
  the human answers it.
- **Don't treat "0 findings" with `degraded` findings as "all clear".**
  Report degraded-blindness explicitly. "Yes, no findings, but the
  integrity check was skipped because the script wasn't root."

## 3. Triage by finding type

Delta findings compare against yesterday; reading them wrong usually means
forgetting that. The recurring ones:

- **`INTEGRITY: changed/added/removed <path>`** — a crown-jewel file
  (sudoers, sshd_config, crontabs, authorized_keys) differs from the
  baseline. Legitimate config changes trip this too. Verify the change is
  one you made; the baseline self-updates after each run, so an
  unexplained change is only visible until the next daily run erases it.
  Investigate *before* the next timer fire, or capture the baseline:
  `cp /var/lib/box-audit/integrity-baseline.json /tmp/`.
- **`SUID: N suid binaries (baseline M)`** — count drift. New SUID
  binaries are a classic rootkit persistence move. Check the diff, not
  just the count.
- **`OUTBOUND: <ip>`** — a non-LAN outbound connection. Expected for apt,
  NTP, your own services. Unexpected IPs are the C2 question; resolve and
  identify before dismissing.
- **`CUSTOM-TIMERS: N non-standard`** — systemd timers outside the known
  set. Persistence mechanism of choice. box-audit's own timer is exempt
  from this check.
- **`SECURITY: N updates`**, **`REBOOT: required`**,
  **`KERNEL-RESTART`**, **`SERVICES-RESTART`** — maintenance debt.
  Routine; batch them into the next maintenance window.
- **`SSH-FAIL` / `SUDO-FAIL`** — brute-force or fat-fingers. Thresholds:
  15 fails/24h (SSH), 100 (sudo).

**Done when:** every finding has a disposition — known-good, maintenance
debt, or needs-investigation — with the needs-investigation ones named
explicitly to the user.

## 4. Report

Match the report to the question asked:

- "Any problems?" → count, highest severity, each non-info finding in one
  line, degraded-causes called out first.
- "How's the box?" → one line: status, finding count, anything above info.
- Full detail → `raw_output` from the JSON, which is the exact text report.

Never report "all clear" from a run with `degraded` findings without
saying what was skipped. A blind pass is not a clean pass.

> Push delivery (webhook/cron) is optional and documented in the README's
> "Getting the report off the box" section.

## Repair branch: timer or baseline

Symptoms that the daily machinery broke: `latest.json` timestamp older
than ~48h, timer inactive, or JSON parse errors on the snapshot.

```bash
systemctl status box-audit.timer --no-pager
sudo systemctl start box-audit.service && systemctl show box-audit.service -p Result -p ExecMainStatus
```

If the snapshot is corrupted JSON (a known cause was `StandardOutput=file:`
leaving stale bytes after a shorter document — fixed to `truncate:` in the
unit in `references/install.md`), delete the file and start the service
once to regenerate. Don't trust the *content* of a file that failed to
parse.

If the integrity baseline is genuinely poisoned (non-root run wrote
partial hashes — the script guards against this, so treat it as
last-resort), `sudo rm /var/lib/box-audit/integrity-baseline.json` and the
next run silently rebuilds it. That erases all remembered history: after
this, drift from before the reset is invisible. Say so when doing it.

## Developing box-audit

The repo checkout is the source of truth for development: the three-tier
test model and how to run it are in the repo README ("Testing" section),
entry point `bash test/all.sh`. Nothing in this skill is needed to develop
the tool.

