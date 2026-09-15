# box-audit

> Daily-delta security and health audit for personal Linux boxes, designed
> for at-a-glance delivery to a phone via Telegram / Discord / Pushover.

`box-audit` runs ~25 checks against a Linux box and emits a short report
flagging anything that differs from a normal baseline. It complements — does
not replace — tools like [Lynis](https://github.com/CISOfy/lynis) by
answering a different question:

- **Lynis**: "What's the absolute state of my hardening?" (score 0–100, hundreds
  of CIS-style checks, run weekly/monthly)
- **box-audit**: "What's *different* since yesterday?" (delta-style,
  finds new SUID binaries, unexpected outbound connections, custom cron jobs,
  pending reboots, security updates — run daily)

## What it checks

| Section | Checks |
|---|---|
| Resources | Disk > 85%, swap > 70%, load > 3.0 |
| Security | fail2ban banned IPs, SSH failures (24h), sudo failures, listening ports vs baseline, **outbound non-LAN IPs** (catches C2), **SUID binary count** (catches rootkits) |
| System | Failed systemd units, unhealthy Docker containers, Apport crash dumps, kernel errors, **non-standard systemd timers** (catches persistence), **unexpected user crontabs**, **unexpected `/etc/cron.d/` drop-ins** |
| Updates | Pending security updates, kernel CVEs (reboot-required), origin classification (distro vs third-party) |
| Maintenance | Reboot-required state, apt cache freshness, unattended-upgrades health, needrestart (libc/kernel drift, services needing restart) |

The bold items are the **delta-style** checks that distinguish box-audit from
Lynis-style absolute scoring.

## Output formats

```bash
# Human-readable (default): emoji-coded lines for Telegram / Discord
./scripts/box-audit.sh

# Machine-readable JSON for webhooks / piped delivery
./scripts/box-audit.sh --json
```

`--json` output shape:

```json
{
  "status": "findings",
  "timestamp": "2026-09-15T14:29:33Z",
  "host": "your-hostname",
  "findings": [
    {"severity": "warn", "check_id": "updates.security_pending", "message": "2 security update(s) pending"},
    {"severity": "warn", "check_id": "maintenance.kernel_restart", "message": "Kernel: 7.0.0-31-generic (newer kernel on disk, current kernel still running)"}
  ],
  "raw_output": "..."
}
```

Each finding carries a stable `check_id` (see `box-audit --print-schema`
for the full table), so downstream tools can branch without parsing the
message text. Count-carrying checks (`security.outbound_remote_count`,
`security.suid_count`, `updates.security_pending`) also carry a numeric
`count` field.

Exit codes: `0` = all clear, `1` = findings present, `2` = bad CLI flag.
In `--json` mode the exit code is always `0`; the JSON body's `status`
field (`ok` vs `findings`) is the signal instead.

## Install

### One command (recommended)

```bash
git clone https://github.com/ManningWorks/box-audit && cd box-audit
sudo ./install.sh
```

Same command for fresh installs and upgrades. It sanity-checks the script
before installing, writes the systemd units below, and finishes on a
verify gate (service success, `latest.json` parses, timer active with a
real next-run time) — non-zero exit on any failure. Re-runs only touch
files that changed, and a customized timer schedule is preserved with a
warning, never clobbered.

Dependencies: `sudo apt install -y needrestart fail2ban python3`
(docker only if you run containers and want the health check). Install
them before or after — the audit degrades those checks gracefully and
names what's missing.

### Removing box-audit

```bash
sudo systemctl disable --now box-audit.timer
sudo rm /etc/systemd/system/box-audit.service /etc/systemd/system/box-audit.timer
sudo rm -f /usr/local/bin/box-audit /usr/local/bin/notify-webhook.sh
sudo rm -rf /usr/local/share/box-audit /var/lib/box-audit /var/log/box-audit
sudo systemctl daemon-reload
```

`/var/lib/box-audit/` holds the per-box allowlists and the file-integrity
baseline; `/var/log/box-audit/` holds the snapshots and delta history.
Deleting them resets everything the tool has learned about your box —
the next run re-seeds from scratch.

### Manual install (fallback)

```bash
# 1. Install dependencies (Ubuntu/Debian)
sudo apt install -y needrestart fail2ban python3
# docker only if you run containers and want the health check:
# sudo apt install -y docker.io

# 2. Drop the script somewhere on PATH
sudo install -m 0755 scripts/box-audit.sh /usr/local/bin/box-audit

# 3. Test it
sudo box-audit
```

Run it with sudo at least once (or via the systemd unit, which runs as
root) so the file-integrity baseline can read all crown-jewel files.
Non-root runs skip the integrity check rather than poison the baseline.

### Via an AI agent

If you use an AI agent that supports the [Skills](https://agentskills.io) format
(Hermes, opencode, Claude Code, etc.), point it at the `skills/box-audit/SKILL.md` file:

> "Install the box-audit skill from
> https://github.com/ManningWorks/box-audit/tree/master/skills/box-audit"

The agent runs the same `install.sh` you'd run by hand, walks the verify
gate, reads the findings, and reports back — the skill encodes how to
interpret and triage the output, not a separate install path.

### Schedule daily

`install.sh` writes these units for you; shown here for the manual path or
if you want to know what lands on your box:

The unit runs `box-audit --json` once a day. To inspect or tweak the
allowlists (`--init`, `--accept-port`, `--accept-timer`,
`--outbound-threshold`), see
[`skills/box-audit/references/cli.md`](skills/box-audit/references/cli.md).

```ini
# /etc/systemd/system/box-audit.service
[Unit]
Description=box-audit daily security + health check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
# DO NOT use `ExecStart=/bin/bash -c '... > /path'` — systemd parses
# whitespace as argv boundaries and will pass the redirect target to
# bash as a positional argument instead of shell syntax. Use
# StandardOutput=truncate:... to bypass the shell entirely.
StandardOutput=truncate:/var/log/box-audit/latest.json
StandardError=journal
ExecStart=/usr/local/bin/box-audit --json
# Sudo is invoked internally by the script for fail2ban/docker checks;
# run as root or grant NOPASSWD to /usr/bin/fail2ban-client, /usr/bin/docker.

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/box-audit.timer
[Unit]
Description=Run box-audit daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now box-audit.timer
```

## Getting the report off the box

### Default is pull, and that's deliberate

Every run leaves the full report in `/var/log/box-audit/latest.json`. You
— or your agent — read it when you ask "how's the box?". Nothing arrives
unprompted.

That's not a missing feature. A daily audit that pings "all clear!" every
morning trains you to ignore it within a week, and then the one morning it
says something real, you will too. Silence means nothing changed. When
something does, the report is already on disk, waiting to be read — and
the severity table in `skills/box-audit/SKILL.md` says how to read it.

### Webhook push (optional)

If you'd rather certain findings come to you, ship them with
`scripts/notify-webhook.sh`: it reads `latest.json` and POSTs the JSON
body to `$BOX_AUDIT_WEBHOOK_URL` (set it in the environment or in
`/etc/default/box-audit`). Any incoming-webhook endpoint works — Discord
webhook, a Telegram bot via a relay, ntfy, your own receiver.

Wire it into the daily run with a drop-in, not a second unit:

```bash
sudo systemctl edit box-audit.service
```

```ini
[Service]
ExecStartPost=/usr/local/bin/notify-webhook.sh
```

Then `sudo systemctl daemon-reload`. `install.sh` puts the notifier at
`/usr/local/bin/notify-webhook.sh` alongside the main script.
`ExecStartPost` runs after the main process exits, so it pushes this
run's fresh snapshot and `latest.json` stays intact for pull readers.
Don't replace `ExecStart` with a pipe into the notifier — the pipe eats
the run's output, the notifier doesn't read stdin, and the unit's
`truncate:` capture would then overwrite `latest.json` with nothing.
When the notifier is wired in, the verify gate still checks the file,
plus the webhook POST now participates in the unit's success/failure.

### Log retention

`latest.json` is overwritten in place on every run — it never grows.
The daily snapshots in `/var/log/box-audit/history/` are bounded by the
script itself: each run deletes snapshots older than 30 days after
writing today's. There is deliberately no logrotate config — rotating
(rename + compress) the date-named snapshots would break `--diff`,
which looks them up by exact filename. If you want a longer history,
raise `HISTORY_RETENTION_DAYS` in the script; if you want the space
back sooner, delete old files from `history/` — the tool re-seeds
gracefully.

### Hermes recipe

What the author actually runs: a Hermes cron job once a day whose entire
configuration is this prompt — the agent does the reading and the
sending, the box-audit timer does the auditing:

> Read `/var/log/box-audit/latest.json`. If the file is missing, empty,
> or unparseable, send a single Telegram message: '❌ box-audit:
> latest.json missing or unreadable — check the systemd timer'.
> Otherwise, parse the JSON. If `status == 'ok'`, send '✅ Box audit
> clean (timestamp <ts>)'. If `status == 'findings'`, send each entry
> from `findings[]` as one Telegram line using `hermes-telegram-send`.
> Group findings with the same severity together. Include the timestamp
> from the JSON. Do NOT run the script yourself — only read the JSON
> file written by the box-audit systemd timer.

No separate delivery daemon to keep alive. Severity → Telegram format:
see the severity table in `skills/box-audit/SKILL.md` § 2, which is
also the contract the cron should follow.

## Compatibility

- **Tested on**: Ubuntu 24.04 LTS (Noble)
- **Should work on**: any Debian/Ubuntu LTS, recent Fedora (untested)
- **Won't work on**: macOS, Windows, Alpine (uses systemd, apt, journalctl,
  fail2ban-client — Ubuntu/Debian idioms)

## CI

Every push and PR runs two GitHub Actions workflows: `ci.yml` runs
`test/smoke.sh` (shellcheck plus the degraded-path suite) on a bare
non-root runner. The `install-ci` workflow additionally runs
`install.sh --ci` inside a privileged
systemd container (`jrei/systemd-ubuntu:24.04`) on every push and PR, plus a
negative variant that mutates `ExecStart=` to confirm the verify gate fails
loudly. Dependabot bumps the base image weekly.

## What it does NOT do

- **Not a security tool.** It is an observer. It does not block, patch,
  quarantine, or remediate. It surfaces things; you decide.
- **Not comprehensive.** It checks ~25 things. Lynis checks hundreds.
- **Not CIS-compliant.** No compliance framework. If you need CIS / PCI /
  HIPAA evidence, run Lynis or OpenSCAP.

## Why not just use Lynis?

Lynis is excellent. Use it for monthly deep audits. The reason box-audit
exists alongside it:

| | box-audit | Lynis |
|---|---|---|
| Frequency | Daily | Weekly/monthly |
| Output shape | One Telegram screen | Hundreds of lines |
| Style | Delta (what changed) | Score (absolute) |
| Runtime | ~2 seconds | 1–5 minutes |
| Dependencies | bash + coreutils | None (Perl-like bundle) |
| Learning curve | Zero (read the README) | Medium (test IDs, profiles) |

Run both. Lynis monthly for the score; box-audit daily for the delta.

## License

MIT. See `LICENSE`.

## Author

Luke Manning — [lukemanning.ie](https://lukemanning.ie)