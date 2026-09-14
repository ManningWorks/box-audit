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
  "timestamp": "2026-09-14T14:29:33Z",
  "host": "your-hostname",
  "findings": [
    {"severity": "warn", "id": "security:_2_security", "message": "SECURITY: 2 security update(s) pending"},
    {"severity": "warn", "id": "kernel-restart:_kernel:_7.0.0-31-generic", "message": "KERNEL-RESTART: ..."}
  ],
  "raw_output": "..."
}
```

Exit codes: `0` = all clear, `1` = findings present, `2` = setup error.

## Install

### Manual install

```bash
# 1. Install dependencies (Ubuntu/Debian; all are in main repos)
sudo apt install -y bash coreutils util-linux systemd

# 2. Drop the script somewhere on PATH
sudo install -m 0755 scripts/box-audit.sh /usr/local/bin/box-audit

# 3. Test it
box-audit
```

### Via an AI agent (recommended)

If you use an AI agent that supports the [Skills](https://agentskills.io) format
(Hermes, opencode, Claude Code, etc.), point it at the `skill/SKILL.md` file:

> "Install the box-audit skill from
> https://github.com/ManningWorks/box-audit/tree/master/skill"

The agent will walk through: copy the script, set up a daily systemd timer,
verify with a dry-run, and report back.

### Schedule daily

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

## Compatibility

- **Tested on**: Ubuntu 24.04 LTS (Noble)
- **Should work on**: any Debian/Ubuntu LTS, recent Fedora (untested)
- **Won't work on**: macOS, Windows, Alpine (uses systemd, apt, journalctl,
  fail2ban-client — Ubuntu/Debian idioms)

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