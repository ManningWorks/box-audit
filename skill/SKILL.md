---
name: box-audit
version: 0.1.0
description: Install the box-audit daily system health + security audit. Use when the user pastes a github URL pointing to ManningWorks/box-audit, names "box-audit", or asks for a daily Telegram/Discord audit of a Linux box. Installs the script + a daily systemd unit + a verify-with-dry-run gate before declaring done.
trigger: User wants daily system audit, security + health Telegram summary, or "install box-audit"
---

# box-audit installer

Install the box-audit daily-delta security + health check on this Linux box.
Pair the script with a daily systemd timer and verify with a dry-run before
declaring done.

## When this skill applies

- User pastes `github.com/ManningWorks/box-audit` or any URL under it
- User says "install box-audit", "set up box-audit", "daily system audit"
- User asks "give me a daily Telegram summary of my box's security"
- User wants to replace an ad-hoc daily check script with this

Skip if not Linux (the script depends on systemd, apt, journalctl).

## Steps

### 1. Fetch the script from upstream

```bash
mkdir -p /tmp/box-audit-install
curl -fsSL https://raw.githubusercontent.com/ManningWorks/box-audit/master/scripts/box-audit.sh \
    -o /tmp/box-audit-install/box-audit.sh
```

Verify the script:
- File is non-empty (>5 KB)
- Starts with `#!/bin/bash`
- Contains `--json` flag handling
- Contains the function `report_security` (sanity check it didn't get truncated)

If any check fails, stop and ask the user — do not install a malformed script.

### 2. Install the script

```bash
sudo install -m 0755 /tmp/box-audit-install/box-audit.sh /usr/local/bin/box-audit
which box-audit && box-audit --help
```

### 3. Verify dependencies

The script's `check_deps()` function lists required binaries. Most are in
`coreutils`, `util-linux`, `systemd`. The optional ones:

| Binary | Required by check | Install |
|---|---|---|
| `needrestart` | libc/kernel drift detection | `sudo apt install -y needrestart` |
| `fail2ban-client` | fail2ban banned-IP status | `sudo apt install -y fail2ban` (if not already) |
| `docker` | Docker container health check | only if user runs docker |

Run `box-audit` once and check the output for any `❓ DEGRADED: '<bin>' not found` lines. Tell the user what's missing and ask whether to install.

### 4. Install the systemd units

Write `/etc/systemd/system/box-audit.service` and `box-audit.timer`. The
service runs `box-audit --json` and either pipes the output to the user's
delivery system or writes to a file the user can pick up later.

Default delivery is **to a file** at `/var/log/box-audit/latest.json`. The
user can swap in a webhook / Telegram bot later without changing the script.

```ini
# /etc/systemd/system/box-audit.service
[Unit]
Description=box-audit daily system health + security check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
# systemd parses whitespace in ExecStart as argv boundaries — DO NOT put
# a `>` redirection inside `ExecStart=/bin/bash -c '...'` because systemd
# will pass the redirect target to bash as an argv element instead of
# parsing it as shell syntax. Use StandardOutput=file:... instead, which
# bypasses the shell and captures stdout directly.
StandardOutput=file:/var/log/box-audit/latest.json
StandardError=journal
ExecStart=/usr/local/bin/box-audit --json
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
sudo mkdir -p /var/log/box-audit
sudo systemctl daemon-reload
sudo systemctl enable --now box-audit.timer
sudo systemctl status box-audit.timer --no-pager
```

### 5. Verify with a dry-run (GATE — do not declare done unless this passes)

Run the service once manually and inspect the output:

```bash
sudo systemctl start box-audit.service
sudo systemctl status box-audit.service --no-pager
sudo journalctl -u box-audit.service --since "5 minutes ago" --no-pager
test -s /var/log/box-audit/latest.json && echo "JSON output file written"
```

Expected:
- Service status: `active (exited)` with exit code 0
- `/var/log/box-audit/latest.json` exists, is non-empty, parses as valid JSON:
  ```bash
  python3 -c "import json; d=json.load(open('/var/log/box-audit/latest.json')); print(f'{len(d[\"findings\"])} findings, status={d[\"status\"]}')"
  ```

If the service fails or the JSON is malformed, debug before declaring done.
Common failures:
- `sudo: a password is required` — script needs `NOPASSWD` in sudoers, or run service as a user with NOPASSWD already configured
- `needrestart: command not found` — install it, or accept the DEGRADED line
- Exit code 2 from script — unknown CLI flag passed; rerun manually to see

### 6. (Optional) Wire up delivery

If the user has a Telegram / Discord bot already configured for system
notifications, replace the `ExecStart` in the service file with a webhook
POST:

```ini
ExecStart=/bin/bash -c '/usr/local/bin/box-audit --json | curl -fsS -X POST -H "Content-Type: application/json" -d @- https://your-webhook.example.com/audit'
```

The downstream formatter turns the JSON findings into a Telegram message
using the `severity`, `id`, and `message` fields.

### 7. Report

Tell the user:
- Script installed at `/usr/local/bin/box-audit`
- Daily systemd timer `box-audit.timer` is active
- Latest output is at `/var/log/box-audit/latest.json` (or their webhook)
- Show today's finding count: `python3 -c "import json; print(len(json.load(open('/var/log/box-audit/latest.json'))['findings']), 'findings')"`
- Note any DEGRADED lines that need follow-up
- Suggest pairing with monthly Lynis for absolute scoring (not part of this skill)

## Pitfalls

- **Do not install without the verify gate.** A systemd unit that fails
  silently every day is worse than not having one — it gives false peace
  of mind. Step 5 is mandatory.
- **Do not assume NOPASSWD sudo.** Many personal boxes don't have it. Either
  configure sudoers first (audit-only rules: `/usr/bin/fail2ban-client`,
  `/usr/bin/docker`) or document that the user needs to do this.
- **Do not write the timer with `OnCalendar=hourly`**. Daily is right for
  this audit; hourly generates noise the user will tune out.
- **Do not modify the script before installing.** The upstream version has
  been tested. If you need a local change, fork or wrap, don't patch in place.
- **`/var/log/box-audit/` needs to exist before the service runs.** Create
  it in step 4 or the first run will fail with a permission/IO error.