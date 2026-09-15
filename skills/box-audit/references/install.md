---
name: box-audit
version: 0.2.0
description: Install or repair the box-audit daily security + health audit (script + systemd timer) on a Linux box. Use when the user names "box-audit", pastes a github.com/ManningWorks/box-audit URL, or asks for a daily Telegram/Discord system audit of their machine.
---

# box-audit installer

Install the box-audit daily-delta audit: script on PATH, systemd timer for
the daily run, output file the user (or a bot) reads. ~10 minutes end to end.

The verify gate (step 4) is the skill. A timer that fails silently every
morning hands the user false peace of mind. That's the exact opposite of
what an audit is for. No gate pass, no "done".

Upstream source of truth: https://github.com/ManningWorks/box-audit
This skill describes the install; the script's own behaviour is documented
in its `--help` and the repo README. Where they disagree with this file,
trust the script and file an issue.

## 1. Fetch and sanity-check the script

```bash
curl -fsSL https://raw.githubusercontent.com/ManningWorks/box-audit/master/scripts/box-audit.sh \
    -o /tmp/box-audit-install/box-audit.sh
bash -n /tmp/box-audit-install/box-audit.sh \
  && grep -q 'report_security' /tmp/box-audit-install/box-audit.sh \
  && grep -q -- '--json' /tmp/box-audit-install/box-audit.sh
```

`bash -n` parses the whole file, so a truncated or corrupted download fails
here rather than at 9am on the box.

**Done when:** the compound command exits 0. On failure, stop and report the
fetch as bad; install nothing.

## 2. Install the script and check dependencies

```bash
sudo install -m 0755 /tmp/box-audit-install/box-audit.sh /usr/local/bin/box-audit
box-audit --help        # usage text, exit 0
sudo box-audit          # first run, as root
```

The first run must be root so the file-integrity baseline reads all
crown-jewel files; a non-root first run leaves the integrity check degraded.
Collect any `❓ DEGRADED:` lines from the output. Each names the missing
binary and the check it would enable (`needrestart`, `fail2ban-client`,
`docker`). List them for the user and install the ones they want before
moving on; the checks are the product.

**Done when:** `box-audit --help` exits 0 and the first run prints a report
(ok or findings; findings are fine, they're the tool working).

## 3. Install the systemd units

Create `/var/log/box-audit/` first, then write both units:

`/etc/systemd/system/box-audit.service`:

```ini
[Unit]
Description=box-audit daily system health + security check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
# truncate:, not file: — file: never truncates, so a shorter JSON document
# following a longer one leaves stale bytes glued to the end and the file
# stops parsing. truncate: cuts on service start.
StandardOutput=truncate:/var/log/box-audit/latest.json
StandardError=journal
ExecStart=/usr/local/bin/box-audit --json
```

`/etc/systemd/system/box-audit.timer`:

```ini
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
```

**Done when:** `systemctl is-active box-audit.timer` prints `active` and
`systemctl list-timers box-audit.timer` shows a next-run time.

## 4. Verify gate

```bash
sudo systemctl start box-audit.service
systemctl show box-audit.service -p Result -p ExecMainStatus
python3 -c "import json; d=json.load(open('/var/log/box-audit/latest.json')); print(d['status'], len(d['findings']), 'findings')"
```

**Done when all three hold:**
- `Result=success`, `ExecMainStatus=0`
- `latest.json` parses and prints its status + finding count
- the timer from step 3 still shows `active` with a next-run time

If the gate fails, debug before declaring done. The usual suspects, in
order of likelihood:
- `sudo: a password is required` in the journal: the script shells out to
  `sudo -n` for `fail2ban-client` and `docker`. Either run the service as
  root (as above) or grant NOPASSWD for exactly those two commands.
- directory missing. `/var/log/box-audit/` doesn't exist when the service
  first runs, and the run fails on output.
- exit 2 from the script itself. A bad CLI flag reached `ExecStart`; run
  the same command by hand to see the error.

## 5. Report

Tell the user, with real values from the gate run:
- script path (`/usr/local/bin/box-audit`) and version from `--help`
- timer active, with the actual next-run time
- where output lands (`/var/log/box-audit/latest.json`) and today's
  finding count
- any DEGRADED lines left unfixed, as explicit follow-ups
- one line on pairing with monthly Lynis for absolute (non-delta) scoring

## Webhook delivery (optional branch)

If the user already has a Telegram/Discord bot for system notifications,
replace the service's stdout capture with a POST:

```ini
ExecStart=/bin/bash -c '/usr/local/bin/box-audit --json | curl -fsS -X POST -H "Content-Type: application/json" -d @- https://your-webhook.example.com/audit'
```

The JSON's `severity`, `id`, and `message` fields per finding are the
formatter contract. Everything else in the skill is unchanged; the gate
still runs, checking the webhook received the payload instead of the file.

## Pitfalls

- Run the verify gate before declaring done. A unit that fails silently
  every day is worse than no unit.
- Check sudo policy before the first service run: the script probes
  `sudo -n` per command (`fail2ban-client`, `docker`) and degrades the
  check when the probe fails, which is easy to miss in JSON output.
- Keep the timer daily. Hourly re-runs generate noise the user learns to
  ignore, which defeats a delta audit.
- Install the upstream script as-is; wrap or fork for local changes so the
  next update doesn't silently revert them.
- Create `/var/log/box-audit/` before the first service run, not after.
