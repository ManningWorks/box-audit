# Install and upgrade via install.sh

The one-time install (and every later upgrade) is a single command from a
repo checkout:

```bash
git clone https://github.com/ManningWorks/box-audit && cd box-audit
sudo ./install.sh
```

(or download the repo as a tarball/zip — `install.sh` only needs
`scripts/box-audit.sh` and `VERSION` beside it).

## What it does, in order

1. Sanity-checks `scripts/box-audit.sh` (`bash -n`, plus greps for
   `report_security` and `--json`) *before* anything lands on the box — a
   truncated download fails here rather than at 9am.
2. Installs the script to `/usr/local/bin/box-audit` (0755) and runs the
   first audit as root so the file-integrity baseline reads all crown-jewel
   files.
3. Creates `/var/log/box-audit/` and writes the systemd service and timer
   units (same contents as the README's manual section, including the
   `StandardOutput=truncate:` rationale).
4. `daemon-reload` + `enable --now box-audit.timer`.
5. Verify gate: starts the service, checks `Result=success` /
   `ExecMainStatus=0`, parses `latest.json`, and confirms the timer is
   active with a real next-run time. Non-zero exit on any failure — a
   timer that fails silently every morning is the failure mode this whole
   procedure exists to prevent.

## Idempotency and upgrades

The same command is the upgrade path. Targets are byte-compared before
writing, so a re-run only touches files that actually changed, and a
customized `OnCalendar` in the timer is detected and left untouched
(warned, never silently clobbered).

## Webhook delivery (optional)

`scripts/notify-webhook.sh` POSTs `latest.json` to
`$BOX_AUDIT_WEBHOOK_URL` (env or `/etc/default/box-audit`). Wire it in
with a systemd drop-in, not a second unit:

```bash
sudo systemctl edit box-audit.service
```

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c '/usr/local/bin/box-audit --json | /usr/local/bin/notify-webhook.sh'
```

Then `sudo systemctl daemon-reload`. The verify gate still applies — it
just checks the webhook received the payload instead of the file.

The delivery philosophy behind this (pull by default, push opt-in) is in
the README's "Getting the report off the box" section.

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
  (install.sh does this; relevant only for manual installs.)
