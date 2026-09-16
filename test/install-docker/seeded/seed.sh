#!/usr/bin/env bash
# Seed-state mutator for the tier-2 integration-seeded CI container
# (issue #17). Runs at image-build time. Sets up eight seeded
# conditions, one per check_id the driver asserts on.
#
# Sequencing notes:
#   - All /etc writes happen BEFORE systemd-tmpfiles-clean-style
#     sweeps, but we still touch /var/lib/apt/periodic directly so
#     apt's stamp is what the check expects.
#   - The fail2ban server is NOT started here — the driver starts it
#     post-boot and waits for `fail2ban-client ping` before banning
#     an IP (the server needs to be listening before banip sticks).
#   - The python3 http.server is started here in the background; the
#     driver waits for port 9999 to be LISTEN before running the
#     audit (this matters because at build time systemd is not yet
#     PID 1, so listening sockets started here may or may not survive
#     — the driver polls up to 30s to be safe).
#   - The 16 ssh_fails journald entries are written via `logger`,
#     which lands in journald even without rsyslog running. Threshold
#     is 15 (SSH_FAIL_THRESHOLD).
#
# This script is also the target of the negative-variant sed mutation
# in .github/workflows/integration-seeded.yml: removing the cron-d
# drop step causes system.cron_d_dropins to be absent from the
# audit's findings, which the assertion script catches.
set -euo pipefail

# 1. Apt cache stamp: empty file like the real one, mtime 5 days ago.
#    The check (maintenance.apt_cache_stale) flags any stamp older
#    than 48h, so 5 days reliably trips it.
mkdir -p /var/lib/apt/periodic
: > /var/lib/apt/periodic/update-success-stamp
touch -d '5 days ago' /var/lib/apt/periodic/update-success-stamp

# 2. Extra cron.d drop-in. install.sh seeds /var/lib/box-audit/
#    cron-d-allowlist.txt with the four standard names (anacron,
#    e2scrub_all, sysstat, 0hourly); this file is not on the list,
#    so the check emits system.cron_d_dropins.
printf 'fake-cron-line\n' > /etc/cron.d/0box-audit-test

# 3. Non-empty root crontab. install.sh and box-audit both run as
#    root, so `crontab -u root -l` is the lens the check uses.
printf '# dummy\n* * * * * /bin/echo fake\n' > /tmp/root-cron
crontab -u root /tmp/root-cron
rm -f /tmp/root-cron

# 4. Failed systemd unit. ExecStart=/bin/false is the cheapest way
#    to drive system.failed_units. The driver starts it explicitly
#    (rather than enabling-and-starting here) so the failure is
#    observable to systemd during the audit window.
cat > /etc/systemd/system/box-audit-fail.service <<'UNIT'
[Unit]
Description=box-audit seeded failure
[Service]
Type=oneshot
ExecStart=/bin/false
[Install]
WantedBy=multi-user.target
UNIT
systemctl enable box-audit-fail.service

# 5. Fail2ban sshd jail config. bantime.incremental = false stops
#    the ban from auto-expiring during the audit window
#    (fail2ban-reincidive can shorten bans on repeat offenders).
cat > /etc/fail2ban/jail.local <<'JAIL'
[sshd]
enabled = true
bantime.incremental = false
JAIL

# 6. Two seeded-state mutations are intentionally NOT here — they
#    need a running systemd and are done by the driver
#    (test/install-seeded.sh) post-boot:
#
#      - python3 -m http.server 9999: the security.new_port check
#        reads `ss -tlnH` and flags any port not in
#        ports-allowlist.txt (allowlist is 22/53/80/443/631).
#        Build-time nohup'd processes don't survive the RUN.
#
#      - 16 `logger -p auth.err -t sshd "Failed password ..."` lines:
#        the security.ssh_fails check counts 24h auth-fails. But
#        journald in jrei/systemd-ubuntu is volatile
#        (/var/log/journal is missing), so anything written at build
#        time is gone after the first boot. Driver seeds them after
#        systemd is PID 1.
#
# The driver also starts the failed unit (ExecStart=/bin/false is
# enough; `systemctl start` here would fail because systemd isn't
# running yet during build), grants sudoers for fail2ban-client,
# mutates /etc/passwd, and waits for fail2ban + the http.server to
# become ready before capturing --json.