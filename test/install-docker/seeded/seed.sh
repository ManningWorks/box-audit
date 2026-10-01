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

# 3b. Deterministic security-pending update (drives updates.security_pending
#     + the Issue #38 persist-sidecar "below-threshold field must be > 0"
#     probe in test/install-seeded.sh).
#
# The security_pending check (scripts/box-audit.sh:1351) counts lines in
# `apt list --upgradable` that mention "security". On a real box that is the
# live Ubuntu security pocket. The seeded container must NOT depend on live
# archive state — the archive drains and refills on a schedule, and when it
# hits 0 the "below-threshold field must be > 0" assertion in the driver
# flips to a fail (the 2026-10-01 master integration-seeded failure:
# `FAIL_PERSIST_SIDECAR: security_pending=0`).
#
# So we CREATE the pending update: install a base version of a fixture
# package, then expose a local file:// apt repo whose Release Codename is
# "resolute-security" and which offers a NEWER version. After `apt-get
# update`, `apt list --upgradable` always carries
# `boxaudit-secfixture/resolute-security ... [upgradable from: ...]` ->
# `grep -ci security` is deterministically >= 1, independent of the archive.
#
# Layout is the hierarchical form apt requires
# (dists/<dist>/main/binary-amd64/Packages + dists/<dist>/Release);
# `[trusted=yes]` skips GPG so no key is needed at build time. apt-ftparchive
# is NOT required — the Packages index is hand-written (dpkg-deb is shipped
# by the base image).
SEC_REPO=/opt/box-audit-security-fixture
SEC_PKG=boxaudit-secfixture
SEC_BASE=1:1.0
SEC_NEW=1:2.0
SEC_DIST=resolute-security
SEC_WORK=/opt/box-audit-secfixture-build
mkdir -p "$SEC_WORK/deb/DEBIAN" "$SEC_WORK/deb/usr/bin"
build_sec_deb() { # $1 = version
    printf '#!/bin/sh\nexit 0\n' > "$SEC_WORK/deb/usr/bin/$SEC_PKG"
    chmod 0755 "$SEC_WORK/deb/usr/bin/$SEC_PKG"
    cat > "$SEC_WORK/deb/DEBIAN/control" <<EOF
Package: $SEC_PKG
Version: $1
Architecture: amd64
Maintainer: box-audit <test@example.com>
Description: deterministic security-pending fixture
EOF
    dpkg-deb --build --root-owner-group "$SEC_WORK/deb" \
        "$SEC_WORK/${SEC_PKG}_${1//:/_}.deb" >/dev/null
}
# Install the base version so apt has something to upgrade FROM.
build_sec_deb "$SEC_BASE"
dpkg -i "$SEC_WORK/${SEC_PKG}_1_1.0.deb" >/dev/null 2>&1 || true
# Newer version laid out as a local apt repo.
build_sec_deb "$SEC_NEW"
mkdir -p "$SEC_REPO/pool/main/b" "$SEC_REPO/dists/$SEC_DIST/main/binary-amd64"
cp "$SEC_WORK/${SEC_PKG}_1_2.0.deb" "$SEC_REPO/pool/main/b/${SEC_PKG}_1_2.0.deb"
cat > "$SEC_REPO/dists/$SEC_DIST/main/binary-amd64/Packages" <<EOF
Package: $SEC_PKG
Version: $SEC_NEW
Architecture: amd64
Maintainer: box-audit <test@example.com>
Filename: pool/main/b/${SEC_PKG}_1_2.0.deb
Description: deterministic security-pending fixture
EOF
cat > "$SEC_REPO/dists/$SEC_DIST/Release" <<EOF
Origin: box-audit-security-fixture
Label: box-audit-security-fixture
Suite: $SEC_DIST
Codename: $SEC_DIST
Architectures: amd64
Components: main
Description: local security-pending fixture for the seeded audit tier
EOF
# Point apt at the local repo (trusted: no GPG at build time) and refresh.
printf 'deb [trusted=yes] file://%s %s main\n' \
    "$SEC_REPO" "$SEC_DIST" \
    > /etc/apt/sources.list.d/box-audit-security-fixture.list
apt-get update -qq 2>/dev/null || true
# The apt-get update above refreshes the periodic stamp to "now", which
# would clear the maintenance.apt_cache_stale finding (step 1 stamped it 5
# days old). Re-stamp it stale after the refresh so both seeded conditions
# hold at audit time.
: > /var/lib/apt/periodic/update-success-stamp
touch -d '5 days ago' /var/lib/apt/periodic/update-success-stamp

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

# 5. Fail2ban jail config: sshd (the security.fail2ban_banned floor) plus
#    recidive (a second, non-sshd jail that drives the F2 jail-discovery
#    check — security.fail2ban_jail). bantime.incremental = false stops the
#    ban from auto-expiring during the audit window. The driver bans one
#    documentation IP on each jail post-boot (sshd 192.0.2.1, recidive
#    203.0.113.7).
cat > /etc/fail2ban/jail.local <<'JAIL'
[sshd]
enabled = true
bantime.incremental = false

[recidive]
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