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

# 3b. Deterministic security-pending updates (drives updates.security_pending
#     + the Issue #38 persist-sidecar "below-threshold field must be > 0"
#     probe AND the delta-mutation block, both in test/install-seeded.sh).
#
# The security_pending check (scripts/box-audit.sh:1351) counts lines in
# `apt list --upgradable` that mention "security". On a real box that is the
# live Ubuntu security pocket. The seeded container must NOT depend on live
# archive state — the archive drains and refills on a schedule, and when it
# hits 0: (a) the "below-threshold field must be > 0" sidecar probe fails
# (the 2026-10-01 master integration-seeded failure:
# `FAIL_PERSIST_SIDECAR: security_pending=0`), and (b) the mutated-security
# delta run needs today - yesterday > 1, which is impossible when
# today <= 1 (yesterday clamps to 0, delta = today = 1, not > 1).
#
# So we CREATE the pending updates: install base versions of three fixture
# packages, then expose a local file:// apt repo (Release Codename
# "resolute-security") that offers a NEWER version of each. After
# `apt-get update`, `apt list --upgradable` always carries three
# `boxaudit-sec* /resolute-security ... [upgradable from: ...]` lines ->
# `grep -ci security` is deterministically >= 3, independent of the archive.
# Three (not one) is the floor that keeps the delta-mutation arithmetic
# deterministic: today >= 3, so the clamped-yesterday path (today < 10)
# yields delta = today >= 3 > 1 and the natural path (today >= 10) yields
# delta = 10.
#
# Layout is the hierarchical form apt requires
# (dists/<dist>/main/binary-amd64/Packages + dists/<dist>/Release);
# `[trusted=yes]` skips GPG so no key is needed at build time. apt-ftparchive
# is NOT required — the Packages index is hand-written (dpkg-deb is shipped
# by the base image).
SEC_REPO=/opt/box-audit-security-fixture
SEC_DIST=resolute-security
SEC_WORK=/opt/box-audit-secfixture-build
# Three packages -> three upgradable security lines, the deterministic floor.
# dpkg-deb packages the WHOLE build tree, so each build gets its own isolated
# tree ($SEC_WORK/build-<pkg>-<ver>/) — a shared tree would let later .debs
# pick up earlier packages' /usr/bin files and dpkg -i would fail on the
# file-ownership conflict.
SEC_PKGS=(boxaudit-secfixture boxaudit-secfixture2 boxaudit-secfixture3)
build_sec_deb() { # $1 = pkg, $2 = version
    local pkg="$1" ver="$2" tree
    tree="$SEC_WORK/build-${pkg}-${ver//:/_}"
    mkdir -p "$tree/DEBIAN" "$tree/usr/bin"
    printf '#!/bin/sh\nexit 0\n' > "$tree/usr/bin/$pkg"
    chmod 0755 "$tree/usr/bin/$pkg"
    cat > "$tree/DEBIAN/control" <<EOF
Package: $pkg
Version: $ver
Architecture: amd64
Maintainer: box-audit <test@example.com>
Description: deterministic security-pending fixture
EOF
    dpkg-deb --build --root-owner-group "$tree" \
        "$SEC_WORK/${pkg}_${ver//:/_}.deb" >/dev/null
}
SEC_BASE=1:1.0
SEC_NEW=1:2.0
mkdir -p "$SEC_REPO/pool/main/b" "$SEC_REPO/dists/$SEC_DIST/main/binary-amd64"
for pkg in "${SEC_PKGS[@]}"; do
    # Install the base version so apt has something to upgrade FROM.
    build_sec_deb "$pkg" "$SEC_BASE"
    dpkg -i "$SEC_WORK/${pkg}_1_1.0.deb" >/dev/null 2>&1 || true
    # Newer version into the pool + append to the Packages index.
    build_sec_deb "$pkg" "$SEC_NEW"
    cp "$SEC_WORK/${pkg}_1_2.0.deb" "$SEC_REPO/pool/main/b/${pkg}_1_2.0.deb"
    printf 'Package: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: box-audit <test@example.com>\nFilename: pool/main/b/%s_1_2.0.deb\nDescription: deterministic security-pending fixture\n\n' \
        "$pkg" "$SEC_NEW" "$pkg" \
        >> "$SEC_REPO/dists/$SEC_DIST/main/binary-amd64/Packages"
done
cat > "$SEC_REPO/dists/$SEC_DIST/Release" <<EOF
Origin: box-audit-security-fixture
Label: box-audit-security-fixture
Suite: $SEC_DIST
Codename: $SEC_DIST
Architectures: amd64
Components: main
Date: 2026-01-01T00:00:00Z
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