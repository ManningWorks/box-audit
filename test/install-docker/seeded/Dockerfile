# Tier-2 seeded-container base for the integration-seeded CI job
# (issue #17). Built on top of test/install-docker/Dockerfile so the
# two paths share a base; this image only adds packages and seeded
# state. The driver (test/install-seeded.sh) builds the base image
# first as `box-audit-base:test`, then builds THIS file referencing
# that tag.
#
# Build sequence in test/install-seeded.sh:
#   docker build -t box-audit-base:test -f test/install-docker/Dockerfile .
#   docker build -t box-audit-install:seeded \
#       -f test/install-docker/seeded/Dockerfile .
#
# IMPORTANT: the build context for THIS Dockerfile is the repo root
# (test/install-seeded.sh uses `cp -R "$REPO/." "$WORK/"` as the
# context). The COPY path below is therefore relative to the repo
# root, not to the directory holding this Dockerfile.
#
# Seeded state inside the container (see seed.sh for the order):
#   - fail2ban + docker.io + rsyslog packages
#   - /var/lib/apt/periodic/update-success-stamp with mtime 5 days ago
#   - /etc/cron.d/0box-audit-test (extra cron drop-in)
#   - root crontab with one entry
#   - /etc/systemd/system/box-audit-fail.service (ExecStart=/bin/false)
#   - /etc/fail2ban/jail.local enabling the sshd jail
#   - python3 -m http.server 9999 listening on 127.0.0.1
#   - 16 journald auth.err entries (drives security.ssh_fails above threshold)
#
# The driver does the time-sensitive mutations after boot:
#   - systemctl start fail2ban + wait for `fail2ban-client ping`
#   - fail2ban-client set sshd banip 192.0.2.1
#   - systemctl start box-audit-fail.service (observe the failed unit)
#   - mutate /etc/passwd (drives integrity.change vs the install-time baseline)
FROM box-audit-base:test

RUN apt-get update && apt-get install -y --no-install-recommends \
        fail2ban \
        docker.io \
        rsyslog \
        cron \
        sudo \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Tell systemd we're running in a container (same env var the base
# image sets; restated for self-containment of this Dockerfile).
ENV container=docker \
    SYSTEMD_LOG_LEVEL=info

COPY test/install-docker/seeded/seed.sh /tmp/seed.sh
RUN bash /tmp/seed.sh && rm /tmp/seed.sh