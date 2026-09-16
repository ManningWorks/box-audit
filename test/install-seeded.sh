#!/usr/bin/env bash
# Driver for the tier-2 seeded-container integration CI job
# (issue #17). Mirrors test/install.sh line-for-line where possible,
# with seeded-state setup after boot.
#
#   bash test/install-seeded.sh [image-tag] [sed-mutation]
#
# With a sed-mutation, it is applied to seed.sh inside a throwaway
# build context first, so the negative variant can prove the JSON
# assertion gate has teeth without touching the working tree.
#
# The mutation target is test/install-docker/seeded/seed.sh (not
# Dockerfile), so removing one line in the cron-d drop step deletes
# the seeded state and the audit no longer emits
# system.cron_d_dropins — which the assertion script catches and
# exits non-zero over. The workflow inverts that exit into a pass
# (proving the gate caught the regression).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="${1:-box-audit-install:seeded}"
MUTATION="${2:-}"

# Base image (built from the existing test/install-docker/Dockerfile;
# tagged locally as box-audit-base:test so the seeded Dockerfile's
# FROM box-audit-base:test resolves).
BASE_TAG="box-audit-base:test"

# 1. Throwaway copy of the repo (plus optional mutation) as the
#    build context.
WORK="$(mktemp -d)"
cp -R "$REPO/." "$WORK/"

if [[ -n "$MUTATION" ]]; then
    # Apply the sed to the throwaway seed.sh only — never the working
    # tree. The negative-variant workflow mutates the cron-d drop
    # step.
    sed -i "$MUTATION" "$WORK/test/install-docker/seeded/seed.sh"
fi

# 2. Build base image (test/install-docker/Dockerfile), then the
#    seeded image which FROM-references it. Output suppressed to keep
#    CI logs readable; failures surface via non-zero exit.
docker build -t "$BASE_TAG" -f "$REPO/test/install-docker/Dockerfile" "$WORK" >/dev/null
docker build -t "$IMAGE_TAG" -f "$REPO/test/install-docker/seeded/Dockerfile" "$WORK" >/dev/null

# 3. Boot the container detached, exec install.sh --ci into the
#    running system. Same flag set as test/install.sh (privileged,
#    rw cgroup, tmpfs /run and /var/log) so the install path is
#    byte-identical between tier 1 and tier 2.
CID="$(docker run -d --privileged \
    --cgroupns=host \
    --tmpfs /run \
    --tmpfs /var/log \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$WORK":/work \
    -e container=docker \
    "$IMAGE_TAG")"

# Wait for systemd to accept commands. "degraded" means booted with
# some unit failed — fine; the assertion script judges the audit's
# findings.
STATE=""
for _ in $(seq 1 60); do
    STATE="$(docker exec "$CID" systemctl is-system-running 2>/dev/null || true)"
    case "$STATE" in
        running|degraded) break ;;
    esac
    sleep 1
done
if [[ "$STATE" != "running" && "$STATE" != "degraded" ]]; then
    echo "test/install-seeded.sh: systemd did not become ready (last state: '${STATE:-none}')" >&2
    exit 1
fi

# 4. Install.sh --ci. The first audit run inside install.sh's verify
#    gate seeds /var/lib/box-audit/integrity-baseline.json (root-only,
#    required before integrity.change can be asserted).
docker exec "$CID" /bin/bash -c 'cd /work && bash install.sh --ci' >/dev/null

# Grant NOPASSWD sudo for fail2ban-client — the security.fail2ban_banned
# check probes `sudo -n fail2ban-client` and silently skips the finding
# if sudo isn't usable. The audit's broader check_deps probe also
# flags 'sudo' as missing on PATH otherwise.
docker exec "$CID" /bin/bash -c '
    echo "ALL ALL=(root) NOPASSWD: /usr/bin/fail2ban-client" \
        > /etc/sudoers.d/box-audit-fail2ban
    chmod 0440 /etc/sudoers.d/box-audit-fail2ban
' >/dev/null

# 5. Start the seeded failed unit. systemd will record it as failed
#    in `systemctl --failed`, which is exactly what system.failed_units
#    reads.
docker exec "$CID" systemctl start box-audit-fail.service >/dev/null 2>&1 || true

# Start fail2ban and wait for the server to be ready before banning
# an IP. `fail2ban-client ping` returning "pong" is the documented
# readiness signal; `systemctl start` returns before the server is
# listening.
docker exec "$CID" systemctl start fail2ban >/dev/null 2>&1 || true
F2B_READY=""
for _ in $(seq 1 30); do
    if docker exec "$CID" fail2ban-client ping 2>/dev/null | grep -q "pong"; then
        F2B_READY=yes
        break
    fi
    sleep 1
done
if [[ -z "$F2B_READY" ]]; then
    echo "test/install-seeded.sh: fail2ban-server did not become ready" >&2
    exit 1
fi
docker exec "$CID" fail2ban-client set sshd banip 192.0.2.1 >/dev/null 2>&1 || true

# Start the python http.server that drives the new_port check.
# Backgrounded with setsid so it survives the docker exec
# subshell — pid is captured for cleanup.
docker exec "$CID" /bin/bash -c '
    setsid python3 -m http.server 9999 --bind 127.0.0.1 --directory /tmp \
        >/tmp/box-audit-seed-http.log 2>&1 < /dev/null &
    echo $! > /tmp/box-audit-seed-http.pid
' >/dev/null
HTTP_READY=""
for _ in $(seq 1 30); do
    if docker exec "$CID" ss -tlnH 2>/dev/null | grep -q ':9999 '; then
        HTTP_READY=yes
        break
    fi
    sleep 1
done
if [[ -z "$HTTP_READY" ]]; then
    echo "test/install-seeded.sh: python http.server did not bind to 9999" >&2
    docker exec "$CID" cat /tmp/box-audit-seed-http.log >&2 || true
    exit 1
fi

# 6. Mutate /etc/passwd AFTER the install-time integrity baseline was
#    written. The check hashes /etc/passwd on every run and diffs
#    against /var/lib/box-audit/integrity-baseline.json; this
#    mutation is what makes integrity.change fire.
docker exec "$CID" /bin/bash -c 'echo "# seeded-mutation $(date +%s)" >> /etc/passwd' >/dev/null

# 7. Seed 16 ssh_fails journald entries. Threshold is 15
#    (SSH_FAIL_THRESHOLD), so 16 trips the warn. `logger -p auth.err
#    -t sshd` writes to journald with the auth facility — same lens
#    the check reads. Build-time logger calls were discarded:
#    jrei/systemd-ubuntu's journald is volatile (no
#    /var/log/journal/), so anything seeded at build time is gone
#    after the first boot. Documentation-range IP (192.0.2.0/24)
#    per RFC 5737.
for _ in $(seq 1 16); do
    docker exec "$CID" logger -p auth.err -t sshd \
        "Failed password for invalid user admin from 192.0.2.1 port 22 ssh2"
done

# 8. Kill containerd if it's listening — it ships with the
#     jrei/systemd-ubuntu image and binds a high port inside the
#     container. The security.new_port check fires for *any* port
#     not in the baseline; we want exactly one finding (the seeded
#     python http.server on 9999), so silence containerd here. Best
#     effort — a missing containerd shouldn't fail the run.
docker exec "$CID" /bin/bash -c \
    'pkill -f containerd || true; sleep 1' >/dev/null 2>&1 || true

# Capture --json output and run the assertion script.
BA_JSON="$(mktemp)"
BA_ERR="$(mktemp)"
# Best-effort cleanup: docker rm -f may legitimately return non-zero
# when the container is already gone. The `|| true` keeps the trap
# itself from failing the run under `set -e`.
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true; rm -rf "$WORK" "$BA_JSON" "$BA_ERR"' EXIT

docker exec "$CID" /usr/local/bin/box-audit --json > "$BA_JSON" 2>"$BA_ERR" || true

if ! python3 "$REPO/test/install-seeded/assert-json.py" < "$BA_JSON"; then
    echo "test/install-seeded.sh: JSON assertions failed" >&2
    echo "--- audit stderr ---" >&2
    cat "$BA_ERR" >&2
    echo "--- audit stdout (last 50 lines) ---" >&2
    tail -50 "$BA_JSON" >&2
    exit 1
fi

# 9. Regression: box-audit --init must populate timers-baseline.txt
# with the actual .timer units from `systemctl list-timers --all`.
# Before issue #12 was fixed, --init silently wrote 0 bytes (python
# IndentationError in the init block's python3 -c heredoc); the seeded
# install.sh filled the file with 21 lines from its own seed, so the
# regression stayed invisible until someone ran --init manually on a
# seeded box. The assertion below runs --init against a wiped file
# and compares against a fresh filter of `systemctl list-timers` so
# any future regression of this class fails the tier-2 gate.
docker exec "$CID" /bin/bash -c '
    set -e
    : > /var/lib/box-audit/timers-baseline.txt
    /usr/local/bin/box-audit --init >/dev/null
' || { echo "test/install-seeded.sh: box-audit --init failed post-wipe" >&2; exit 1; }

INIT_LINES="$(docker exec "$CID" /bin/bash -c '/usr/bin/wc -l < /var/lib/box-audit/timers-baseline.txt')"
if [[ "${INIT_LINES:-0}" -eq 0 ]]; then
    echo "test/install-seeded.sh: timers-baseline.txt is empty after --init (regression of issue #12)" >&2
    exit 1
fi

EXPECTED="$(docker exec "$CID" /bin/bash -c '
    /usr/bin/systemctl list-timers --all --no-pager --no-legend --output json 2>/dev/null \
        | /usr/bin/python3 -c "import sys,json
for r in json.load(sys.stdin):
    u=r.get(\"unit\",\"\")
    if u.endswith(\".timer\"): print(u)"' | /usr/bin/sort -u)"
ACTUAL="$(docker exec "$CID" /bin/bash -c '/usr/bin/sort -u /var/lib/box-audit/timers-baseline.txt')"
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    echo "test/install-seeded.sh: --init output does not match 'systemctl list-timers --all | .timer filter'" >&2
    echo "--- expected ---" >&2
    echo "$EXPECTED" >&2
    echo "--- actual ---" >&2
    echo "$ACTUAL" >&2
    exit 1
fi

echo "test/install-seeded.sh: seeded-container integration PASSED"