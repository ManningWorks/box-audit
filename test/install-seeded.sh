#!/usr/bin/env bash
# Driver for the tier-2 seeded-container integration CI job
# (issue #17). Mirrors test/install.sh line-for-line where possible,
# with seeded-state setup after boot.
#
#   bash test/install-seeded.sh [image-tag] [sed-mutation]
#
# With a sed-mutation, it is applied to seed.sh inside the throwaway
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

# shellcheck source=./install-lib.sh
# shellcheck disable=SC1091
source "$(dirname "$0")/install-lib.sh"

# Stage WORK once and share it across both builds. The seeded Dockerfile's
# COPY test/install-docker/seeded/seed.sh uses a repo-relative path, so
# both the base build and the seeded build must read from the same
# context dir. We mktemp here and pass it into both privileged_build
# calls so the library's `cp -R` only runs once.
SEEDED_WORK="$(mktemp -d)"
LIB_CLEANUP_PATHS+=("$SEEDED_WORK")

privileged_build "$REPO/test/install-docker/Dockerfile" "$BASE_TAG" "$SEEDED_WORK"

if [[ -n "$MUTATION" ]]; then
    # Apply the sed to the throwaway seed.sh only — never the working
    # tree. The negative-variant workflow mutates the cron-d drop step.
    sed -i "$MUTATION" "$SEEDED_WORK/test/install-docker/seeded/seed.sh"
fi

privileged_build "$REPO/test/install-docker/seeded/Dockerfile" "$IMAGE_TAG" "$SEEDED_WORK"

privileged_prep "$IMAGE_TAG"

# Install.sh --ci. The first audit run inside install.sh's verify
# gate seeds /var/lib/box-audit/integrity-baseline.json (root-only,
# required before integrity.change can be asserted).
privileged_exec /bin/bash -c 'cd /work && bash install.sh --ci' >/dev/null

# Grant NOPASSWD sudo for fail2ban-client — the security.fail2ban_banned
# check probes `sudo -n fail2ban-client` and silently skips the finding
# if sudo isn't usable. The audit's broader check_deps probe also
# flags 'sudo' as missing on PATH otherwise.
privileged_exec /bin/bash -c '
    echo "ALL ALL=(root) NOPASSWD: /usr/bin/fail2ban-client" \
        > /etc/sudoers.d/box-audit-fail2ban
    chmod 0440 /etc/sudoers.d/box-audit-fail2ban
' >/dev/null

# Start the seeded failed unit. systemd will record it as failed in
# `systemctl --failed`, which is exactly what system.failed_units reads.
privileged_exec systemctl start box-audit-fail.service >/dev/null 2>&1 || true

# Start fail2ban and wait for the server to be ready before banning
# an IP. `fail2ban-client ping` returning "pong" is the documented
# readiness signal; `systemctl start` returns before the server is
# listening.
#
# The recidive jail (drives the F2 jail-discovery check) inherits the
# default logpath /var/log/fail2ban.log, and the container mounts /var/log
# as a tmpfs so the build-time file is hidden at runtime. fail2ban-server
# refuses to start when a jail's logpath is missing, so create the file
# here, at boot, before the start.
privileged_exec touch /var/log/fail2ban.log >/dev/null 2>&1 || true
privileged_exec systemctl start fail2ban >/dev/null 2>&1 || true
F2B_READY=""
for _ in $(seq 1 30); do
    if privileged_exec fail2ban-client ping 2>/dev/null | grep -q "pong"; then
        F2B_READY=yes
        break
    fi
    sleep 1
done
if [[ -z "$F2B_READY" ]]; then
    echo "test/install-seeded.sh: fail2ban-server did not become ready" >&2
    exit 1
fi
privileged_exec fail2ban-client set sshd banip 192.0.2.1 >/dev/null 2>&1 || true
# Ban one documentation IP on the second (non-sshd) jail too — recidive
# drives the F2 jail-discovery check (security.fail2ban_jail). Different IPs
# keep the two findings' messages distinguishable (sshd 192.0.2.1, recidive
# 203.0.113.7, both RFC 5737 documentation ranges).
privileged_exec fail2ban-client set recidive banip 203.0.113.7 >/dev/null 2>&1 || true

# Start the python http.server that drives the new_port check.
# Backgrounded with setsid so it survives the docker exec subshell —
# pid is captured for cleanup.
privileged_exec /bin/bash -c '
    setsid python3 -m http.server 9999 --bind 127.0.0.1 --directory /tmp \
        >/tmp/box-audit-seed-http.log 2>&1 < /dev/null &
    echo $! > /tmp/box-audit-seed-http.pid
' >/dev/null
HTTP_READY=""
for _ in $(seq 1 30); do
    if privileged_exec ss -tlnH 2>/dev/null | grep -q ':9999 '; then
        HTTP_READY=yes
        break
    fi
    sleep 1
done
if [[ -z "$HTTP_READY" ]]; then
    echo "test/install-seeded.sh: python http.server did not bind to 9999" >&2
    privileged_exec cat /tmp/box-audit-seed-http.log >&2 || true
    exit 1
fi

# Mutate /etc/passwd AFTER the install-time integrity baseline was
# written. The check hashes /etc/passwd on every run and diffs
# against /var/lib/box-audit/integrity-baseline.json; this mutation
# is what makes integrity.change fire. The $(date +%s) is intentionally
# evaluated by the *container's* shell (we want a fresh timestamp each
# run, not the host's build-time clock), so SC2016 is wrong here.
# shellcheck disable=SC2016
privileged_exec /bin/bash -c 'echo "# seeded-mutation $(date +%s)" >> /etc/passwd' >/dev/null

# Seed 16 ssh_fails journald entries. Threshold is 15
# (SSH_FAIL_THRESHOLD), so 16 trips the warn. `logger -p auth.err
# -t sshd` writes to journald with the auth facility — same lens
# the check reads. Build-time logger calls were discarded:
# jrei/systemd-ubuntu's journald is volatile (no
# /var/log/journal/), so anything seeded at build time is gone
# after the first boot. Documentation-range IP (192.0.2.0/24)
# per RFC 5737.
for _ in $(seq 1 16); do
    privileged_exec logger -p auth.err -t sshd \
        "Failed password for invalid user admin from 192.0.2.1 port 22 ssh2"
done

# Kill containerd if it's listening — it ships with the
# jrei/systemd-ubuntu image and binds a high port inside the
# container. The security.new_port check fires for *any* port
# not in the baseline; we want exactly one finding (the seeded
# python http.server on 9999), so silence containerd here. Best
# effort — a missing containerd shouldn't fail the run.
privileged_exec /bin/bash -c \
    'pkill -f containerd || true; sleep 1' >/dev/null 2>&1 || true

# Capture --json output and run the assertion script.
BA_JSON="$(mktemp)"
BA_ERR="$(mktemp)"
LIB_CLEANUP_PATHS+=("$BA_JSON" "$BA_ERR")

docker exec "$CID" /usr/local/bin/box-audit --json > "$BA_JSON" 2>"$BA_ERR" || true

if ! python3 "$REPO/test/install-seeded/assert-json.py" < "$BA_JSON"; then
    echo "test/install-seeded.sh: JSON assertions failed" >&2
    echo "--- audit stderr ---" >&2
    cat "$BA_ERR" >&2
    echo "--- audit stdout (last 50 lines) ---" >&2
    tail -50 "$BA_JSON" >&2
    exit 1
fi

# --- Issue #38 regression: persist-write sidecar witness (H1) --------------
# Pin the second half of the #38 contract the existing tier-2 block above
# leaves un-observed: history_persist_live_counts must actually write
# /var/log/box-audit/history/.latest-counts.json with today's live
# counts so that tomorrow's delta check has a baseline to read from.
# The constant/mutated runs below exercise the *load* path; they plant
# the sidecar by hand, so any regression here (key rename between emitter
# and reader, silent-no-write bug, starvation of the counts vars) would
# stay invisible to them. This block reads the sidecar back untouched —
# the one the audit just wrote during the BA_JSON capture above — and
# asserts it agrees with what the audit emitted.
#
# Sidecar keys (scripts/box-audit.sh:1389-1395): outbound_count,
# suid_count, security_pending. stdout JSON emitter uses
# outbound_remote_count (renamed in the sidecar by persist). Equality
# across all three is the load-bearing check; "suid_count > 0 AND
# security_pending > 0" pins the regression class the old code fell
# into (writing 0 for below-threshold counts because findings[] only
# carries a count when the absolute check tripped).
SIDECAR_JSON="$(privileged_exec /usr/bin/cat /var/log/box-audit/history/.latest-counts.json)"
if [[ -z "$SIDECAR_JSON" ]]; then
    echo "test/install-seeded.sh: FAIL — persist sidecar .latest-counts.json is empty or missing after --json run" >&2
    echo "(history_persist_live_counts did not write, or write failed silently)" >&2
    exit 1
fi
# The probe script exits non-zero when its findings disagree; under
# `set -e`, that would abort the driver before this block's own
# `exit 1` ever runs (silent failure). || true swallows the rc so the
# assignment lands, then we branch on the captured value below.
SIDECAR_PROBE_OUT="$(SIDECAR_JSON="$SIDECAR_JSON" BA_JSON="$BA_JSON" python3 - <<'PY' || true
import json, os, sys
sidecar = json.loads(os.environ["SIDECAR_JSON"])
stdout_counts = json.load(open(os.environ["BA_JSON"]))["counts"]
# Sidecar keys (renamed in history_persist_live_counts at
# scripts/box-audit.sh:1389-1395).
checks = [
    ("suid_count",         "suid_count"),
    ("outbound_count",     "outbound_remote_count"),  # rename witnessed here
    ("security_pending",   "security_pending"),
]
problems = []
for sidecar_key, stdout_key in checks:
    s = sidecar.get(sidecar_key)
    o = stdout_counts.get(stdout_key)
    if s != o:
        problems.append(f"{sidecar_key}: sidecar={s!r} stdout={o!r} (mismatch)")
# Below-threshold fields must be NON-ZERO — this is the exact invariant
# the old code broke: it sourced counts from findings[], which only
# carries a count when the absolute check tripped, so a healthy seeded
# box recorded 0 for every one of the three and tomorrow's delta
# computed today's-live - 0 = today's-live. On this seeded jrei image
# suid_count=9 and security_pending=9 are the typical values; outbound
# is intentionally skipped (the seeded container has no outbound
# remote connections, so a >0 assertion would be false-positive-prone).
for key in ("suid_count", "security_pending"):
    v = sidecar.get(key)
    if not isinstance(v, int) or v <= 0:
        problems.append(f"{key}={v!r} (below-threshold field must be > 0 in sidecar)")
if problems:
    print("FAIL_PERSIST_SIDECAR:" + "; ".join(problems))
    sys.exit(1)
print(f"OK suid={sidecar['suid_count']} outbound={sidecar['outbound_count']} security_pending={sidecar['security_pending']}")
PY
)"
if [[ "$SIDECAR_PROBE_OUT" == OK* ]]; then
    echo "test/install-seeded.sh: persist sidecar agrees with --json counts (${SIDECAR_PROBE_OUT#OK })"
else
    echo "test/install-seeded.sh: FAIL — persist sidecar disagrees with --json counts" >&2
    echo "$SIDECAR_PROBE_OUT" >&2
    echo "--- sidecar ---" >&2
    echo "$SIDECAR_JSON" >&2
    echo "--- audit stdout ---" >&2
    cat "$BA_JSON" >&2
    exit 1
fi

# --- F1/0.9.0: --init idempotency report (both branches) --------------------
# install.sh seeds the five config files with comment-heavy defaults; the
# first post-install --init rewrites them from live state, so it must report
# "seeded ...". An immediate re-run over an unchanged box must report the
# no-op line instead — this is the branch tier 1 can only cover where root is
# available, and the one an operator runs as a smoke check. Then a manual
# edit to one allowlist must flip the report back to "seeded ..." (the edit
# differs from anything --init would write, so the rewrite is real; the
# rewrite also removes the junk line, leaving the config valid for the
# issue-#12 block below).
INIT_OUT="$(privileged_exec /usr/local/bin/box-audit --init || true)"
if [[ "$INIT_OUT" == "box-audit: seeded "* ]]; then
    echo "test/install-seeded.sh: first --init after install reports seeded"
elif [[ "$INIT_OUT" == "box-audit: config unchanged at /var/lib/box-audit" ]]; then
    echo "test/install-seeded.sh: FAIL — first --init after install reported unchanged; install.sh defaults must differ from a live snapshot" >&2
    exit 1
else
    echo "test/install-seeded.sh: FAIL — first --init after install emitted neither 'seeded' nor 'config unchanged': $INIT_OUT" >&2
    exit 1
fi
INIT_OUT="$(privileged_exec /usr/local/bin/box-audit --init || true)"
if [[ "$INIT_OUT" == "box-audit: config unchanged at /var/lib/box-audit" ]]; then
    echo "test/install-seeded.sh: no-op --init re-run reports config unchanged"
else
    echo "test/install-seeded.sh: FAIL — no-op --init re-run did not report 'config unchanged': $INIT_OUT" >&2
    exit 1
fi
privileged_exec /bin/bash -c 'echo box-audit-test-junk >> /var/lib/box-audit/ports-allowlist.txt' >/dev/null
INIT_OUT="$(privileged_exec /usr/local/bin/box-audit --init || true)"
if [[ "$INIT_OUT" == "box-audit: seeded "* ]]; then
    echo "test/install-seeded.sh: --init after a manual allowlist edit reports seeded again"
else
    echo "test/install-seeded.sh: FAIL — --init after a manual allowlist edit did not report 'seeded ...': $INIT_OUT" >&2
    exit 1
fi

# Regression: box-audit --init must populate timers-baseline.txt
# with the actual .timer units from `systemctl list-timers --all`.
# Before issue #12 was fixed, --init silently wrote 0 bytes (python
# IndentationError in the init block's python3 -c heredoc); the seeded
# install.sh filled the file with 21 lines from its own seed, so the
# regression stayed invisible until someone ran --init manually on a
# seeded box. The assertion below runs --init against a wiped file
# and compares against a fresh filter of `systemctl list-timers` so
# any future regression of this class fails the tier-2 gate.
privileged_exec /bin/bash -c '
    set -e
    : > /var/lib/box-audit/timers-baseline.txt
    /usr/local/bin/box-audit --init >/dev/null
' || { echo "test/install-seeded.sh: box-audit --init failed post-wipe" >&2; exit 1; }

INIT_LINES="$(privileged_exec /bin/bash -c '/usr/bin/wc -l < /var/lib/box-audit/timers-baseline.txt')"
if [[ "${INIT_LINES:-0}" -eq 0 ]]; then
    echo "test/install-seeded.sh: timers-baseline.txt is empty after --init (regression of issue #12)" >&2
    exit 1
fi

EXPECTED="$(privileged_exec /bin/bash -c '
    /usr/bin/systemctl list-timers --all --no-pager --no-legend --output json 2>/dev/null \
        | /usr/bin/python3 -c "import sys,json
for r in json.load(sys.stdin):
    u=r.get(\"unit\",\"\")
    if u.endswith(\".timer\"): print(u)"' | /usr/bin/sort -u)"
ACTUAL="$(privileged_exec /bin/bash -c '/usr/bin/sort -u /var/lib/box-audit/timers-baseline.txt')"
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    echo "test/install-seeded.sh: --init output does not match 'systemctl list-timers --all | .timer filter'" >&2
    echo "--- expected ---" >&2
    echo "$EXPECTED" >&2
    echo "--- actual ---" >&2
    echo "$ACTUAL" >&2
    exit 1
fi

# --- F4 (0.9.0): IPv6 outbound parity — both live branches ------------------
# The v6 finding (security.outbound_remote_count_v6) reads the same
# `ss -tnp state established` stream as the combined check and cannot be
# faked any other way (no env override — see
# test/properties/security.outbound_remote_count_v6.sh). This block drives
# both branches with real sockets:
#
#   1. v6-to-public: two ESTAB IPv6 connections to documentation-range
#      (RFC 3849 2001:db8::/32) addresses added on the container's lo.
#      Loopback carries no v6 default route, so `ip -6 addr add` makes the
#      addrs local and connect() succeeds without any external network —
#      the kernel reports two ESTAB v6 sockets, exactly what the check
#      parses. The threshold is lowered to 1 (the minimum valid value)
#      via the EXISTING --outbound-threshold knob — no new per-box config,
#      and 25 would need 26 connections.
#   2. v6-quiet: after the holder expires and the sockets tear down, a
#      second audit must show no v6 finding — v6 capability without v6
#      traffic stays quiet (this is also the graceful-degradation proof
#      for boxes that simply have no v6 traffic).
#
# On a runner whose kernel/bridge has no IPv6 stack, seeding fails at
# `ip -6 addr add`; the block skips itself with a note (the property
# suite's replay assertions still cover the finding's semantics).
# shellcheck disable=SC2016  # bash -c string is deliberately single-quoted
SEED_V6_OUT="$(privileged_exec /bin/bash -c '
    set -e
    ip -6 addr add 2001:db8::100/128 dev lo
    ip -6 addr add 2001:db8::101/128 dev lo
    # Holder: two listeners held at module scope (a loop that reassigns a
    # single socket var drops the first reference and CPython refcount-
    # closes that listener — the connect then hits ECONNREFUSED) + two
    # ESTAB connects. setsid detaches it from this exec session.
    setsid python3 -c "
import socket, time
def listen(ip, port):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(5)
    return s
ls1 = listen(\"2001:db8::100\", 443)
ls2 = listen(\"2001:db8::101\", 443)
c1 = socket.create_connection((\"2001:db8::100\", 443))
c2 = socket.create_connection((\"2001:db8::101\", 443))
time.sleep(30)
" &
    sleep 3
    # The holder must have produced exactly the two ESTAB v6 remotes the
    # check will see. Fewer means the connect raced; fail the seed so the
    # driver skips gracefully instead of asserting on a half-state.
    n=$(ss -tnp state established | grep -c "2001:db8::10" || true)
    [[ "$n" -ge 2 ]]
    echo 1 > /var/lib/box-audit/outbound-threshold.conf
    echo SEED_OK
' 2>&1 || true)"
if [[ "$SEED_V6_OUT" == *SEED_OK* ]]; then
    echo "test/install-seeded.sh: seeded 2 ESTAB v6 remotes (2001:db8::100/101 on lo), threshold=1"
    BA_JSON_V6="$(mktemp)"
    LIB_CLEANUP_PATHS+=("$BA_JSON_V6")
    if ! privileged_exec /usr/local/bin/box-audit --json > "$BA_JSON_V6" 2>/dev/null; then
        echo "test/install-seeded.sh: box-audit --json (v6-seeded run) exited non-zero" >&2
        exit 1
    fi
    V6_PROBE_OUT="$(BA_JSON_V6="$BA_JSON_V6" python3 - <<'PY' || true
import json, os
d = json.load(open(os.environ["BA_JSON_V6"]))
v6 = [f for f in d.get("findings", []) if f.get("check_id") == "security.outbound_remote_count_v6"]
comb = [f for f in d.get("findings", []) if f.get("check_id") == "security.outbound_remote_count"]
probs = []
if len(v6) != 1:
    probs.append(f"expected exactly 1 v6 finding, got {len(v6)}: {v6}")
else:
    if v6[0].get("severity") != "warn":
        probs.append(f"v6 severity {v6[0].get('severity')!r} != warn")
    if v6[0].get("count") != 2:
        probs.append(f"v6 count {v6[0].get('count')!r} != 2 (two distinct doc-range remotes)")
    msg = v6[0].get("message", "")
    if "2001:db8::100" not in msg or "2001:db8::101" not in msg:
        probs.append(f"v6 message missing both doc-range remotes: {msg!r}")
if not comb:
    probs.append("combined security.outbound_remote_count did not fire alongside the v6 finding")
if probs:
    print("FAIL_V6:" + "; ".join(probs))
    raise SystemExit(1)
print(f"OK v6={v6[0]['count']} comb={comb[0]['count']}")
PY
)"
    if [[ "$V6_PROBE_OUT" == OK* ]]; then
        echo "test/install-seeded.sh: v6-seeded run fired security.outbound_remote_count_v6 as expected (${V6_PROBE_OUT#OK })"
    else
        echo "test/install-seeded.sh: FAIL — v6-seeded run findings wrong: $V6_PROBE_OUT" >&2
        echo "--- audit stdout ---" >&2
        cat "$BA_JSON_V6" >&2
        exit 1
    fi
    # Restore the threshold before the Issue #38 delta block reads the
    # sidecar this run just wrote (it plants its own sidecar, but the
    # live counts at that point must not include this block's sockets).
    privileged_exec /bin/bash -c 'echo 25 > /var/lib/box-audit/outbound-threshold.conf'
    # Branch A: wait for the holder to expire, then the v6 finding must
    # be gone. The holder sleeps 30s; poll up to 30s for the ESTAB v6
    # rows to disappear so the second audit runs on a settled netns.
    for _ in $(seq 1 30); do
        if ! privileged_exec ss -tnp state established 2>/dev/null | grep -q '2001:db8::10'; then
            break
        fi
        sleep 1
    done
    BA_JSON_NOV6="$(mktemp)"
    LIB_CLEANUP_PATHS+=("$BA_JSON_NOV6")
    if ! privileged_exec /usr/local/bin/box-audit --json > "$BA_JSON_NOV6" 2>/dev/null; then
        echo "test/install-seeded.sh: box-audit --json (v6-quiet run) exited non-zero" >&2
        exit 1
    fi
    NOV6_HITS="$(python3 -c '
import json
d = json.load(open("'"$BA_JSON_NOV6"'"))
hits = [f["check_id"] for f in d.get("findings", []) if f.get("check_id") == "security.outbound_remote_count_v6"]
print("yes" if hits else "no")
')"
    if [[ "$NOV6_HITS" == "no" ]]; then
        echo "test/install-seeded.sh: v6-quiet run fired no v6 finding (sockets torn down)"
    else
        echo "test/install-seeded.sh: FAIL — v6-quiet run still fired the v6 finding" >&2
        echo "--- audit stdout ---" >&2
        cat "$BA_JSON_NOV6" >&2
        exit 1
    fi
else
    echo "test/install-seeded.sh: SKIP — v6 outbound block: no IPv6 stack in this container (seeding failed: ${SEED_V6_OUT:-empty}); property suite covers the finding's replay semantics"
fi

# --- issue #53: IPv4 outbound peer column — live 6.x regression ------------
# The combined finding's v4 side historically hardcoded field $5 for the
# remote (peer) address. iproute2 6.x suppresses the constant State column
# and shifts the peer to field 4, so $5 read empty and the v4 outbound
# check went blind on any 6.x box. This block drives the live path with
# real sockets, mirroring the F4 v6 block above:
#
#   1. v4-to-public: two ESTAB IPv4 connections to documentation-range
#      (RFC 5737 198.51.100.0/24) addresses added on the container's lo.
#      The seeded container ships iproute2 6.x, so this exercises the
#      previously-blind 6.x column layout. The threshold is lowered to 1
#      via the existing --outbound-threshold knob, then restored.
#   2. v4-quiet: after the holder expires and the sockets tear down, a
#      second audit must show no combined finding — the v4 capability
#      without v4 traffic stays quiet.
#
# On a runner where seeding fails the block skips itself; the property
# suite (security.outbound_remote_count_v4.sh) still covers the
# header-driven extraction against 5.x- and 6.x-shaped ss captures.
# shellcheck disable=SC2016  # bash -c string is deliberately single-quoted
SEED_V4_OUT="$(privileged_exec /bin/bash -c '
    set -e
    ip -4 addr add 198.51.100.100/32 dev lo
    ip -4 addr add 198.51.100.101/32 dev lo
    # Holder: two listeners held at module scope + two ESTAB connects.
    # setsid detaches it from this exec session.
    setsid python3 -c "
import socket, time
def listen(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(5)
    return s
ls1 = listen(\"198.51.100.100\", 443)
ls2 = listen(\"198.51.100.101\", 443)
c1 = socket.create_connection((\"198.51.100.100\", 443))
c2 = socket.create_connection((\"198.51.100.101\", 443))
time.sleep(30)
" &
    sleep 3
    n=$(ss -tnp state established | grep -c "198.51.100" || true)
    [[ "$n" -ge 2 ]]
    echo 1 > /var/lib/box-audit/outbound-threshold.conf
    echo SEED_OK
' 2>&1 || true)"
if [[ "$SEED_V4_OUT" == *SEED_OK* ]]; then
    echo "test/install-seeded.sh: seeded 2 ESTAB v4 remotes (198.51.100.100/101 on lo), threshold=1"
    BA_JSON_V4="$(mktemp)"
    LIB_CLEANUP_PATHS+=("$BA_JSON_V4")
    if ! privileged_exec /usr/local/bin/box-audit --json > "$BA_JSON_V4" 2>/dev/null; then
        echo "test/install-seeded.sh: box-audit --json (v4-seeded run) exited non-zero" >&2
        exit 1
    fi
    V4_PROBE_OUT="$(BA_JSON_V4="$BA_JSON_V4" python3 - <<'PY' || true
import json, os
d = json.load(open(os.environ["BA_JSON_V4"]))
comb = [f for f in d.get("findings", []) if f.get("check_id") == "security.outbound_remote_count"]
probs = []
if len(comb) != 1:
    probs.append(f"expected exactly 1 combined finding, got {len(comb)}: {comb}")
else:
    if comb[0].get("severity") != "warn":
        probs.append(f"combined severity {comb[0].get('severity')!r} != warn")
    # The combined counter includes any baseline non-LAN v4 traffic, so
    # assert the two seeded remotes are present rather than an exact
    # count (mirrors the F4 block's defensiveness on the combined finding).
    msg = comb[0].get("message", "")
    if "198.51.100.100" not in msg or "198.51.100.101" not in msg:
        probs.append(f"combined message missing both doc-range v4 remotes: {msg!r}")
    if comb[0].get("count", 0) < 2:
        probs.append(f"combined count {comb[0].get('count')!r} < 2")
if probs:
    print("FAIL_V4:" + "; ".join(probs))
    raise SystemExit(1)
print(f"OK comb={comb[0]['count']}")
PY
)"
    if [[ "$V4_PROBE_OUT" == OK* ]]; then
        echo "test/install-seeded.sh: v4-seeded run fired security.outbound_remote_count as expected (${V4_PROBE_OUT#OK })"
    else
        echo "test/install-seeded.sh: FAIL — v4-seeded run findings wrong: $V4_PROBE_OUT" >&2
        echo "--- audit stdout ---" >&2
        cat "$BA_JSON_V4" >&2
        exit 1
    fi
    # Restore the threshold before the Issue #38 delta block reads the
    # sidecar this run just wrote (the live counts must not include this
    # block's sockets).
    privileged_exec /bin/bash -c 'echo 25 > /var/lib/box-audit/outbound-threshold.conf'
    # v4-quiet: wait for the holder to expire, then the combined finding
    # must be gone. The holder sleeps 30s; poll up to 30s for the ESTAB
    # v4 rows to disappear so the second audit runs on a settled netns.
    for _ in $(seq 1 30); do
        if ! privileged_exec ss -tnp state established 2>/dev/null | grep -q '198.51.100'; then
            break
        fi
        sleep 1
    done
    BA_JSON_NOV4="$(mktemp)"
    LIB_CLEANUP_PATHS+=("$BA_JSON_NOV4")
    if ! privileged_exec /usr/local/bin/box-audit --json > "$BA_JSON_NOV4" 2>/dev/null; then
        echo "test/install-seeded.sh: box-audit --json (v4-quiet run) exited non-zero" >&2
        exit 1
    fi
    NOV4_HITS="$(python3 -c '
import json
d = json.load(open("'"$BA_JSON_NOV4"'"))
hits = [f["check_id"] for f in d.get("findings", []) if f.get("check_id") == "security.outbound_remote_count"]
print("yes" if hits else "no")
')"
    if [[ "$NOV4_HITS" == "no" ]]; then
        echo "test/install-seeded.sh: v4-quiet run fired no combined finding (sockets torn down)"
    else
        echo "test/install-seeded.sh: FAIL — v4-quiet run still fired the combined finding" >&2
        echo "--- audit stdout ---" >&2
        cat "$BA_JSON_NOV4" >&2
        exit 1
    fi
else
    echo "test/install-seeded.sh: SKIP — v4 outbound block: seeding failed (${SEED_V4_OUT:-empty}); property suite covers the header-driven v4 extraction"
fi

# --- Issue #38 regression: delta-mode signal integrity ---------------------
# History: the ORIGINAL issue #38 defect — the persist sidecar sourcing
# today's counts from the JSON snapshot's findings[] array, which only
# carries a count when the corresponding absolute check tripped. On a
# healthy seeded box (low SUID, no outbound, no security updates) every
# one of the three is below threshold, so the sidecar recorded 0 — and
# tomorrow's delta check computed today's-live - 0 = today's-live, firing
# security.suid_delta / outbound_delta / security_delta every morning
# forever. That was fixed in v0.7.1 (94c250a): the additive counts block
# alongside findings[] is populated from the live measurement regardless
# of threshold, and history_persist_live_counts now takes the same three
# values straight from the script-scope vars instead of re-parsing the
# snapshot.
#
# Two assertions:
#
#   1. constant-count run: after the first audit, write today's live
#      count back as yesterday's, re-run --json, assert no delta finding
#      fires for any of the three.
#   2. mutated-count run: write yesterday = today - 10, re-run --json,
#      assert the corresponding delta finding fires.
#
# The first capture (above, BA_JSON) already gave us today's counts. Read
# them out, drive both scenarios, and check.
TODAY_COUNTS="$(python3 -c '
import json
d = json.load(open("'"$BA_JSON"'"))
c = d.get("counts", {})
print(c.get("suid_count"), c.get("outbound_remote_count"), c.get("security_pending"))
')"
TODAY_SUID=$(echo "$TODAY_COUNTS" | /usr/bin/awk "{print \$1}")
TODAY_OUT=$(echo "$TODAY_COUNTS" | /usr/bin/awk "{print \$2}")
TODAY_SEC=$(echo "$TODAY_COUNTS" | /usr/bin/awk "{print \$3}")
if [[ -z "$TODAY_SUID" || -z "$TODAY_OUT" || -z "$TODAY_SEC" ]]; then
    echo "test/install-seeded.sh: could not read today's counts from $BA_JSON (counts: $TODAY_COUNTS)" >&2
    exit 1
fi
echo "test/install-seeded.sh: today's live counts: suid=$TODAY_SUID out=$TODAY_OUT sec=$TODAY_SEC"

# 1. constant-count run: write today's live count back as yesterday's,
#    re-run --json, assert no *_delta finding fires. This is the load-
#    bearing regression: under the old code, the persist sidecar recorded
#    0 for every below-threshold count (because findings[] only carries
#    counts when the absolute check trips), so the next-day delta check
#    computed today's-live - 0 = today's-live, e.g. +19 suid_delta on a
#    healthy 19-SUID box. Today's audit reads the planted yesterday from
#    the sidecar and computes today's-live - today's-live = 0 → no delta.
if ! privileged_exec /bin/bash -c '
    mkdir -p /var/log/box-audit/history
    cat > /var/log/box-audit/history/.latest-counts.json <<JSON
{"outbound_count": '"$TODAY_OUT"', "suid_count": '"$TODAY_SUID"', "security_pending": '"$TODAY_SEC"', "timestamp": "constant-run", "host": "constant-run"}
JSON
' ; then
    echo "test/install-seeded.sh: failed to seed .latest-counts.json for constant-count run" >&2
    exit 1
fi

BA_JSON_CONST="$(mktemp)"
LIB_CLEANUP_PATHS+=("$BA_JSON_CONST")
if ! privileged_exec /usr/local/bin/box-audit --json > "$BA_JSON_CONST" 2>/dev/null; then
    echo "test/install-seeded.sh: box-audit --json (constant-count run) exited non-zero" >&2
    exit 1
fi
DELTA_HITS="$(python3 -c '
import json
d = json.load(open("'"$BA_JSON_CONST"'"))
hits = [f["check_id"] for f in d.get("findings", []) if f.get("check_id", "").endswith("_delta")]
print(",".join(hits) if hits else "none")
')"
if [[ "$DELTA_HITS" == "none" ]]; then
    echo "test/install-seeded.sh: constant-count run produced no *_delta finding (suid=$TODAY_SUID out=$TODAY_OUT sec=$TODAY_SEC)"
else
    echo "test/install-seeded.sh: FAIL — constant-count run produced delta findings: $DELTA_HITS" >&2
    echo "--- audit stdout ---" >&2
    cat "$BA_JSON_CONST" >&2
    exit 1
fi

# 2. mutated-count run: plant yesterday = today - 10 for each field in
#    turn, re-run --json, assert the corresponding *_delta finding fires.
#    We pick the direction that crosses the >2 / >1 / >2x delta thresholds
#    respectively. The outbound case is the trickiest: outbound_delta
#    requires today > 5 AND today > 2x yesterday — a bare seeded jrei
#    image has today = 0, so we can't trigger outbound_delta cleanly.
#    Skip it (the constant-count run already proves the load-bearing
#    direction: no false positive on a healthy box).
for FIELD in suid security; do
    if [[ "$FIELD" == "suid" ]]; then
        SID="suid_count"
        DELTA_ID="security.suid_delta"
        YESTERDAY_VAL=$((TODAY_SUID - 10))
        [[ $YESTERDAY_VAL -lt 0 ]] && YESTERDAY_VAL=0
    else
        SID="security_pending"
        DELTA_ID="updates.security_delta"
        YESTERDAY_VAL=$((TODAY_SEC - 10))
        [[ $YESTERDAY_VAL -lt 0 ]] && YESTERDAY_VAL=0
    fi
    # Plant a mutated .latest-counts.json: take today's counts as the
    # baseline, then overwrite the one we're testing with its yesterday
    # value. The audit reads this file at startup to compute deltas.
    # The opening heredoc delimiter is single-quoted ('PY') so the inner
    # bash doesn't re-expand $TODAY_OUT / $SID / $YESTERDAY_VAL — those
    # were already interpolated by the outer shell via the '"$VAR"'
    # single-quote-break pattern. The closing PY stays literal (no
    # quoting needed) — bash's heredoc terminator is a line consisting
    # of just the delimiter text.
    if ! privileged_exec /bin/bash -c '
        /usr/bin/python3 - <<'"'"'PY'"'"'
import json
p = "/var/log/box-audit/history/.latest-counts.json"
d = {"outbound_count": '"$TODAY_OUT"', "suid_count": '"$TODAY_SUID"', "security_pending": '"$TODAY_SEC"', "timestamp": "mutated-run", "host": "mutated-run"}
d["'"$SID"'"] = '"$YESTERDAY_VAL"'
with open(p, "w") as fh:
    json.dump(d, fh)
PY
    ' ; then
        echo "test/install-seeded.sh: failed to seed mutated .latest-counts.json for $FIELD" >&2
        exit 1
    fi
    BA_JSON_MUT="$(mktemp)"
    LIB_CLEANUP_PATHS+=("$BA_JSON_MUT")
    if ! privileged_exec /usr/local/bin/box-audit --json > "$BA_JSON_MUT" 2>/dev/null; then
        echo "test/install-seeded.sh: box-audit --json (mutated $FIELD) exited non-zero" >&2
        exit 1
    fi
    HIT="$(python3 -c '
import json
d = json.load(open("'"$BA_JSON_MUT"'"))
hits = [f["check_id"] for f in d.get("findings", []) if f.get("check_id") == "'"$DELTA_ID"'"]
print("yes" if hits else "no")
')"
    if [[ "$HIT" == "yes" ]]; then
        echo "test/install-seeded.sh: mutated-$FIELD run fired $DELTA_ID as expected (yesterday=$YESTERDAY_VAL)"
    else
        echo "test/install-seeded.sh: FAIL — mutated-$FIELD run did NOT fire $DELTA_ID (yesterday=$YESTERDAY_VAL, today=$TODAY_SUID/$TODAY_SEC)" >&2
        echo "--- audit stdout ---" >&2
        cat "$BA_JSON_MUT" >&2
        exit 1
    fi
done

echo "test/install-seeded.sh: seeded-container integration PASSED"