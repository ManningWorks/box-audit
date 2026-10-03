#!/usr/bin/env bash
# Tier-2 driver: install-time baseline learning (issue #71).
#
#   bash test/install-learn.sh [image-tag]
#
# Proves the ONE deliberate write the installer makes — snapshotting the
# box's real state on a fresh interactive install — and its negative
# variants (per AGENTS.md: every new gate gets the negative that proves
# its teeth). The learn step is driven by the installer's own TTY gate
# (fresh + interactive + non-CI, or forced with --learn), so a pty is
# needed: `docker exec` carries no TTY, and the tier-1 --ci surface is
# deliberately non-interactive. We boot a privileged systemd container
# (the same surface install-seeded.sh uses) and install through `script`,
# which allocates a pty so install.sh sees `-t 0` and learns.
#
# State control (repo rule: a seeded test never reads uncontrolled
# base-image state). The learn image (test/install-docker/learn/Dockerfile)
# is the MINIMAL base + iproute2 + cron — no fail2ban, no docker.io, no
# containerd — so the box's listening set, timer set, and /etc/cron.d are
# fully controlled by the driver's seeds below. We CREATE the entries the
# assertions read (a listener on 17777, a probe timer, a cron.d drop-in);
# we never assert on whatever the base image happens to run.
#
# Asserts:
#   1. fresh pty install LEARNS: the summary reports the learned ports /
#      timers / cron.d, and the on-disk config holds the SEEDED values
#      (17777 in the allowlist, probe-timer in the baseline, the drop-in
#      in cron-d) — i.e. the config matches the box's actual state.
#   2. a deliberately-open, unseeded port (18888, started AFTER install)
#      yields a security.new_port finding whose message carries the
#      --accept-port 18888 remedy (positive teeth for self-documenting
#      findings, on the real install surface).
#   3. `--no-init` skips learning: a fresh reinstall with the flag keeps
#      the seeded generic ports (22 53 80 443 631), not the learned 17777.
#   4. an upgrade (non-fresh) install leaves a hand-edited allowlist
#      byte-identical and does NOT run the learn step.
#   5. `--learn` (no pty) forces the learn step on a fresh install — the
#      deterministic test seam the flag exists for (docker exec has no TTY):
#      a fresh non-interactive install that would NOT learn (no -t 0) learns
#      the seeded box state when --learn is passed.
#   6. `--ci --learn` does NOT learn — the force flag must not override the
#      CI no-learn contract (the gate checks CI_MODE before LEARN_FORCE).
#   7. shellcheck-clean is enforced by tier 1 across this file.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="${1:-box-audit-install:learn}"

# shellcheck source=./install-lib.sh
# shellcheck disable=SC1091
source "$(dirname "$0")/install-lib.sh"

# Stage WORK once and share it across both builds (base + learn image).
# The learn Dockerfile's `FROM box-audit-base:test` requires that base
# image to exist; install the same way install-seeded.sh does: build the
# base first into a shared, registered WORK so both builds read the same
# repo snapshot.
LEARN_WORK="$(mktemp -d)"
LIB_CLEANUP_PATHS+=("$LEARN_WORK")
privileged_build "$REPO/test/install-docker/Dockerfile" "box-audit-base:test" "$LEARN_WORK"
privileged_build "$REPO/test/install-docker/learn/Dockerfile" "$IMAGE_TAG" "$LEARN_WORK"
privileged_prep "$IMAGE_TAG"

# --- controlled seeds -------------------------------------------------------
# All three are under driver control. The listener is backgrounded with
# setsid so it survives the exec subshell (same pattern install-seeded.sh
# uses for 9999).
# shellcheck disable=SC2016  # inner bash -c is deliberately single-quoted
privileged_exec /bin/bash -c '
    cat > /etc/systemd/system/probe-timer.timer <<UNIT
[Unit]
Description=box-audit learn-test timer
[Timer]
OnCalendar=daily
[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    systemctl enable probe-timer.timer >/dev/null
    printf "probe-learn-cron-line\n" > /etc/cron.d/probe-learn-test
    setsid python3 -m http.server 17777 --bind 127.0.0.1 --directory /tmp \
        >/tmp/learn-http.log 2>&1 < /dev/null &
' >/dev/null
HTTP_READY=""
for _ in $(seq 1 30); do
    if privileged_exec ss -tlnH 2>/dev/null | grep -q ':17777 '; then
        HTTP_READY=yes
        break
    fi
    sleep 1
done
[[ -n "$HTTP_READY" ]] || { echo "test/install-learn.sh: listener 17777 did not bind" >&2; exit 1; }

# pty_install <install-args...>: run install.sh under `script` so stdin is a
# TTY and install.sh's interactive learn gate (fresh + `-t 0`) fires. `script`
# exits with the child's code, so set -e still catches a failed install.
pty_install() {
    docker exec "$CID" /bin/bash -c "script -qec 'cd /work && bash install.sh $*' /dev/null"
}
# plain_install <install-args...>: run install.sh WITHOUT a pty (docker exec
# carries no TTY, stdin from /dev/null), so install.sh's interactive `-t 0`
# gate is FALSE. This is the seam the `--learn` force flag exists to drive:
# a fresh install that would NOT learn without `--learn`. Same set -e
# propagation as pty_install (docker exec returns the child's code).
plain_install() {
    docker exec "$CID" /bin/bash -c "cd /work && bash install.sh $* </dev/null"
}

# --- 1. fresh interactive install LEARNS ------------------------------------
FRESH_OUT="$(mktemp)"
LIB_CLEANUP_PATHS+=("$FRESH_OUT")
pty_install "" > "$FRESH_OUT" 2>&1
if ! grep -q "learned baseline (from live box state)" "$FRESH_OUT"; then
    echo "test/install-learn.sh: FAIL — fresh pty install did not learn" >&2
    tail -30 "$FRESH_OUT" >&2
    exit 1
fi
echo "test/install-learn.sh: fresh pty install learned the baseline"
# The on-disk config must match the SEEDED (created) state, not the base
# image's. Each of the three seeded values must be present.
if ! privileged_exec grep -qxF 17777 /var/lib/box-audit/ports-allowlist.txt; then
    echo "test/install-learn.sh: FAIL — learned ports-allowlist lacks seeded port 17777" >&2
    privileged_exec cat /var/lib/box-audit/ports-allowlist.txt >&2 || true
    exit 1
fi
if ! privileged_exec grep -qxF probe-timer.timer /var/lib/box-audit/timers-baseline.txt; then
    echo "test/install-learn.sh: FAIL — learned timers-baseline lacks seeded probe-timer.timer" >&2
    privileged_exec cat /var/lib/box-audit/timers-baseline.txt >&2 || true
    exit 1
fi
if ! privileged_exec grep -qxF probe-learn-test /var/lib/box-audit/cron-d-allowlist.txt; then
    echo "test/install-learn.sh: FAIL — learned cron-d-allowlist lacks seeded probe-learn-test" >&2
    privileged_exec cat /var/lib/box-audit/cron-d-allowlist.txt >&2 || true
    exit 1
fi
echo "test/install-learn.sh: learned config matches the seeded box state (17777 / probe-timer / probe-learn-test)"

# --- 2. unseeded open port -> new_port finding WITH the remedy --------------
# 17777 was learned (in the baseline), so a finding can't come from it. Open a
# NEW port the baseline never saw; it must fire security.new_port and name its
# --accept-port remedy (the self-documenting contract on the installed binary).
# shellcheck disable=SC2016
privileged_exec /bin/bash -c '
    setsid python3 -m http.server 18888 --bind 127.0.0.1 --directory /tmp \
        >/tmp/learn-http2.log 2>&1 < /dev/null &
' >/dev/null
for _ in $(seq 1 30); do
    if privileged_exec ss -tlnH 2>/dev/null | grep -q ':18888 '; then break; fi
    sleep 1
done
BA_JSON="$(mktemp)"; LIB_CLEANUP_PATHS+=("$BA_JSON")
if ! privileged_exec /usr/local/bin/box-audit --json > "$BA_JSON" 2>/dev/null; then
    echo "test/install-learn.sh: FAIL — box-audit --json (remedy run) exited non-zero" >&2
    exit 1
fi
if ! REMEDY_OUT="$(BA_JSON="$BA_JSON" python3 - <<'PY' || true
import json, os
d = json.load(open(os.environ["BA_JSON"]))
hits = [f for f in d.get("findings", []) if f.get("check_id") == "security.new_port"]
# 18888 must be the port flagged (17777 was learned away).
p18888 = [f for f in hits if "18888 is open (not in baseline)" in f.get("message", "")]
if not p18888:
    print("FAIL_NO_FINDING: 18888 not flagged as new_port: " + repr([f.get("message") for f in hits]))
    raise SystemExit(1)
msg = p18888[0]["message"]
if "--accept-port 18888" not in msg:
    print("FAIL_NO_REMEDY: message lacks --accept-port 18888: " + repr(msg))
    raise SystemExit(1)
if "--init to re-learn" not in msg:
    print("FAIL_NO_RELEARN: message lacks --init re-learn: " + repr(msg))
    raise SystemExit(1)
print("OK " + msg)
PY
)"; then
    echo "test/install-learn.sh: FAIL — new_port remedy assertion: $REMEDY_OUT" >&2
    cat "$BA_JSON" >&2
    exit 1
fi
echo "test/install-learn.sh: unseeded port 18888 fired new_port with the --accept-port remedy (${REMEDY_OUT#OK })"

# --- 3. --no-init skips learning (negative: seeded defaults kept) -----------
# Wipe the learned state to force a genuinely fresh install, then install with
# --no-init. The ports file must be the seeded generic set, NOT the learned
# 17777 — proof the flag suppresses the learn step.
privileged_exec /bin/bash -c 'rm -rf /var/lib/box-audit /usr/local/bin/box-audit /usr/local/share/box-audit'
NOINIT_OUT="$(mktemp)"
LIB_CLEANUP_PATHS+=("$NOINIT_OUT")
pty_install --no-init > "$NOINIT_OUT" 2>&1
if grep -q "learned baseline (from live box state)" "$NOINIT_OUT"; then
    echo "test/install-learn.sh: FAIL — --no-init install still ran the learn step" >&2
    tail -30 "$NOINIT_OUT" >&2
    exit 1
fi
if ! privileged_exec /bin/bash -c 'grep -qx 22 /var/lib/box-audit/ports-allowlist.txt && grep -qx 631 /var/lib/box-audit/ports-allowlist.txt'; then
    echo "test/install-learn.sh: FAIL — --no-init did not keep the seeded generic ports" >&2
    privileged_exec cat /var/lib/box-audit/ports-allowlist.txt >&2 || true
    exit 1
fi
if privileged_exec grep -qxF 17777 /var/lib/box-audit/ports-allowlist.txt; then
    echo "test/install-learn.sh: FAIL — --no-init leaked the learned port 17777 into the allowlist" >&2
    exit 1
fi
echo "test/install-learn.sh: --no-init skipped learning (seeded generic ports kept, no learn step)"

# --- 4. upgrade leaves allowlists byte-identical and does not learn ----------
# Hand-edit the allowlist (simulating a customized box), snapshot its hash,
# reinstall (non-fresh upgrade path), and assert the file is byte-identical
# and the learn step did not run.
privileged_exec /bin/bash -c 'echo 4242 >> /var/lib/box-audit/ports-allowlist.txt'
BEFORE="$(privileged_exec /usr/bin/sha256sum /var/lib/box-audit/ports-allowlist.txt | awk "{print \$1}")"
UPG_OUT="$(mktemp)"
LIB_CLEANUP_PATHS+=("$UPG_OUT")
pty_install "" > "$UPG_OUT" 2>&1
AFTER="$(privileged_exec /usr/bin/sha256sum /var/lib/box-audit/ports-allowlist.txt | awk "{print \$1}")"
if [[ "$BEFORE" != "$AFTER" ]]; then
    echo "test/install-learn.sh: FAIL — upgrade changed ports-allowlist.txt ($BEFORE -> $AFTER)" >&2
    exit 1
fi
if grep -q "learned baseline (from live box state)" "$UPG_OUT"; then
    echo "test/install-learn.sh: FAIL — upgrade (non-fresh) ran the learn step" >&2
    tail -30 "$UPG_OUT" >&2
    exit 1
fi
echo "test/install-learn.sh: upgrade left the hand-edited allowlist byte-identical and did not learn"

# --- 5. --learn (no pty) FORCES the learn step on a fresh install -----------
# The --learn force flag exists so the suites can drive the learn path
# deterministically (docker exec has no TTY, so the interactive -t 0 gate
# alone can't be hit in a plain docker-exec install). This is the positive
# teeth for the forced branch: wipe to a genuinely fresh install, then install
# via plain_install (NO pty, so -t 0 is FALSE and the box would NOT learn
# without the flag). With --learn the learn step MUST run and the on-disk
# config must hold the seeded box state (17777 / probe-timer / probe-learn-test
# are still live from the seeds above), proving the forced branch is exercised
# and not dead.
privileged_exec /bin/bash -c 'rm -rf /var/lib/box-audit /usr/local/bin/box-audit /usr/local/share/box-audit'
LEARNOUT="$(mktemp)"
LIB_CLEANUP_PATHS+=("$LEARNOUT")
plain_install --learn > "$LEARNOUT" 2>&1
if ! grep -q "learned baseline (from live box state)" "$LEARNOUT"; then
    echo "test/install-learn.sh: FAIL — --learn (no pty) fresh install did not learn" >&2
    tail -30 "$LEARNOUT" >&2
    exit 1
fi
echo "test/install-learn.sh: --learn forced the learn step on a fresh non-interactive install"
# The forced learn must have captured the SEEDED box state (same three values
# section 1 asserts), not the seeded generic defaults — proof the forced branch
# ran --init against live state.
if ! privileged_exec grep -qxF 17777 /var/lib/box-audit/ports-allowlist.txt; then
    echo "test/install-learn.sh: FAIL — --learn learned ports-allowlist lacks seeded port 17777" >&2
    privileged_exec cat /var/lib/box-audit/ports-allowlist.txt >&2 || true
    exit 1
fi
if ! privileged_exec grep -qxF probe-timer.timer /var/lib/box-audit/timers-baseline.txt; then
    echo "test/install-learn.sh: FAIL — --learn learned timers-baseline lacks seeded probe-timer.timer" >&2
    privileged_exec cat /var/lib/box-audit/timers-baseline.txt >&2 || true
    exit 1
fi
if ! privileged_exec grep -qxF probe-learn-test /var/lib/box-audit/cron-d-allowlist.txt; then
    echo "test/install-learn.sh: FAIL — --learn learned cron-d-allowlist lacks seeded probe-learn-test" >&2
    privileged_exec cat /var/lib/box-audit/cron-d-allowlist.txt >&2 || true
    exit 1
fi
echo "test/install-learn.sh: --learn learned config matches the seeded box state (17777 / probe-timer / probe-learn-test)"

# --- 6. --ci --learn does NOT learn (CI precedence over the force flag) -----
# The learn gate is IS_FRESH_INSTALL && !CI_MODE && !NO_INIT && (-t 0 || LEARN_FORCE).
# CI_MODE is checked before LEARN_FORCE, so --learn must NOT override the CI
# no-learn contract: a fresh --ci install with --learn keeps the seeded generic
# defaults (the CI branch of the gate, negative variant). Wipe to fresh first.
privileged_exec /bin/bash -c 'rm -rf /var/lib/box-audit /usr/local/bin/box-audit /usr/local/share/box-audit'
CI_LEARNOUT="$(mktemp)"; LIB_CLEANUP_PATHS+=("$CI_LEARNOUT")
plain_install --ci --learn > "$CI_LEARNOUT" 2>&1
if grep -q "learned baseline (from live box state)" "$CI_LEARNOUT"; then
    echo "test/install-learn.sh: FAIL — --ci --learn still ran the learn step (CI must take precedence over the force flag)" >&2
    tail -30 "$CI_LEARNOUT" >&2
    exit 1
fi
if privileged_exec grep -qxF 17777 /var/lib/box-audit/ports-allowlist.txt; then
    echo "test/install-learn.sh: FAIL — --ci --learn leaked the learned port 17777 into the allowlist" >&2
    privileged_exec cat /var/lib/box-audit/ports-allowlist.txt >&2 || true
    exit 1
fi
if ! privileged_exec /bin/bash -c 'grep -qx 22 /var/lib/box-audit/ports-allowlist.txt && grep -qx 631 /var/lib/box-audit/ports-allowlist.txt'; then
    echo "test/install-learn.sh: FAIL — --ci --learn did not keep the seeded generic ports" >&2
    privileged_exec cat /var/lib/box-audit/ports-allowlist.txt >&2 || true
    exit 1
fi
echo "test/install-learn.sh: --ci --learn kept the seeded generic defaults (CI takes precedence over --learn)"

echo "test/install-learn.sh: install-time learning PASSED"
