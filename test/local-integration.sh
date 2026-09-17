#!/usr/bin/env bash
# Driver for the tier-3 local pre-merge script (issue #18).
# Third vertical slice of the #14 three-tier test model.
#
#   bash test/local-integration.sh
#
# Mirrors test/install.sh structurally (privileged systemd container,
# install.sh --ci, then capture --json) without the seeded-state setup
# T03 needs. Tier 3's contract is narrower than tier 2's:
#
#   1. install.sh --ci exits 0 inside the container.
#   2. box-audit --json exits 0.
#   3. The emitted JSON parses with python3 -m json.tool and contains
#      the four top-level keys: status, timestamp, host, findings.
#   4. /usr/local/bin/box-audit --version reports a string containing
#      +replay (the version-suffix invariant shipped in 0.6.0).
#
# Per-check severities are tier 2's job (assert-json.py); tier 3 asserts
# the JSON *shape* and the version suffix, both of which are invariants
# the schema and the smoke suite already cover.
#
# The hard budget is 240 seconds end-to-end (raised from 60s for issue
# #31: the stale-group phase runs three more full installs inside the
# same container). If the host can't run a
# privileged container (the common CI-runner case), the script prints
# "skipped: requires privileged Docker" and exits 0 — the orchestrator
# test/all.sh counts that as a skip, not a failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="${1:-box-audit-local:positive}"
BUDGET_MS=$((240 * 1000))

# Skip detection: try `docker run --rm --privileged alpine true`. A
# non-zero exit (or no docker on PATH) means the host can't satisfy the
# tier-3 contract. Print the documented message and exit 0 so
# test/all.sh can record this as a skip rather than a failure. Per
# issue #25 Q4, skip-detection stays in the driver (the library
# shouldn't grow knowledge of which drivers want to skip).
if ! command -v docker >/dev/null 2>&1; then
    echo "local-integration: skipped: requires privileged Docker (docker not on PATH)"
    exit 0
fi
if ! docker run --rm --privileged alpine true >/dev/null 2>&1; then
    echo "local-integration: skipped: requires privileged Docker (docker run --privileged failed)"
    exit 0
fi

TOTAL_START_NS=$(date +%s%N)

# phase <name> — start/ok-or-fail wrapper. Tracks per-phase elapsed
# milliseconds and prints a single line on completion.
phase_start() { echo "phase $1 start"; }

phase_ok() {
    local name="$1" start_ns="$2"
    local elapsed_ms=$(( ($(date +%s%N) - start_ns) / 1000000 ))
    echo "phase $name ok in ${elapsed_ms}ms"
}

phase_fail() {
    local name="$1" start_ns="$2" reason="$3"
    local elapsed_ms=$(( ($(date +%s%N) - start_ns) / 1000000 ))
    echo "phase $name FAIL after ${elapsed_ms}ms — $reason" >&2
    exit 1
}

# shellcheck source=./install-lib.sh
# shellcheck disable=SC1091
source "$(dirname "$0")/install-lib.sh"

# Tier 3 allocates extra mktemps (capture files + the inline JSON probe
# script) that the library's trap should clean up. Drivers append to
# LIB_CLEANUP_PATHS BEFORE the first privileged_* call so the trap
# registration in privileged_prep sees them.
BA_JSON="$(mktemp)"
BA_ERR="$(mktemp)"
SCHEMA_PROBE="$(mktemp)"
PROBE_SCRIPT="$(mktemp)"
LIB_CLEANUP_PATHS+=("$BA_JSON" "$BA_ERR" "$SCHEMA_PROBE" "$PROBE_SCRIPT")

# Inline JSON-contract probe. Reads the JSON path from argv[1] so the
# script is decoupled from stdin/stdout of the outer pipeline. Exit
# 0 on success; 1 on missing keys; 2 on bad shape; non-zero on parse
# failure (caught by the caller).
cat > "$PROBE_SCRIPT" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    doc = json.load(f)
missing = [k for k in ("status", "timestamp", "host", "findings") if k not in doc]
if missing:
    sys.stderr.write("missing top-level keys: " + ",".join(missing) + "\n")
    sys.exit(1)
findings = doc.get("findings")
if not isinstance(findings, list):
    sys.stderr.write("'findings' is not a list\n")
    sys.exit(2)
PY

# --- phase: build ----------------------------------------------------------
BUILD_START=$(date +%s%N)
phase_start build
if ! privileged_build "$REPO/test/install-docker/Dockerfile" "$IMAGE_TAG" 2>"$BA_ERR"; then
    phase_fail "build" "$BUILD_START" "docker build failed (see $BA_ERR)"
fi
phase_ok "build" "$BUILD_START"

# --- phase: boot -----------------------------------------------------------
BOOT_START=$(date +%s%N)
phase_start boot
privileged_prep "$IMAGE_TAG"
phase_ok "boot" "$BOOT_START"

# --- phase: install --------------------------------------------------------
INSTALL_START=$(date +%s%N)
phase_start install
if ! privileged_exec /bin/bash -c 'cd /work && bash install.sh --ci' >/dev/null 2>"$BA_ERR"; then
    phase_fail "install" "$INSTALL_START" "install.sh --ci exited non-zero (see $BA_ERR)"
fi
phase_ok "install" "$INSTALL_START"

# --- phase: audit ----------------------------------------------------------
AUDIT_START=$(date +%s%N)
phase_start audit
# Hit the *installed* binary (/usr/local/bin/box-audit) so the +replay
# suffix and the JSON contract are exercised against the same surface
# the daily timer runs, not the repo copy.
if ! privileged_exec /usr/local/bin/box-audit --json > "$BA_JSON" 2>"$BA_ERR"; then
    phase_fail "audit" "$AUDIT_START" "/usr/local/bin/box-audit --json exited non-zero (see $BA_ERR)"
fi
# Tier-3 contract 1: emitted JSON parses.
if ! python3 -m json.tool < "$BA_JSON" > "$SCHEMA_PROBE" 2>>"$BA_ERR"; then
    phase_fail "audit" "$AUDIT_START" "box-audit --json output is not valid JSON"
fi
# Tier-3 contract 2: four top-level keys present. Probe the *original*
# raw emission, not the pretty-printed copy, so the assertion fails
# the same way for both the production and a future variant.
if ! python3 "$PROBE_SCRIPT" "$BA_JSON" 2>>"$BA_ERR"; then
    phase_fail "audit" "$AUDIT_START" "JSON contract assertion failed (status/timestamp/host/findings)"
fi
# Tier-3 contract 3: --version carries +replay on the installed binary.
VERSION_OUT="$(privileged_exec /usr/local/bin/box-audit --version 2>/dev/null || true)"
if [[ "$VERSION_OUT" != *"+replay"* ]]; then
    phase_fail "audit" "$AUDIT_START" "--version missing +replay suffix (got: $VERSION_OUT)"
fi
phase_ok "audit" "$AUDIT_START"

# --- phase: stale-group warning (issue #31) ---------------------------------
# The install adds the invoking user to the boxaudit group; every process
# that user started beforehand keeps its old group list until restart.
# Exercise warn_stale_group_processes end-to-end:
#
#   1. warn-fires: a user + a long-lived process lacking the gid, install
#      via sudo so SUDO_USER is set, STALE_PROC_MIN_AGE=0 so the fresh
#      seed process counts as "old". Assert the warning line, the pid,
#      and the trailing restart hint appear in the output.
#   2. warn-doesn't-fire: same setup but STALE_PROC_MIN_AGE=999999 — the
#      seed process is younger than the threshold, so no warning header.
#      (`deluser seeduser boxaudit` first — otherwise the install would
#      take the `unchanged:` path and the no-header assertion would be
#      vacuous.)
#   3. unchanged: re-run — seeduser back in the group → `unchanged:`
#      path; the scan must not run at all, even at threshold 0.
#
# Runs in the same container after the main install phases: the boxaudit
# group already exists and the root-installed state is in place, so the
# second install's group step takes the `added:` path for the NEW user
# (never added before) — exactly the path the scan hooks into.
STALE_LOG="$(mktemp)"
STALE_ERR="$(mktemp)"
LIB_CLEANUP_PATHS+=("$STALE_LOG" "$STALE_ERR")

privileged_exec /bin/bash -c '
    useradd -m seeduser
    # Long-lived process owned by seeduser, started before any group
    # membership exists. setsid detaches it from the exec session so
    # it survives; sleep infinity is the stand-in daemon.
    setsid runuser -u seeduser -- sleep infinity </dev/null >/dev/null 2>&1 &
    sleep 1
' >/dev/null

SEED_PIDS="$(privileged_exec pgrep -u seeduser)"
[[ -n "$SEED_PIDS" ]] || { echo "local-integration: FAIL — no seeded process for seeduser" >&2; exit 1; }

# 1. warn-fires: threshold 0 → every process of seeduser is "old".
if ! docker exec -e STALE_PROC_MIN_AGE=0 -e SUDO_USER=seeduser "$CID" \
        /bin/bash -c 'cd /work && bash install.sh --ci' >"$STALE_LOG" 2>"$STALE_ERR"; then
    echo "local-integration: FAIL — second install (warn-fires) exited non-zero" >&2
    cat "$STALE_ERR" >&2
    exit 1
fi
WARN_HEADER='long-running process(es) owned by seeduser'
if ! grep -Fq "$WARN_HEADER" "$STALE_LOG"; then
    echo "local-integration: FAIL — stale-group warning header missing (warn-fires case)" >&2
    tail -20 "$STALE_LOG" >&2
    exit 1
fi
for pid in $SEED_PIDS; do
    if ! grep -q "pid $pid " "$STALE_LOG"; then
        echo "local-integration: FAIL — seeded pid $pid not listed in stale-group warning" >&2
        exit 1
    fi
done
if ! grep -q 'restart these, or log out and back in' "$STALE_LOG"; then
    echo "local-integration: FAIL — trailing restart hint missing" >&2
    exit 1
fi

# 2. warn-doesn't-fire: threshold ~11.5 days → the seconds-old seed
#    process is younger; no warning header may appear.
if ! docker exec -e STALE_PROC_MIN_AGE=999999 -e SUDO_USER=seeduser "$CID" \
        /bin/bash -c 'cd /work && deluser seeduser boxaudit >/dev/null 2>&1; bash install.sh --ci' >"$STALE_LOG" 2>"$STALE_ERR"; then
    echo "local-integration: FAIL — third install (warn-doesn't-fire) exited non-zero" >&2
    cat "$STALE_ERR" >&2
    exit 1
fi
if grep -Fq "$WARN_HEADER" "$STALE_LOG"; then
    echo "local-integration: FAIL — stale-group warning printed below-threshold process (warn-doesn't-fire case)" >&2
    exit 1
fi

# 3. unchanged: re-run — seeduser is in the group now, so the group step
#    takes the `unchanged:` path and the scan must not run at all, even
#    with a zero threshold that would otherwise flag everything.
if ! docker exec -e STALE_PROC_MIN_AGE=0 -e SUDO_USER=seeduser "$CID" \
        /bin/bash -c 'cd /work && bash install.sh --ci' >"$STALE_LOG" 2>"$STALE_ERR"; then
    echo "local-integration: FAIL — fourth install (unchanged re-run) exited non-zero" >&2
    cat "$STALE_ERR" >&2
    exit 1
fi
if ! grep -q 'unchanged: seeduser is in boxaudit' "$STALE_LOG"; then
    echo "local-integration: FAIL — unchanged: path not taken on re-run" >&2
    exit 1
fi
if grep -Fq "$WARN_HEADER" "$STALE_LOG"; then
    echo "local-integration: FAIL — scan ran on the unchanged: path (must skip entirely)" >&2
    exit 1
fi
echo "phase stale-group-warning ok"

# --- budget assertion ------------------------------------------------------
TOTAL_MS=$(( ($(date +%s%N) - TOTAL_START_NS) / 1000000 ))
if [[ $TOTAL_MS -gt $BUDGET_MS ]]; then
    echo "local-integration: FAIL — over budget (total ${TOTAL_MS}ms)" >&2
    exit 1
fi
echo "local-integration: within budget (total ${TOTAL_MS}ms)"
echo "local-integration: PASS"
