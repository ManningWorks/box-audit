#!/usr/bin/env bash
# Local entry point for all four tiers of the #14 three-tier test
# model (issue #18). Runs smoke → install → install-seeded →
# local-integration in sequence; each tier owns its own skip logic
# (tier 3 prints "skipped: requires privileged Docker" and exits 0
# when the host can't run a privileged container).
#
# Final line:
#   all: 4 passed                 (tier 3 ran and passed)
#   all: 3 passed, 1 skipped      (tier 3 skipped)
# Aggregate exit 0 only if every tier that ran passed.
#
# The four tiers are not equivalent in scope — tier 1 catches
# dispatch-order regressions on a bare runner; tier 2 catches
# per-check regressions against seeded state; tier 3 is the local
# pre-merge net for the author's box. Running them in this order is
# fail-fast on the cheapest first.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PASSED=0
SKIPPED=0
FAILED=0

# Run one tier, stream its output, capture its skip-vs-pass status.
# Tier 3 prints "skipped: requires privileged Docker" on the line
# that is unique to the skip path; an exit-0 run that includes that
# line counts as a skip in the summary. The grep matches the line
# anywhere in the captured log so test ordering inside the driver
# (phase markers, intermediate output) doesn't matter.
run_tier() {
    local name="$1" script="$2"
    shift 2
    local log start_ms elapsed_ms rc
    log="$(mktemp)"
    start_ms=$(date +%s%N)
    echo
    echo "============================================================"
    echo "tier: $name ($script)"
    echo "============================================================"
    set +e
    bash "$REPO/$script" "$@" >"$log" 2>&1
    rc=$?
    set -e
    cat "$log"
    elapsed_ms=$(( ($(date +%s%N) - start_ms) / 1000000 ))
    if [[ $rc -eq 0 ]]; then
        if grep -q "skipped: requires privileged Docker" "$log" 2>/dev/null; then
            SKIPPED=$((SKIPPED + 1))
            echo "tier $name: SKIPPED (${elapsed_ms}ms)"
        else
            PASSED=$((PASSED + 1))
            echo "tier $name: PASSED (${elapsed_ms}ms)"
        fi
    else
        FAILED=$((FAILED + 1))
        echo "tier $name: FAILED (${elapsed_ms}ms)" >&2
    fi
    rm -f "$log"
}

# Smoke is the cheapest gate — catches dispatch-order regressions
# before we spend 30+ seconds on a privileged container.
run_tier "smoke"             "test/smoke.sh"
# Tier 1 install driver — exercises install.sh --ci end-to-end on a
# privileged systemd container, positive path only (the negative
# variant lives in install.yml and is a CI gate, not a local check).
run_tier "install"            "test/install.sh" "box-audit-install:all"
# Tier 2 — seeded container, eight-check assertion.
run_tier "install-seeded"     "test/install-seeded.sh"
# Tier 3 — local pre-merge (skips itself on non-privileged hosts).
run_tier "local-integration"  "test/local-integration.sh"

# --- summary ---------------------------------------------------------------
echo
echo "============================================================"
if [[ $FAILED -eq 0 ]]; then
    if [[ $SKIPPED -eq 0 ]]; then
        echo "all: $PASSED passed"
    else
        echo "all: $PASSED passed, $SKIPPED skipped"
    fi
    exit 0
fi
echo "all: $PASSED passed, $SKIPPED skipped, $FAILED failed" >&2
exit 1
