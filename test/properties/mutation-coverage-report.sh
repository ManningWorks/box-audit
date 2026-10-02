#!/usr/bin/env bash
# mutation-coverage-report — F6 report surface (0.9.0). Asserts the driver's
# report renderer against fixture result sets: the per-entry verdict table
# and the mutation score (flipped/total as a percentage) must render
# correctly. Uses the driver's --report-fixture seam, so this asserts the
# REAL renderer (not a copy) and runs with no container and no docker.
#
# Fixtures cover the three shapes the score must survive:
#   * mixed        (1 FLIPPED + 1 SURVIVED)  -> score 50.0%
#   * survived-only (the negative variant)   -> score 0.0%, no FLIPPED line
#   * 0-entry      (empty result set)        -> total=0, score n/a, no crash
# A survived-only result set is a coverage signal, NOT a failure — the
# renderer must report it as 0.0%, never as an error.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

DRIVER="$REPO_ROOT/test/mutation-coverage.sh"
[[ -f "$DRIVER" ]] || { fail "driver missing: $DRIVER"; props_done "mutation-coverage-report"; exit 1; }

FIXDIR="$(mktemp -d)"
trap 'rm -rf "$FIXDIR"' EXIT

# render <fixture> -> run the driver's renderer on <fixture>, capture stdout
# and rc into OUT / RC for follow-up assertions.
render() {
    OUT="$(bash "$DRIVER" --report-fixture "$1" 2>/dev/null)"
    RC=$?
}

# one-line helper: join captured output for failure diagnostics.
diag() { printf '%s' "$OUT" | tr '\n' '|'; }

# --- mixed fixture: 1 FLIPPED + 1 SURVIVED -> score 50.0% -------------------
MIXED="$FIXDIR/mixed.tsv"
{
    printf 'security.fail2ban_banned\tscripts/box-audit.sh\tFLIPPED\n'
    printf 'system.cron_d_dropins\ttest/install-docker/seeded/seed.sh\tSURVIVED\n'
} > "$MIXED"
render "$MIXED"
if [[ $RC -eq 0 ]]; then
    ok "mixed fixture renders (exit $RC)"
else
    fail "mixed fixture must exit 0, got $RC"
fi
if [[ "$OUT" == *"security.fail2ban_banned"*"FLIPPED"* ]]; then
    ok "mixed fixture: FLIPPED entry line rendered"
else
    fail "mixed fixture: missing FLIPPED entry line — $(diag)"
fi
if [[ "$OUT" == *"system.cron_d_dropins"*"SURVIVED"* ]]; then
    ok "mixed fixture: SURVIVED entry line rendered"
else
    fail "mixed fixture: missing SURVIVED entry line — $(diag)"
fi
if [[ "$OUT" == *"total=2"* && "$OUT" == *"flipped=1"* && "$OUT" == *"survived=1"* ]]; then
    ok "mixed fixture: counts correct (total=2 flipped=1 survived=1)"
else
    fail "mixed fixture: counts wrong — $(diag)"
fi
if [[ "$OUT" == *"score=50.0%"* ]]; then
    ok "mixed fixture: mutation score 50.0%"
else
    fail "mixed fixture: score not 50.0% — $(diag)"
fi

# --- survived-only (the negative variant): 2 SURVIVED -> score 0.0% ---------
SURV="$FIXDIR/survived.tsv"
{
    printf 'system.failed_units\tscripts/box-audit.sh\tSURVIVED\n'
    printf 'updates.security_delta\tscripts/box-audit.sh\tSURVIVED\n'
} > "$SURV"
render "$SURV"
if [[ $RC -eq 0 ]]; then
    ok "survived-only fixture renders (exit $RC)"
else
    fail "survived-only fixture must exit 0, got $RC"
fi
if [[ "$OUT" == *"flipped=0"* && "$OUT" == *"survived=2"* ]]; then
    ok "survived-only fixture: flipped=0 survived=2"
else
    fail "survived-only fixture: counts wrong — $(diag)"
fi
if [[ "$OUT" == *"score=0.0%"* ]]; then
    ok "survived-only fixture: mutation score 0.0% (a coverage signal, not a failure)"
else
    fail "survived-only fixture: score not 0.0% — $(diag)"
fi
if [[ "$OUT" == *"FLIPPED"* ]]; then
    fail "survived-only fixture: a FLIPPED line must not render — $(diag)"
else
    ok "survived-only fixture: no FLIPPED line rendered"
fi

# --- 0-entry fixture: empty result set -> total=0, score n/a, no crash ------
EMPTY="$FIXDIR/empty.tsv"
: > "$EMPTY"
render "$EMPTY"
if [[ $RC -eq 0 ]]; then
    ok "0-entry fixture renders without a divide-by-zero (exit $RC)"
else
    fail "0-entry fixture must exit 0, got $RC"
fi
if [[ "$OUT" == *"total=0"* && "$OUT" == *"flipped=0"* && "$OUT" == *"survived=0"* ]]; then
    ok "0-entry fixture: counts zero"
else
    fail "0-entry fixture: counts wrong — $(diag)"
fi
if [[ "$OUT" == *"score=n/a"* ]]; then
    ok "0-entry fixture: score n/a"
else
    fail "0-entry fixture: score not n/a — $(diag)"
fi

props_done "mutation-coverage-report"
