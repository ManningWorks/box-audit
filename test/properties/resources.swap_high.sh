#!/usr/bin/env bash
# resources.swap_high — warns when swap usage exceeds 70%
# (SWAP_THRESHOLD). Input: `free` (fields derived from /proc/meminfo's
# SwapTotal/SwapFree).
#
# SEAM: no env-var override for the input path, and a full --json run
# costs ~7s on a sudo-granted box — see resources.disk_high.sh for the
# full seam note. T03's seeded container owns threshold-driving.
# Asserted instead:
#   1. schema contract.
#   2. delta semantics — a finding present yesterday and gone today
#      surfaces as "- GONE" (a resolved condition leaves the diff).
#   3. fixture integrity — swap.txt / swap-high.txt are real
#      /proc/meminfo shapes on either side of the 70% threshold.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "resources.swap_high"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"resources\.swap_high"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: baseline with the finding, today without it.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "resources.swap_high", "section": "resources", "message": "82% used"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/none.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "resolved swap_high surfaces as - GONE" '^- GONE' "$CORPUS/diff.out"
assert_grep "message carries the finding text" '82% used' "$CORPUS/diff.out"
assert_grep "footer counts the one removal" '\(\+0 -1\)' "$CORPUS/diff.out"

# 3. fixture integrity: same key shape, usage below/above 70%.
swap_pct() {
    # Percentage used from a /proc/meminfo-shaped file, as `free` derives it.
    awk '/^SwapTotal:/ { t = $2 } /^SwapFree:/ { f = $2 }
         END { if (t > 0) printf "%.0f", (t - f) / t * 100; else print "0" }' "$1"
}
assert_eq "swap.txt usage below the 70% threshold" "0" "$(swap_pct "$FIX/swap.txt")"
# shellcheck disable=SC2016  # awk programs are deliberately single-quoted
assert_exit "swap-high.txt usage above the 70% threshold" '^0$' \
    awk '/^SwapTotal:/ { t = $2 } /^SwapFree:/ { f = $2 }
         END { exit !((t - f) / t * 100 > 70) }' "$FIX/swap-high.txt"

props_done "resources.swap_high"
