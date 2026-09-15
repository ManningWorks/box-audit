#!/usr/bin/env bash
# resources.load_high — warns when 1-minute load average exceeds 3.0
# (LOAD_THRESHOLD). Input: first field of /proc/loadavg.
#
# SEAM: no env-var override for /proc/loadavg, and a full --json run
# costs ~7s on a sudo-granted box — see resources.disk_high.sh. T03's
# seeded container owns threshold-driving. Asserted instead:
#   1. schema contract.
#   2. delta semantics — the same check_id present in BOTH snapshots is
#      NOT a diff entry, even when the magnitude changed: history_diff
#      keys on check_id presence, so load drifting 4.1 → 5.6 is not
#      "added" or "gone". Pinning this prevents a future "fix" that
#      re-fires every persistent finding as a daily delta.
#   3. fixture integrity — loadavg.txt / loadavg-high.txt are real
#      /proc/loadavg shapes on either side of the 3.0 threshold.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "resources.load_high"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"resources\.load_high"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: same id on both sides, different magnitude.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
printf '%s\n' '{"severity": "warn", "check_id": "resources.load_high", "section": "resources", "message": "load 4.10 (threshold 3.0)"}' > "$CORPUS/yesterday.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "resources.load_high", "section": "resources", "message": "load 5.60 (threshold 3.0)"}' > "$CORPUS/today.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/yesterday.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/today.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
CHANGES="$(grep -cE '^\+ ADDED|^- GONE' "$CORPUS/diff.out")"
assert_eq "persistent check_id is not re-reported as a change" "0" "$CHANGES"
assert_grep "footer shows an empty delta" '\(\+0 -0\)' "$CORPUS/diff.out"

# 3. fixture integrity: real /proc/loadavg shape, both sides of 3.0.
# shellcheck disable=SC2016  # awk programs are deliberately single-quoted
assert_exit "loadavg.txt 1-min load below the 3.0 threshold" '^0$' \
    awk '{ exit !($1 + 0 <= 3.0) }' "$FIX/loadavg.txt"
# shellcheck disable=SC2016  # awk programs are deliberately single-quoted
assert_exit "loadavg-high.txt 1-min load above the 3.0 threshold" '^0$' \
    awk '{ exit !($1 + 0 > 3.0) }' "$FIX/loadavg-high.txt"
# shellcheck disable=SC2016  # awk programs are deliberately single-quoted
assert_exit "both fixtures carry runnable-procs and last-pid fields" '^0$' \
    awk '{ exit !(NF == 5 && $4 ~ /\//) }' "$FIX/loadavg.txt"

props_done "resources.load_high"
