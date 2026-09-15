#!/usr/bin/env bash
# resources.disk_high — warns when root filesystem usage exceeds 85%
# (DISK_THRESHOLD). Input: `df / --output=...` against the live filesystem.
#
# SEAM: the script hardcodes every input path (CONFIG_DIR, HISTORY_DIR,
# INTEGRITY_* and the df/journalctl/ss/systemctl calls carry no env-var
# override), and one full `--json` run costs ~7s on a box with broad
# NOPASSWD sudo — over this suite's 5s budget. So the threshold logic
# itself cannot be fixture-driven here; T03's seeded container (or env
# seams) owns that. Asserted instead:
#   1. schema contract — the check_id exists in --print-schema output.
#   2. delta semantics — the real --replay --diff 1 path surfaces a
#      newly-emitted disk_high finding as "+ ADDED" with its message.
#   3. fixture integrity — df-output.txt is real df output shape and
#      documents both sides of the 85% threshold for T03 to drive.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "resources.disk_high"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"resources\.disk_high"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: baseline without the finding, today with it.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "resources.disk_high", "section": "resources", "message": "/dev/sdb1 233G 218G 3G 99% (99% used)"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/none.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/one.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "new disk_high surfaces as + ADDED" '^\+ ADDED' "$CORPUS/diff.out"
assert_grep "message carries the finding text" '99% used' "$CORPUS/diff.out"
assert_grep "footer counts the one addition" '\(\+1 -0\)' "$CORPUS/diff.out"

# 3. fixture integrity: real df shape, one row on each side of 85%.
assert_grep "df fixture has the --output header" '^Filesystem' "$FIX/df-output.txt"
PCTS="$(grep -oE '[0-9]+%' "$FIX/df-output.txt" | tr -d '%')"
ABOVE="$(printf '%s\n' "$PCTS" | awk '$1 + 0 > 85' | wc -l | tr -d ' ')"
BELOW="$(printf '%s\n' "$PCTS" | awk '$1 + 0 <= 85' | wc -l | tr -d ' ')"
assert_eq "fixture has a row above the 85% threshold" "1" "$ABOVE"
assert_eq "fixture has a row at-or-below the threshold" "1" "$BELOW"

props_done "resources.disk_high"
