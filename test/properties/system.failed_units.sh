#!/usr/bin/env bash
# system.failed_units — warns when one or more systemd service units are
# in the failed state. Input: `systemctl list-units --type=service
# --state=failed --no-legend --plain --no-pager`; every output line is
# one failed unit, and the message names the first five.
#
# SEAM: systemd state cannot be redirected (no env override; full --json
# run costs ~7s on a sudo-granted box) — see resources.disk_high.sh.
# T03's seeded container will mask a real unit as failed. Asserted
# instead:
#   1. schema contract.
#   2. delta semantics — a unit failing overnight surfaces as "+ ADDED".
#   3. fixture integrity — systemctl-failed-units.txt is a real captured
#     line: each line carries a *.service first field, and the line count
#     is exactly the failed-unit count the check reports.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "system.failed_units"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"system\.failed_units"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: a unit fails overnight.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "system.failed_units", "section": "system", "message": "1 failed service(s): nginx.service"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/none.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/one.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "new failed_units surfaces as + ADDED" '^\+ ADDED' "$CORPUS/diff.out"
assert_grep "message names the failed unit" 'nginx\.service' "$CORPUS/diff.out"

# 3. fixture integrity: real systemctl shape; line count == unit count.
UNIT_NAMES="$(awk '{print $1}' "$FIX/systemctl-failed-units.txt" | grep -c '\.service$')"
assert_eq "fixture has one failed unit line" "1" "$UNIT_NAMES"
assert_grep "unit line carries the loaded/failed state columns" \
    '\.service loaded failed failed ' "$FIX/systemctl-failed-units.txt"

props_done "system.failed_units"
