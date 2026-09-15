#!/usr/bin/env bash
# maintenance.timer_drift — warns when apt-daily.timer or
# apt-daily-upgrade.timer has never fired, or last fired more than 26h
# ago (TIMER_DRIFT_SECS=104400). Input: `systemctl show <timer>
# --property=LastTriggerUSec --value`, converted to epoch seconds.
#
# SEAM: systemd timer state cannot be redirected (no env override; full
# --json run costs ~7s on a sudo-granted box) — see resources.disk_high.sh.
# T03's seeded container will mask LastTriggerUSec. There is also no
# fixture for systemctl-show output yet (fixtures README "Gaps").
# Asserted instead:
#   1. schema contract.
#   2. delta semantics — a timer firing again (drift resolved) surfaces
#      as "- GONE".
#   3. (fixture gap) no fixture exists for `systemctl show
#      --property=LastTriggerUSec` output yet; a threshold test would
#      need to copy the date arithmetic, which is self-matching slop.
#      The fixtures README tracks this as a T03 gap.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "maintenance.timer_drift"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"maintenance\.timer_drift"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: drift resolves when the timer fires again.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "maintenance.timer_drift", "section": "maintenance", "message": "apt-daily.timer hasn'\''t fired in 187200s (52h)"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/none.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "resolved timer_drift surfaces as - GONE" '^- GONE' "$CORPUS/diff.out"
assert_grep "message names the timer" 'apt-daily\.timer' "$CORPUS/diff.out"

props_done "maintenance.timer_drift"
