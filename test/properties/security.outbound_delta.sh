#!/usr/bin/env bash
# security.outbound_delta — fires when today's non-LAN remote IP count
# is more than 2x yesterday's AND more than 5 absolute (classic C2
# beaconing signature). The live check reads the delta from
# .latest-counts.json (issue #38); the replay path exercises the same
# finding through presence-based diffing of two --json snapshots.
#
# SEAM: `ss -tnp state established` cannot be faked without a network
# namespace (no env override) — see security.new_port.sh. The seeded
# container pins absolute counts (tier 2); these fixtures pin the delta
# branch. Asserted against test/fixtures/replay/deltas/:
#   1. schema contract.
#   2. positive — today carries outbound_delta alone (0 → 6 remote IPs,
#      over both the 2x and >5 boundaries), so --replay --diff 1
#      reports it as + ADDED.
#   3. negative — identical snapshots at a small steady count (3 → 3):
#      the delta must NOT fire.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures/replay/deltas"
CORPUS_OUT="$(mktemp)"
trap 'rm -f "$CORPUS_OUT"' EXIT

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "security.outbound_delta"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"security\.outbound_delta"' "$BA_PROP_SCHEMA_FILE"

# 2. positive: 0 → 6 non-LAN remote IPs (clears both >2x and >5).
assert_exit "--replay <outbound-delta corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$FIX/security-outbound_delta" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
assert_grep "outbound_delta finding fires as + ADDED" \
    '^\+ ADDED.*6 non-LAN remote IP\(s\), was 0 yesterday' "$CORPUS_OUT"

# 3. negative: identical snapshots at 3 → 3 — under the >5 absolute
#    floor anyway, and presence-based diffing sees no new finding.
assert_exit "--replay <outbound-stable corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$FIX/negative-outbound-stable" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
if grep -q 'outbound_delta\|non-LAN' "$CORPUS_OUT"; then
    fail "steady remote count must not fire outbound_delta (got: $(cat "$CORPUS_OUT"))"
else
    ok "steady remote count fires no outbound_delta finding"
fi
assert_grep "footer shows an empty delta" '(\+0 -0)' "$CORPUS_OUT"

props_done "security.outbound_delta"
