#!/usr/bin/env bash
# security.outbound_remote_count_v6 — the F4 (0.9.0) v6-parity finding.
# Fires when the distinct non-private IPv6 remote count exceeds the
# outbound threshold (same knob as the combined v4+v6 check). The live
# check reads `ss -tnp state established` and cannot be faked without a
# network namespace — same seam as security.new_port.sh; the seeded
# container exercises the live path (tier 2). Asserted against replay:
#   1. schema contract.
#   2. positive — today carries the v6 finding alone, so --replay
#      --diff 1 reports it as + ADDED with the IPv6 message shape.
#   3. negative — a combined (v4+v6) finding today must NOT surface
#      the IPv6 message: the two findings are separate check_ids, so
#      folding one into the other would change this line.
#   4. negative — a steady v6 count (identical snapshots) fires
#      nothing: the finding is about presence above threshold, not
#      about day-over-day change (that is outbound_delta's job).
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

CORPUS_OUT="$(mktemp)"
trap 'rm -f "$CORPUS_OUT"' EXIT

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "security.outbound_remote_count_v6"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"security\.outbound_remote_count_v6"' "$BA_PROP_SCHEMA_FILE"
# The combined id must remain registered — F4 is additive, not a rename.
assert_grep "combined check_id still in --print-schema" '"security\.outbound_remote_count"' "$BA_PROP_SCHEMA_FILE"

CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"; rm -f "$CORPUS_OUT"' EXIT

: > "$CORPUS/none.jsonl"

# 2. positive: 0 → 2 non-LAN IPv6 remotes. The v6 message carries the
#    "IPv6" marker so the ADDED line is distinguishable from the
#    combined finding's line in the same report.
printf '%s\n' '{"severity": "warn", "check_id": "security.outbound_remote_count_v6", "section": "security", "message": "2 non-LAN IPv6 remote IP(s) connected: 2001:db8::1,2001:db8::2", "count": 2}' > "$CORPUS/v6.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/none.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/v6.jsonl"
assert_exit "--replay <v6 corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
assert_grep "v6 finding fires as + ADDED" \
    '^\+ ADDED.*2 non-LAN IPv6 remote IP\(s\) connected' "$CORPUS_OUT"

# 3. negative: today carries only the COMBINED finding (the v4 message
#    shape). The v6 id must stay absent — a regression that folds the
#    families into one check_id (or drops "IPv6" from the v6 message)
#    changes what this diff can show.
printf '%s\n' '{"severity": "warn", "check_id": "security.outbound_remote_count", "section": "security", "message": "2 non-LAN remote IP(s) connected: 198.51.100.7,203.0.113.9", "count": 2}' > "$CORPUS/v4.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/none.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/v4.jsonl"
assert_exit "--replay <v4 corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
assert_grep "combined finding still fires as + ADDED" \
    '^\+ ADDED.*2 non-LAN remote IP\(s\) connected' "$CORPUS_OUT"
if grep -q 'IPv6 remote IP(s)' "$CORPUS_OUT"; then
    fail "v4-only corpus must not surface the IPv6 message (got: $(cat "$CORPUS_OUT"))"
else
    ok "v4-only corpus surfaces no v6 finding"
fi

# 4. negative: identical v6 snapshots (2 → 2, steady) — presence-based
#    diffing sees no new finding, and the footer reports an empty delta.
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/v6.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/v6.jsonl"
assert_exit "--replay <steady v6 corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
if grep -q 'ADDED\|GONE' "$CORPUS_OUT"; then
    fail "steady v6 count must fire no finding (got: $(cat "$CORPUS_OUT"))"
else
    ok "steady v6 count fires no v6 finding"
fi
assert_grep "footer shows an empty delta" '(\+0 -0)' "$CORPUS_OUT"

props_done "security.outbound_remote_count_v6"
