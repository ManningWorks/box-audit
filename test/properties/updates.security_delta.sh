#!/usr/bin/env bash
# updates.security_delta — fires when the security-update queue grows
# by more than 1 vs yesterday (unattended-upgrades failing faster than
# it can drain). The live check reads the delta from
# .latest-counts.json (issue #38); the replay path exercises the same
# finding through presence-based diffing of two --json snapshots.
#
# SEAM: `apt list --upgradable` output is box-specific and cannot be
# redirected (no env override; cache priming needs NOPASSWD sudo) —
# see updates.upgradable.sh. The seeded container pins absolute counts
# (tier 2); these fixtures pin the delta branch. Asserted against
# test/fixtures/replay/deltas/:
#   1. schema contract.
#   2. positive — today carries security_delta alone (1 → 4 pending,
#      over the >1 growth threshold), so --replay --diff 1 reports it
#      as + ADDED.
#   3. negative — identical snapshots whose security_pending finding
#      exists on BOTH days (1 → 1): presence-based diffing sees no
#      change, and the delta must NOT fire even though a security
#      finding is present — the queue is steady, not growing.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures/replay/deltas"
CORPUS_OUT="$(mktemp)"
trap 'rm -f "$CORPUS_OUT"' EXIT

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "updates.security_delta"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"updates\.security_delta"' "$BA_PROP_SCHEMA_FILE"

# 2. positive: 1 → 4 security updates pending (growth of 3, over >1).
assert_exit "--replay <security-delta corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$FIX/updates-security_delta" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
assert_grep "security_delta finding fires as + ADDED" \
    '^\+ ADDED.*security queue grew by 3 vs yesterday' "$CORPUS_OUT"

# 3. negative: identical snapshots, security_pending on BOTH days.
#    The sharpest negative here: an existing finding is not a delta —
#    only growth past the threshold is.
assert_exit "--replay <security-stable corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$FIX/negative-security-stable" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
if grep -q 'security_delta\|grew by' "$CORPUS_OUT"; then
    fail "steady security queue must not fire security_delta (got: $(cat "$CORPUS_OUT"))"
else
    ok "steady security queue fires no security_delta finding"
fi
assert_grep "footer shows an empty delta" '(\+0 -0)' "$CORPUS_OUT"

props_done "updates.security_delta"
