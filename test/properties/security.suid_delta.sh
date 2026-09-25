#!/usr/bin/env bash
# security.suid_delta — fires when today's SUID count exceeds yesterday's
# by more than 2 (classic rootkit persistence: a dropped SUID binary).
# The live check reads the delta from .latest-counts.json (issue #38);
# the replay path exercises the same finding through presence-based
# diffing of two --json snapshots.
#
# SEAM: /-wide SUID find cannot be redirected (no env override; a full
# --json run costs ~7s on a sudo-granted box) — see resources.disk_high.sh.
# The seeded container pins absolute counts (tier 2); these fixtures pin
# the delta branch. Asserted against test/fixtures/replay/deltas/:
#   1. schema contract.
#   2. positive — today carries suid_delta alone (21 → 24 SUID), so
#      --replay --diff 1 reports it as + ADDED.
#   3. negative — identical snapshots: the delta must NOT fire.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures/replay/deltas"
CORPUS_OUT="$(mktemp)"
trap 'rm -f "$CORPUS_OUT"' EXIT

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "security.suid_delta"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"security\.suid_delta"' "$BA_PROP_SCHEMA_FILE"

# 2. positive: 21 → 24 SUID binaries (+3, over the >2 jump threshold).
assert_exit "--replay <suid-delta corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$FIX/security-suid_delta" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
assert_grep "suid_delta finding fires as + ADDED" '^\+ ADDED.*\+3 new SUID binaries' "$CORPUS_OUT"

# 3. negative: identical snapshots — a stable count is not a delta.
assert_exit "--replay <suid-stable corpus> --diff 1 exits 0" '^0$' \
    bash "$SCRIPT" --replay "$FIX/negative-suid-stable" --diff 1
printf '%s' "$OUT" > "$CORPUS_OUT"
if grep -q 'suid_delta\|SUID binaries' "$CORPUS_OUT"; then
    fail "stable SUID count must not fire suid_delta (got: $(cat "$CORPUS_OUT"))"
else
    ok "stable SUID count fires no suid_delta finding"
fi
assert_grep "footer shows an empty delta" '(\+0 -0)' "$CORPUS_OUT"

props_done "security.suid_delta"
