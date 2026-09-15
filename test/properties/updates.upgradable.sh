#!/usr/bin/env bash
# updates.upgradable — emits an info-severity finding when more than 20
# packages are upgradable (UPDATE_THRESHOLD) — note the severity class:
# a big queue is routine state, not a warning (security_pending is the
# warn-severity sibling). Input: `apt list --upgradable | tail -n +2`.
#
# SEAM: apt state cannot be redirected (no env override; and on a box
# with NOPASSWD apt-get — like this NucBox — a full --json run also
# primes the cache, pushing one run to ~7s) — see resources.disk_high.sh.
# T03's seeded container will pin a package count. Asserted instead:
#   1. schema contract.
#   2. delta semantics — a persistent upgrade queue is NOT a delta:
#      the same check_id on both days is not re-reported as changed.
#   3. (fixture gap) no apt fixture exists yet — `apt list --upgradable`
#      output is box-specific enough that T03 should record it inside
#      the container; tracked in the fixtures README's gaps section.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "updates.upgradable"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"updates\.upgradable"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: the queue persists day-over-day with different
# magnitude — presence-based diffing keeps it out of the delta.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
printf '%s\n' '{"severity": "info", "check_id": "updates.upgradable", "section": "updates", "message": "28 packages upgradable (distro: 20 · 3rd-party: 8)"}' > "$CORPUS/yesterday.jsonl"
printf '%s\n' '{"severity": "info", "check_id": "updates.upgradable", "section": "updates", "message": "35 packages upgradable (distro: 27 · 3rd-party: 8)"}' > "$CORPUS/today.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/yesterday.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/today.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
CHANGES="$(grep -cE '^\+ ADDED|^- GONE' "$CORPUS/diff.out")"
assert_eq "persistent queue is not re-reported as a change" "0" "$CHANGES"
assert_grep "footer shows an empty delta" '\(\+0 -0\)' "$CORPUS/diff.out"

props_done "updates.upgradable"
