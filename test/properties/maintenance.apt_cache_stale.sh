#!/usr/bin/env bash
# maintenance.apt_cache_stale — warns when /var/lib/apt/periodic/
# update-success-stamp is older than 48h (APT_CACHE_STALE_SECS=172800),
# or when it is missing entirely (apt update has never succeeded).
# Input: the stamp file's mtime — the file content is empty.
#
# SEAM: the stamp path is hardcoded and its mtime cannot be faked from
# outside (no env override; full --json run costs ~7s on a sudo-granted
# box) — see resources.disk_high.sh. T03's seeded container will age a
# real stamp. Asserted instead:
#   1. schema contract.
#   2. delta semantics — the cache going stale surfaces as "+ ADDED".
#   3. fixture integrity — both stamp variants are empty files like the
#      real stamp (mtime is the signal), and the stale variant's mtime
#      is genuinely older than the 48h window while fresh is not.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "maintenance.apt_cache_stale"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"maintenance\.apt_cache_stale"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: the stamp crosses the 48h line today.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "maintenance.apt_cache_stale", "section": "maintenance", "message": "stale (259200s / 48h since last apt update)"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/none.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/one.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "new apt_cache_stale surfaces as + ADDED" '^\+ ADDED' "$CORPUS/diff.out"
assert_grep "message carries the staleness" 'since last apt update' "$CORPUS/diff.out"

# 3. fixture integrity: empty content like the real stamp; mtime
# carries the age on either side of 172800s (48h). Git does not track
# mtimes, so the test re-stamps both files itself — this is also the
# regeneration recipe documented in test/fixtures/README.md.
assert_exit "fresh stamp is empty like the real stamp" '^0$' test ! -s "$FIX/apt-update-stamp-fresh"
assert_exit "stale stamp is empty like the real stamp" '^0$' test ! -s "$FIX/apt-update-stamp-stale"

touch "$FIX/apt-update-stamp-fresh"
touch -d '4 days ago' "$FIX/apt-update-stamp-stale"

stamp_older_than() {
    # stamp_older_than <file> <secs> — exit 0 when the file's mtime age
    # exceeds <secs>. Called via assert_exit, so the rc IS the assertion.
    local now age
    now=$(date +%s)
    age=$(( now - $(stat -c %Y "$1") ))
    (( age > $2 ))
}
assert_exit "fresh stamp is younger than 48h" '^1$' stamp_older_than "$FIX/apt-update-stamp-fresh" 172800
assert_exit "stale stamp is older than 48h" '^0$' stamp_older_than "$FIX/apt-update-stamp-stale" 172800

props_done "maintenance.apt_cache_stale"
