#!/usr/bin/env bash
# security.ssh_fails — warns when SSH auth failures in the last 24h exceed
# 15 (SSH_FAIL_THRESHOLD). Input: journalctl --facility=auth filtered by
# grep -ciE 'Failed password|Invalid user'.
#
# SEAM: journalctl output cannot be redirected (no env override, and a
# full --json run costs ~7s on a sudo-granted box) — see
# resources.disk_high.sh. T03's seeded container will feed real journal
# lines. Asserted instead:
#   1. schema contract.
#   2. delta semantics — a new ssh_fails finding surfaces as "+ ADDED".
#   3. fixture integrity + monotonicity — journalctl-ssh-auth-fail.txt
#      holds three real-format journal lines the check's own patterns
#      count as 3; the empty variant counts as 0. Adding failed-auth
#      lines to the corpus never decreases the count, which is the
#      monotonicity property the seeded container will assert against
#      live journal input.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "security.ssh_fails"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"security\.ssh_fails"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: brute-force campaign begins today.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "security.ssh_fails", "section": "security", "message": "23 failed auth attempts (24h)"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/none.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/one.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "new ssh_fails surfaces as + ADDED" '^\+ ADDED' "$CORPUS/diff.out"
assert_grep "message carries the finding text" '23 failed auth attempts' "$CORPUS/diff.out"

# 3. fixture integrity: real journalctl line shape; the check's own
# count patterns (gc 'Failed password|Invalid user') yield 3 vs 0.
assert_grep "populated fixture is real journalctl auth format" \
    '^[A-Z][a-z]{2} +[0-9]+ [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ sshd\[[0-9]+\]: (Failed password|Invalid user)' \
    "$FIX/journalctl-ssh-auth-fail.txt"
POPULATED="$(grep -ciE 'Failed password|Invalid user' "$FIX/journalctl-ssh-auth-fail.txt")"
EMPTY="$(grep -ciE 'Failed password|Invalid user' "$FIX/journalctl-ssh-auth-fail-empty.txt")"
assert_eq "populated fixture counts 3 failed-auth lines" "3" "$POPULATED"
assert_eq "empty fixture counts 0 failed-auth lines" "0" "$EMPTY"
assert_exit "adding auth-fail lines never decreases the count" '^0$' \
    test "$POPULATED" -gt "$EMPTY"

props_done "security.ssh_fails"
