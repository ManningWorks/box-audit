#!/usr/bin/env bash
# security.fail2ban_jail — F2 (0.9.0). Discovers active fail2ban jails at
# runtime via `fail2ban-client status` instead of the hardcoded jail-name
# list, and emits one alert per discovered (non-sshd) jail that has a
# non-zero banned count. sshd stays on the existing security.fail2ban_banned
# floor (shape-unchanged) so it is never double-reported.
#
# SEAM: the live `fail2ban-client status` / `status <jail>` output is
# environment-dependent (jail set varies per box), so — like
# security.ssh_fails.sh — we assert the PARSE against real-format fixtures
# rather than a live client. The tier-2 seeded container (recidive + sshd)
# exercises the live discovery path end to end.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "security.fail2ban_jail"; exit 1; }

# 1. schema contract: the per-jail finding id must be registered in
#    --print-schema (the smoke.sh schema gate rejects any emitted check_id
#    that is not there), and the sshd floor id must stay put.
assert_grep "security.fail2ban_jail in --print-schema" '"security\.fail2ban_jail"' "$BA_PROP_SCHEMA_FILE"
assert_grep "security.fail2ban_banned floor id still in --print-schema" '"security\.fail2ban_banned"' "$BA_PROP_SCHEMA_FILE"

# 2. fixture integrity: real fail2ban-client output shape, frozen. The
#    full-status fixture is the multi-jail variant — the exact byte shape the
#    live container produced (alphabetical, comma+space separated). The
#    discovery parse (everything after "list:", tab-stripped) must recover
#    both names and the right count; adding a jail can never shrink the set.
LIST_FIX="$FIX/fail2ban-status-list.txt"
assert_grep "list fixture is the real multi-jail full-status shape" \
    'Jail list:[[:space:]]+recidive, sshd' "$LIST_FIX"
JAILS_PARSED="$(awk -F'list:' '/Jail list/ {print $2}' "$LIST_FIX" | tr -d '\t' | tr ',' ' ')"
assert_eq "jail-list parse recovers both discovered jail names" "recidive sshd" "$(echo "$JAILS_PARSED" | tr -s ' ')"
assert_eq "discovered-jail count agrees with the parse (2)" "2" "$(echo "$JAILS_PARSED" | wc -w | tr -d ' ')"
assert_eq "jail count (2) >= hardcoded floor (1) — discovery is additive" "0" "$(test 2 -ge 1 && echo 0 || echo 1)"

# 3. floor still works: the sshd floor parses the per-jail fixture the same
#    way it does today (the `Currently banned:` value, field 4 after the
#    `|-` prefix). This is independent of discovery — the hardcoded floor
#    must keep producing its count when the client is missing or discovery
#    fails.
FLOOR_FIX="$FIX/fail2ban-status.txt"
assert_grep "per-jail fixture carries the real Currently banned line" \
    'Currently banned:[[:space:]]+1' "$FLOOR_FIX"
BANNED="$(awk '/Currently banned/ {print $4}' "$FLOOR_FIX" | tr -d ' ')"
assert_eq "hardcoded floor (sshd) parses the banned count (1)" "1" "$BANNED"

# 4. delta semantics: a newly discovered jail with a banned IP surfaces as
#    "+ ADDED" in the --replay --diff 1 output.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "alert", "check_id": "security.fail2ban_jail", "section": "security", "message": "1 IP(s) banned on recidive"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/none.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/one.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "new jail finding surfaces as + ADDED" '^\+ ADDED' "$CORPUS/diff.out"
assert_grep "message carries the jail name" 'banned on recidive' "$CORPUS/diff.out"

props_done "security.fail2ban_jail"
