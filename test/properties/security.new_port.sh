#!/usr/bin/env bash
# security.new_port — warns per listening port that is not in the
# ports-allowlist (default "22 53 80 443 631" before --init learns the
# box). Input: `ss -tlnp | grep LISTEN`, column 4 = Local Address:Port.
#
# SEAM: listening sockets cannot be faked without a network namespace or
# the seeded container (no env override for the ss invocation; full --json
# run costs ~7s on a sudo-granted box) — see resources.disk_high.sh.
# T03's container will open a real socket outside the allowlist. Asserted
# instead:
#   1. schema contract.
#   2. delta semantics — a port that closed since yesterday surfaces as
#      "- GONE".
#   3. fixture integrity — ss-tln.txt is real `ss -tlnp` shape whose
#      column-4 ports extract to exactly {22, 9999}: one allowlisted,
#      one not, i.e. the classification boundary in one file.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "security.new_port"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"security\.new_port"' "$BA_PROP_SCHEMA_FILE"

# 2. delta semantics: port 9999 was flagged yesterday, closed since.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "security.new_port", "section": "security", "message": "9999 is open (not in baseline) [mystery-server]"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/none.jsonl"
assert_exit "--replay --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "closed new_port surfaces as - GONE" '^- GONE' "$CORPUS/diff.out"
assert_grep "message carries the port number" '9999 is open' "$CORPUS/diff.out"

# 3. fixture integrity: real ss shape; ports extract to {22, 9999}.
assert_grep "ss fixture has the LISTEN header" '^State' "$FIX/ss-tln.txt"
PORTS="$(awk '{print $4}' "$FIX/ss-tln.txt" | grep -oP ':\K\d+$' | sort -u | tr '\n' ' ')"
PORTS="${PORTS% }"
assert_eq "fixture ports are exactly the allowlisted+unexpected pair" "22 9999" "$PORTS"
# The here-string feeds assert_exit's stdin, which the helper's inner
# command substitution inherits — so grep reads the allowlist text.
assert_exit "22 is inside the default allowlist" '^0$' grep -qw 22 <<< "22 53 80 443 631"
assert_exit "9999 is outside the default allowlist (grep no-match exits 1)" '^1$' \
    grep -qw 9999 <<< "22 53 80 443 631"

props_done "security.new_port"
