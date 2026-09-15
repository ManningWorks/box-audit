#!/usr/bin/env bash
# Smoke suite for the box-audit CLI contract. Plain bash, no framework.
# CI-safe: bare ubuntu-latest has no root, no systemd services, and no
# /var/log/box-audit — every assertion here must hold on such a box.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/box-audit.sh"

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "ok   - $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL - $1"; }

# check <desc> <expected_exit_regex> <cmd...> ; asserts exit code matches,
# and captures stdout/stderr in $OUT / $ERR for follow-up assertions.
check() {
    local desc="$1" want_exit="$2"; shift 2
    OUT="$("$@" 2>/tmp/smoke.err.$$)"
    local rc=$?
    ERR="$(cat /tmp/smoke.err.$$)"
    rm -f /tmp/smoke.err.$$
    if [[ "$rc" =~ $want_exit ]]; then
        ok "$desc (exit $rc)"
        return 0
    else
        fail "$desc — expected exit ~$want_exit, got $rc"
        return 1
    fi
}

# --- schema (needed by the --json finding assertion) -----------------------
check "--print-schema exits 0" '^0$' bash "$SCRIPT" --print-schema
SCHEMA="$OUT"
if printf '%s' "$SCHEMA" | python3 -m json.tool >/dev/null 2>&1; then
    ok "--print-schema pipes clean through python3 -m json.tool"
else
    fail "--print-schema output is not valid JSON"
fi

# --- help / version --------------------------------------------------------
if check "--help exits 0" '^0$' bash "$SCRIPT" --help; then
    if [[ "$OUT" == *"Usage:"* ]]; then ok "--help prints usage"; else fail "--help output missing 'Usage:'"; fi
fi
check "--version exits 0" '^0$' bash "$SCRIPT" --version

# --- unknown flag ----------------------------------------------------------
if check "--nope exits 2" '^2$' bash "$SCRIPT" --nope; then
    if [[ "$ERR" == *"--nope"* ]]; then ok "--nope stderr mentions the flag"; else fail "--nope stderr missing the flag (got: $ERR)"; fi
fi

# --- --tail: optional arg, must not crash under set -u ----------------------
check "bare --tail exits 0" '^0$' bash "$SCRIPT" --tail
if [[ -z "$ERR" ]]; then ok "bare --tail stderr empty"; else fail "bare --tail stderr not empty: $ERR"; fi

check "--tail 3 exits 0" '^0$' bash "$SCRIPT" --tail 3
if [[ -z "$ERR" ]]; then ok "--tail 3 stderr empty"; else fail "--tail 3 stderr not empty: $ERR"; fi

# --- --diff: optional arg; exit 1 only for missing-history, never a
#     dispatch-order failure ("command not found") ---------------------------
check "bare --diff exits 0|1" '^[01]$' bash "$SCRIPT" --diff
if [[ "$ERR" == *"command not found"* ]]; then
    fail "bare --diff stderr contains 'command not found' (dispatch-order bug is back)"
elif [[ -n "$ERR" && "$ERR" != *"cannot find"* ]]; then
    fail "bare --diff unexpected stderr: $ERR"
else
    ok "bare --diff stderr is empty or 'cannot find' (no-history)"
fi

check "--diff 2 exits 0|1" '^[01]$' bash "$SCRIPT" --diff 2
if [[ "$ERR" == *"command not found"* ]]; then
    fail "--diff 2 stderr contains 'command not found'"
elif [[ "$ERR" == *"cannot find"* || -z "$ERR" ]]; then
    ok "--diff 2 stderr is empty or 'cannot find'"
else
    fail "--diff 2 unexpected stderr: $ERR"
fi

# --- --json contract --------------------------------------------------------
check "--json exits 0" '^0$' bash "$SCRIPT" --json
if bash "$SCRIPT" --json 2>/dev/null | python3 -m json.tool >/dev/null 2>&1; then
    ok "--json output parses as JSON"
else
    fail "--json output does not parse as JSON"
fi

JSON_PROBE='
import json, sys
d = json.load(sys.stdin)
missing = [k for k in ("status", "timestamp", "host", "findings") if k not in d]
if missing:
    print("MISSING:" + ",".join(missing)); sys.exit(1)
schema = json.load(open(sys.argv[1]))["check_ids"]
ids = []
for f in d["findings"]:
    cid = f.get("check_id", f.get("id"))
    ids.append(cid)
    if cid not in schema:
        print("UNKNOWN_CHECK:" + str(cid)); sys.exit(2)
print("OK " + str(len(ids)))
'
SCHEMA_FILE="$(mktemp)"
printf '%s' "$SCHEMA" > "$SCHEMA_FILE"
trap 'rm -f "$SCHEMA_FILE"' EXIT
JSON_PROBE_RUNNER() {
    bash "$SCRIPT" --json 2>/dev/null | python3 -c "$JSON_PROBE" "$SCHEMA_FILE"
}
if JSON_ERR="$(JSON_PROBE_RUNNER 2>&1 >/dev/null)"; then
    ok "--json has status/timestamp/host/findings; finding ids in schema ($(JSON_PROBE_RUNNER 2>/dev/null))"
else
    rc=$?
    # Report honestly, do not mask: unknown check ids are a real
    # schema/emit mismatch, not an assertion to hack around.
    fail "--json key/finding check failed (rc=$rc): $JSON_ERR"
fi

# --- shellcheck across the shipped shell surface ----------------------------
if command -v shellcheck >/dev/null 2>&1; then
    if (cd "$REPO" && shellcheck scripts/box-audit.sh scripts/notify-webhook.sh install.sh); then
        ok "shellcheck passes on box-audit.sh, notify-webhook.sh, install.sh"
    else
        fail "shellcheck reported issues"
    fi
else
    fail "shellcheck not installed — cannot verify"
fi

echo
echo "smoke: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
