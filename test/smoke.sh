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
    cid = f.get("check_id")
    if not cid:
        print("MISSING_CHECK_ID"); sys.exit(3)
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

# --- --replay [DIR] mode (issue #15) ---------------------------------------
# Replay is read-only against the live /var/log/box-audit/history — the
# smoke checks here don't touch live state, only the test/fixtures/replay
# corpus and an ephemeral empty dir. The mtime-unwritten invariant is
# checked in the brief's verification block, not here (the smoke runs as
# a non-root user without /var/log/box-audit access anyway).
FIX="$REPO/test/fixtures/replay"
EMPTY_REPLAY_DIR="$(mktemp -d)"
trap 'rm -rf "$EMPTY_REPLAY_DIR"' EXIT

# 1. Empty-dir contract: stdout says "replay directory is empty", exit 0,
#    stderr silent. Stdout/stderr captured separately so a stderr leak fails.
REPLAY_EMPTY_OUT="$(bash "$SCRIPT" --replay "$EMPTY_REPLAY_DIR" 2>/tmp/smoke.err.$$)"
REPLAY_EMPTY_RC=$?
REPLAY_EMPTY_ERR="$(cat /tmp/smoke.err.$$)"
rm -f /tmp/smoke.err.$$
if [[ $REPLAY_EMPTY_RC -eq 0 ]]; then
    ok "--replay <empty-dir> exits 0"
else
    fail "--replay <empty-dir> expected exit 0, got $REPLAY_EMPTY_RC"
fi
if [[ "$REPLAY_EMPTY_OUT" == *"replay directory is empty"* ]]; then
    ok "--replay <empty-dir> stdout contains 'replay directory is empty'"
else
    fail "--replay <empty-dir> stdout missing 'replay directory is empty' (got: $REPLAY_EMPTY_OUT)"
fi
if [[ -z "$REPLAY_EMPTY_ERR" ]]; then
    ok "--replay <empty-dir> stderr empty"
else
    fail "--replay <empty-dir> stderr not empty: $REPLAY_EMPTY_ERR"
fi

# 2. Corpus summary (no --diff): exits 0, stderr silent, no crash.
check "--replay <corpus> exits 0" '^0$' bash "$SCRIPT" --replay "$FIX"
if [[ -z "$ERR" ]]; then ok "--replay <corpus> stderr empty"; else fail "--replay <corpus> stderr not empty: $ERR"; fi

# 3. --diff 1: exits 0, deterministic across two consecutive runs.
check "--replay <corpus> --diff 1 exits 0" '^0$' bash "$SCRIPT" --replay "$FIX" --diff 1
if [[ -z "$ERR" ]]; then ok "--replay <corpus> --diff 1 stderr empty"; else fail "--replay <corpus> --diff 1 stderr not empty: $ERR"; fi
bash "$SCRIPT" --replay "$FIX" --diff 1 > /tmp/smoke.r1.$$
bash "$SCRIPT" --replay "$FIX" --diff 1 > /tmp/smoke.r2.$$
if diff -q /tmp/smoke.r1.$$ /tmp/smoke.r2.$$ >/dev/null; then
    ok "--replay <corpus> --diff 1 output deterministic (two runs byte-identical)"
else
    fail "--replay <corpus> --diff 1 output differs across runs"
    diff /tmp/smoke.r1.$$ /tmp/smoke.r2.$$ | head -5
fi
rm -f /tmp/smoke.r1.$$ /tmp/smoke.r2.$$

# 4. --diff 2: exits 0, deterministic.
check "--replay <corpus> --diff 2 exits 0" '^0$' bash "$SCRIPT" --replay "$FIX" --diff 2
if [[ -z "$ERR" ]]; then ok "--replay <corpus> --diff 2 stderr empty"; else fail "--replay <corpus> --diff 2 stderr not empty: $ERR"; fi
bash "$SCRIPT" --replay "$FIX" --diff 2 > /tmp/smoke.r1.$$
bash "$SCRIPT" --replay "$FIX" --diff 2 > /tmp/smoke.r2.$$
if diff -q /tmp/smoke.r1.$$ /tmp/smoke.r2.$$ >/dev/null; then
    ok "--replay <corpus> --diff 2 output deterministic"
else
    fail "--replay <corpus> --diff 2 output differs across runs"
fi
rm -f /tmp/smoke.r1.$$ /tmp/smoke.r2.$$

# 5. --version carries the +replay suffix.
check "--version exits 0 (replay suffix check)" '^0$' bash "$SCRIPT" --version
if [[ "$OUT" == *"+replay"* ]]; then
    ok "--version contains '+replay' suffix"
else
    fail "--version missing '+replay' suffix (got: $OUT)"
fi

# --- shellcheck across the shipped shell surface ----------------------------
if command -v shellcheck >/dev/null 2>&1; then
    if (cd "$REPO" && shellcheck scripts/box-audit.sh scripts/notify-webhook.sh install.sh test/install-lib.sh test/install.sh test/install-seeded.sh test/local-integration.sh test/all.sh test/properties/*.sh test/properties/live/*.sh); then
        ok "shellcheck passes on box-audit.sh, notify-webhook.sh, install.sh, install drivers, local pre-merge, all.sh orchestrator, property suite"
    else
        fail "shellcheck reported issues"
    fi
else
    fail "shellcheck not installed — cannot verify"
fi

# --- property suite (issue #16) ----------------------------------------------
# The suite must be green AND fast: the spec caps it at 5 seconds so it
# stays CI-cheap. One assertion covers both; a failure prints which half
# broke. (The opt-in live-agreement suite under test/properties/live/ is
# excluded from run.sh and from this budget — see run.sh's header.)
PROPS_START_NS=$(date +%s%N)
if bash "$REPO/test/properties/run.sh" > /tmp/smoke.props.$$ 2>&1; then
    PROPS_RC=0
else
    PROPS_RC=$?
fi
PROPS_ELAPSED_MS=$(( ($(date +%s%N) - PROPS_START_NS) / 1000000 ))
if [[ $PROPS_RC -eq 0 && $PROPS_ELAPSED_MS -lt 5000 ]]; then
    ok "property suite green and under 5s (${PROPS_ELAPSED_MS}ms)"
else
    fail "property suite rc=$PROPS_RC elapsed=${PROPS_ELAPSED_MS}ms (budget 5000ms) — tail of output:"
    tail -15 /tmp/smoke.props.$$
fi
rm -f /tmp/smoke.props.$$

echo
echo "smoke: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
