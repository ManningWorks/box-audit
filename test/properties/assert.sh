# shellcheck shell=bash
# assert.sh — shared assertion helpers for the box-audit property suite.
# Sourced by every test under test/properties/. Mirrors test/smoke.sh's
# style deliberately: plain bash, set -u, PASS/FAIL counters, ok/fail
# helpers — no framework, no new interpreter. props_done() prints the
# per-file summary and exits non-zero on any failure so run.sh can
# aggregate file-level results.

# Repo layout, resolved once from this file's location so tests work
# from any CWD (run.sh invokes by absolute path).
PROPS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$PROPS_DIR/../.." && pwd)"
# Consumed by every sourcing test file (shellcheck can't see across
# `source`, hence the disable below).
# shellcheck disable=SC2034
SCRIPT="$REPO_ROOT/scripts/box-audit.sh"

set -u

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); echo "ok   - $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL - $1"; }

# assert_eq <desc> <expected> <actual> — exact string equality.
assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        ok "$desc"
    else
        fail "$desc — expected [$expected], got [$actual]"
    fi
}

# assert_grep <desc> <pattern> <file> — extended regex must match <file>.
assert_grep() {
    local desc="$1" pattern="$2" file="$3"
    if [[ -f "$file" ]] && grep -qE "$pattern" "$file"; then
        ok "$desc"
    else
        fail "$desc — pattern [$pattern] not found in $file"
    fi
}

# assert_exit <desc> <expected_rc_regex> <cmd...> — run the command,
# assert its exit code matches, and capture stdout/stderr in $OUT/$ERR
# for follow-up assertions (same shape as test/smoke.sh's check()).
assert_exit() {
    local desc="$1" want_rc="$2"; shift 2
    local rc
    # OUT/ERR are read by the CALLER after this returns; shellcheck
    # cannot see across the source boundary.
    # shellcheck disable=SC2034
    OUT="$("$@" 2>/tmp/props.err.$$)"
    rc=$?
    ERR="$(cat /tmp/props.err.$$)"
    rm -f /tmp/props.err.$$
    if [[ "$rc" =~ $want_rc ]]; then
        ok "$desc (exit $rc)"
    else
        fail "$desc — expected exit ~$want_rc, got $rc (stderr: $ERR)"
    fi
}

# props_done [label] — print the per-file summary line and exit non-zero
# when any assertion in this test file failed.
props_done() {
    echo "props: $PASS passed, $FAIL failed — ${1:-$(basename "$0")}"
    [[ $FAIL -eq 0 ]]
}

# props_write_snapshot <out.json> <findings-jsonl>
# Wrap JSONL findings (one json.dumps-shaped finding object per line, the
# exact shape json_push appends to FINDINGS_FILE) into a --json-shaped
# daily snapshot, byte-compatible with what --json emits. Used to build
# ephemeral replay corpora for the delta-semantics assertions.
props_write_snapshot() {
    local out="$1" jsonl="$2"
    {
        printf '{"status":"findings","timestamp":"2026-09-15T03:00:00Z","host":"props-fixture","findings":['
        paste -sd, "$jsonl" 2>/dev/null
        printf '],"raw_output":"(property-test corpus)"}'
    } > "$out"
}
