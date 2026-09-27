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

# --- F2 (0.9.0) fail2ban jail discovery: schema + degraded-floor pins --------
# The per-jail id must be registered in --print-schema (the --json gate below
# rejects any emitted check_id not in the map), and the sshd floor id must
# stay put. Both hold regardless of whether fail2ban is installed here.
if printf '%s' "$SCHEMA" | grep -q '"security.fail2ban_jail"'; then
    ok "--print-schema registers security.fail2ban_jail"
else
    fail "--print-schema missing security.fail2ban_jail"
fi
if printf '%s' "$SCHEMA" | grep -q '"security.fail2ban_banned"'; then
    ok "--print-schema still registers the security.fail2ban_banned floor"
else
    fail "--print-schema missing the security.fail2ban_banned floor id"
fi
# Degraded-floor contract: on a box without fail2ban (CI runner) the check
# must not crash and the audit must stay JSON-valid — the hardcoded floor
# remains the no-regression path when discovery is unavailable.
if bash "$SCRIPT" --json 2>/dev/null | python3 -m json.tool >/dev/null 2>&1; then
    ok "--json stays valid with no fail2ban client (degraded floor path)"
else
    fail "--json not valid on the no-fail2ban path"
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

# --- --init idempotency report (F1, 0.9.0) ----------------------------------
# Root-gated (manage commands require root), so this block runs only where
# root or passwordless sudo is available AND /var/lib/box-audit does not
# exist — --init rewrites the allowlists from live system state, so a box
# with a real install keeps its config untouched. This placement is
# load-bearing: it must run before any root-executed audit below creates
# /var/lib/box-audit for its integrity baseline. Three-run protocol pins
# all three operator-visible outcomes: fresh seed, no-op re-run, re-seed
# after a manual edit. The dir is removed afterwards so re-running the
# suite stays fresh.
INIT_SKIP=""
if [[ -e /var/lib/box-audit ]]; then
    INIT_SKIP="/var/lib/box-audit already exists (live install — not touched)"
elif [[ $EUID -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true >/dev/null 2>&1; then
        INIT_SKIP="no root and no passwordless sudo"
    fi
fi
if [[ -n "$INIT_SKIP" ]]; then
    ok "--init idempotency skipped: $INIT_SKIP"
else
    INIT_PREFIX=()
    [[ $EUID -ne 0 ]] && INIT_PREFIX=(sudo)
    if check "--init on a fresh config dir exits 0" '^0$' "${INIT_PREFIX[@]}" bash "$SCRIPT" --init; then
        if [[ "$OUT" == "box-audit: seeded "* ]]; then ok "--init fresh run reports seeded"; else fail "--init fresh run not reporting seeded (got: $OUT)"; fi
    fi
    if check "--init re-run with no changes exits 0" '^0$' "${INIT_PREFIX[@]}" bash "$SCRIPT" --init; then
        if [[ "$OUT" == "box-audit: config unchanged at /var/lib/box-audit" ]]; then ok "--init no-op re-run reports config unchanged"; else fail "--init no-op re-run not reporting unchanged (got: $OUT)"; fi
    fi
    "${INIT_PREFIX[@]}" /bin/sh -c 'echo 631 >> /var/lib/box-audit/ports-allowlist.txt'
    if check "--init after a manual allowlist edit exits 0" '^0$' "${INIT_PREFIX[@]}" bash "$SCRIPT" --init; then
        if [[ "$OUT" == "box-audit: seeded "* ]]; then ok "--init after manual edit reports seeded again"; else fail "--init after manual edit not reporting seeded (got: $OUT)"; fi
    fi
    "${INIT_PREFIX[@]}" rm -rf /var/lib/box-audit
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

# --- --json `counts` block (issue #38) --------------------------------------
# Regression for the delta-mode signal integrity bug: history_persist_counts_from_json
# used to source counts from findings[] (which only carries counts when the
# absolute threshold tripped), causing false +N delta findings on healthy
# boxes. Fix is an additive `counts` block alongside `findings`, populated
# from the live measurement regardless of threshold. The block is the
# single source of truth the next-day delta check reads from, so its
# presence + shape is the load-bearing contract.
COUNTS_PROBE='
import json, sys
d = json.load(sys.stdin)
c = d.get("counts")
if not isinstance(c, dict):
    print("MISSING_COUNTS_BLOCK"); sys.exit(1)
expected = ("suid_count", "outbound_remote_count", "security_pending")
problems = []
for k in expected:
    v = c.get(k)
    if not isinstance(v, int):
        problems.append(f"{k}={v!r}")
if problems:
    print("BAD_COUNTS_FIELDS:" + ",".join(problems)); sys.exit(2)
print("OK " + ",".join(f"{k}={c[k]}" for k in expected))
'
COUNTS_RUNNER() {
    bash "$SCRIPT" --json 2>/dev/null | python3 -c "$COUNTS_PROBE"
}
# Single audit invocation, two semantic uses (rc + diagnostic). The
# probe writes either "OK key=val,..." or "FAIL_TAG:..." to stdout and
# exits 0 or non-zero accordingly; stderr is silent for both paths.
# Capturing one stream and stamping the rc on the end preserves the
# original two-calls' information without paying for a second --json.
COUNTS_COMBINED="$(COUNTS_RUNNER; echo "RC=$?")"
COUNTS_RC="${COUNTS_COMBINED##*RC=}"
COUNTS_OUT="${COUNTS_COMBINED%RC=*}"
COUNTS_OUT="${COUNTS_OUT%$'\n'}"
if [[ "$COUNTS_RC" -eq 0 ]]; then
    ok "--json has counts block with suid_count/outbound_remote_count/security_pending ($COUNTS_OUT)"
else
    fail "--json counts block check failed (rc=$COUNTS_RC): $COUNTS_OUT"
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

# --- lock gate: unopenable lock dir degrades loudly, never exit 0 ------------
# A read-only lock dir (ProtectSystem=strict without a writable /tmp) makes
# the lockfile unopenable. That must be a LOUD failure (exit 75), not a
# silent exit 0 — the old gate conflated "fd failed to open (EROFS)" with
# "flock held by a real contender" and exit 0'd both, so the service looked
# healthy while having run zero checks. Negative variant per AGENTS.md.
# BOXAUDIT_LOCK_DIR keeps the harness off shared /tmp; on a box without
# shell-exec privileges the open failure can't be induced, so the block
# skips itself (still CI-safe on a bare runner).
LOCKTEST_DIR=""
cleanup_locktest() { [[ -n "$LOCKTEST_DIR" ]] && chmod -R u+w "$LOCKTEST_DIR" 2>/dev/null; rm -rf "${LOCKTEST_DIR:-}"; }
if ! ( : > /tmp/smoke.lockprobe.$$ ) 2>/dev/null; then
    ok "lock-gate EROFS test skipped: no /tmp write permission to stage a read-only dir"
else
    rm -f /tmp/smoke.lockprobe.$$
    LOCKTEST_DIR=$(mktemp -d /tmp/lockgate.XXXXXX)
    LOCKTEST_RO="$LOCKTEST_DIR/ro"
    mkdir -p "$LOCKTEST_RO" && chmod 0555 "$LOCKTEST_RO"
    if ( : > "$LOCKTEST_RO/probe" ) 2>/dev/null; then
        # The probe write SUCCEEDED in a 0555 dir: we are root (or otherwise
        # bypass mode checks), so a read-only dir cannot induce the open
        # failure — the EROFS branch is not inducible here.
        ok "lock-gate EROFS test skipped: run as $EUID, read-only dir not effective"
    else
        OUT="$(BOXAUDIT_LOCK_DIR="$LOCKTEST_RO" bash "$SCRIPT" --json 2>/tmp/smoke.lockerr.$$)"
        rc=$?
        ERR="$(cat /tmp/smoke.lockerr.$$)"
        rm -f /tmp/smoke.lockerr.$$
        if [[ "$rc" -eq 75 ]]; then
            ok "unopenable lock dir exits 75 (loud failure, not silent success) (exit $rc)"
        else
            fail "unopenable lock dir must exit 75, got $rc (silent success is the bug)"
        fi
        if [[ "$ERR" == *"cannot open lock file"* ]]; then
            ok "unopenable lock dir names the failure on stderr"
        else
            fail "unopenable lock dir stderr missing the failure signal (got: $ERR)"
        fi
    fi
fi
cleanup_locktest

# --- notify-webhook severity floor (F3, 0.9.0) --------------------------------
# The notifier POSTs the snapshot to a URL; the sink here is a stub curl
# (temp dir prepended to PATH for this block only) that records the posted
# --data-binary body. No network, no root: the snapshot is a local fixture
# passed as $1, so this holds on a bare CI runner. The fixture carries one
# finding per severity tier, so the filter arithmetic is exact.
NOTIFY_DIR="$(mktemp -d /tmp/notifytest.XXXXXX)"
NOTIFY_FIX="$NOTIFY_DIR/latest.json"
NOTIFY_BODY="$NOTIFY_DIR/body"
NOTIFY_ARGS="$NOTIFY_DIR/args"
NOTIFY_ERRF="$NOTIFY_DIR/stderr"
cat > "$NOTIFY_FIX" <<'NOTIFY_JSON'
{
  "findings": [
    {
      "check_id": "updates.upgradable",
      "message": "3 packages upgradable",
      "section": "updates",
      "severity": "info"
    },
    {
      "check_id": "security.new_port",
      "message": "open port 12345 not in ports-allowlist",
      "section": "security",
      "severity": "warn"
    },
    {
      "check_id": "security.ssh_fails",
      "message": "12 sudo auth failures in last 24h",
      "section": "security",
      "severity": "alert"
    },
    {
      "check_id": "degraded.check",
      "message": "docker not installed",
      "section": "system",
      "severity": "degraded"
    }
  ],
  "host": "fixture",
  "status": "ok",
  "timestamp": "2026-01-01T00:00:00Z"
}
NOTIFY_JSON
cat > "$NOTIFY_DIR/curl" <<'NOTIFY_STUB'
#!/usr/bin/env bash
# stub curl: record the --data-binary body and the arg list, exit 0 (no network).
prev=""
for a in "$@"; do
    if [[ "$prev" == "--data-binary" ]]; then
        cat -- "${a#@}" >> "${NOTIFY_STUB_BODY:?}"
    fi
    prev="$a"
done
printf '%s\n' "$@" >> "${NOTIFY_STUB_ARGS:?}"
exit 0
NOTIFY_STUB
chmod +x "$NOTIFY_DIR/curl"

# notify_run <threshold|"">: run the notifier against the fixture with the
# stub sink; rc and stderr land in NOTIFY_RC / NOTIFY_ERR. PATH is restored
# before returning so the stub curl never leaks into later tiers.
notify_run() {
    local threshold="${1:-}"
    local old_path="$PATH"
    : > "$NOTIFY_BODY"
    : > "$NOTIFY_ARGS"
    export BOX_AUDIT_WEBHOOK_URL="https://fixture.example.com/hook"
    export NOTIFY_STUB_BODY="$NOTIFY_BODY" NOTIFY_STUB_ARGS="$NOTIFY_ARGS"
    export PATH="$NOTIFY_DIR:$old_path"
    if [[ -n "$threshold" ]]; then
        export BOX_AUDIT_NOTIFY_MIN_SEVERITY="$threshold"
    else
        unset BOX_AUDIT_NOTIFY_MIN_SEVERITY
    fi
    NOTIFY_RC=0
    bash "$REPO/scripts/notify-webhook.sh" "$NOTIFY_FIX" 2>"$NOTIFY_ERRF" || NOTIFY_RC=$?
    NOTIFY_ERR="$(cat "$NOTIFY_ERRF")"
    PATH="$old_path"
    unset BOX_AUDIT_WEBHOOK_URL NOTIFY_STUB_BODY NOTIFY_STUB_ARGS BOX_AUDIT_NOTIFY_MIN_SEVERITY
}

# notify_posted_count <severity>: findings of that severity in the posted body.
# notify_posted_total: all findings in the posted body. Empty body -> 0.
notify_posted_count() {
    local sev="$1"
    if [[ -s "$NOTIFY_BODY" ]]; then
        python3 - "$NOTIFY_BODY" "$sev" <<'NOTIFY_PY'
import json, sys
print(sum(1 for f in json.load(open(sys.argv[1])).get("findings", []) if f.get("severity") == sys.argv[2]))
NOTIFY_PY
    else
        echo 0
    fi
}
notify_posted_total() {
    if [[ -s "$NOTIFY_BODY" ]]; then
        python3 - "$NOTIFY_BODY" <<'NOTIFY_PY'
import json, sys
print(len(json.load(open(sys.argv[1])).get("findings", [])))
NOTIFY_PY
    else
        echo 0
    fi
}

# 1. Unset threshold (default): backward-compat — the snapshot is posted
#    byte-identical, the stub got the URL, stderr stays quiet about the filter.
notify_run ""
if [[ "$NOTIFY_RC" -eq 0 ]]; then
    ok "notify-webhook unset threshold exits 0"
else
    fail "notify-webhook unset threshold must exit 0, got $NOTIFY_RC ($NOTIFY_ERR)"
fi
if grep -q "fixture.example.com/hook" "$NOTIFY_ARGS"; then
    ok "notify-webhook unset threshold posts to the webhook URL"
else
    fail "notify-webhook unset threshold did not post to the webhook URL (args: $(cat "$NOTIFY_ARGS"))"
fi
if cmp -s "$NOTIFY_FIX" "$NOTIFY_BODY"; then
    ok "notify-webhook unset threshold posts the snapshot byte-identical"
else
    fail "notify-webhook unset threshold changed the posted payload"
fi
if [[ "$NOTIFY_ERR" == *"suppressed"* ]]; then
    fail "notify-webhook unset threshold leaked a suppression line: $NOTIFY_ERR"
else
    ok "notify-webhook unset threshold is stderr-quiet about the filter"
fi

# 2. warn: info dropped, warn + alert kept, degraded never suppressed,
#    suppressed count on stderr, envelope keys intact.
notify_run "warn"
if [[ "$NOTIFY_RC" -eq 0 ]]; then
    ok "notify-webhook warn threshold exits 0"
else
    fail "notify-webhook warn threshold must exit 0, got $NOTIFY_RC ($NOTIFY_ERR)"
fi
if [[ "$(notify_posted_total)" -eq 3 ]]; then
    ok "notify-webhook warn threshold posts 3 of 4 findings (info suppressed)"
else
    fail "notify-webhook warn threshold posted $(notify_posted_total) findings, want 3"
fi
if [[ "$(notify_posted_count info)" -eq 0 ]]; then
    ok "notify-webhook warn threshold suppresses the info finding"
else
    fail "notify-webhook warn threshold still posted an info finding"
fi
if [[ "$(notify_posted_count degraded)" -eq 1 ]]; then
    ok "notify-webhook warn threshold never suppresses a degraded finding"
else
    fail "notify-webhook warn threshold dropped the degraded finding (blindedness hidden)"
fi
if [[ "$NOTIFY_ERR" == "notify-webhook: suppressed 1 findings below warn threshold" ]]; then
    ok "notify-webhook warn threshold logs the suppressed count to stderr"
else
    fail "notify-webhook warn threshold stderr wrong (want 'suppressed 1 findings below warn threshold', got: $NOTIFY_ERR)"
fi
if python3 - "$NOTIFY_BODY" <<'NOTIFY_PY'
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if all(k in d for k in ("status", "timestamp", "host")) else 1)
NOTIFY_PY
then
    ok "notify-webhook warn threshold keeps the status/timestamp/host envelope"
else
    fail "notify-webhook warn threshold lost envelope keys in the posted body"
fi

# 3. crit: alert only among content severities; degraded still passes.
notify_run "crit"
if [[ "$NOTIFY_RC" -eq 0 ]]; then
    ok "notify-webhook crit threshold exits 0"
else
    fail "notify-webhook crit threshold must exit 0, got $NOTIFY_RC ($NOTIFY_ERR)"
fi
if [[ "$(notify_posted_total)" -eq 2 ]]; then
    ok "notify-webhook crit threshold posts alert + degraded only"
else
    fail "notify-webhook crit threshold posted $(notify_posted_total) findings, want 2 (alert + degraded)"
fi
if [[ "$(notify_posted_count warn)" -eq 0 && "$(notify_posted_count info)" -eq 0 ]]; then
    ok "notify-webhook crit threshold suppresses warn and info"
else
    fail "notify-webhook crit threshold still posted a warn/info finding"
fi
if [[ "$NOTIFY_ERR" == "notify-webhook: suppressed 2 findings below crit threshold" ]]; then
    ok "notify-webhook crit threshold logs the suppressed count to stderr"
else
    fail "notify-webhook crit threshold stderr wrong (want 'suppressed 2 findings below crit threshold', got: $NOTIFY_ERR)"
fi

# 4. Invalid value: fail loudly, non-zero exit, and no POST at all
#    (negative variant — the filter's teeth, per AGENTS.md).
notify_run "foo"
if [[ "$NOTIFY_RC" -ne 0 ]]; then
    ok "notify-webhook invalid threshold exits non-zero"
else
    fail "notify-webhook invalid threshold must exit non-zero, got 0"
fi
if [[ "$NOTIFY_ERR" == *"BOX_AUDIT_NOTIFY_MIN_SEVERITY"* && "$NOTIFY_ERR" == *"info, warn or crit"* ]]; then
    ok "notify-webhook invalid threshold names the variable and allowed values"
else
    fail "notify-webhook invalid threshold stderr unclear (got: $NOTIFY_ERR)"
fi
if [[ ! -s "$NOTIFY_BODY" && ! -s "$NOTIFY_ARGS" ]]; then
    ok "notify-webhook invalid threshold posts nothing"
else
    fail "notify-webhook invalid threshold still POSTed a body"
fi

# 5. Explicit info: the spelled-out no-filter — identical to unset.
notify_run "info"
INFO_LEAK=0
[[ "$NOTIFY_ERR" == *"suppressed"* ]] && INFO_LEAK=1
if [[ "$NOTIFY_RC" -ne 0 ]]; then
    fail "notify-webhook explicit info threshold must exit 0, got $NOTIFY_RC ($NOTIFY_ERR)"
fi
if [[ "$INFO_LEAK" -ne 0 ]]; then
    fail "notify-webhook explicit info threshold leaked a suppression line: $NOTIFY_ERR"
else
    ok "notify-webhook explicit info threshold is the no-filter default"
fi
if cmp -s "$NOTIFY_FIX" "$NOTIFY_BODY"; then
    ok "notify-webhook explicit info threshold posts the snapshot byte-identical"
else
    fail "notify-webhook explicit info threshold changed the posted payload"
fi

rm -rf "$NOTIFY_DIR"

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
