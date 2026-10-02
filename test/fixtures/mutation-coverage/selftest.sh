#!/usr/bin/env bash
# Self-test for test/mutation-coverage.sh — the tier-1 negative variant
# for the F6 driver (AGENTS.md: every gate gets one). Runs the driver's
# loop with a STUBBED docker against a scratch git repo, so it proves
# the registry parse, the sed application, the FLIPPED/SURVIVED verdict
# logic, and the error → non-zero exit contract without a container run.
#
# Scenarios:
#   1. FLIPPED  — the scratch tree's stub box-audit.sh emits the finding
#                 for check_id X; the entry's sed renames the emitted
#                 check_id, so the post-mutation audit lacks it →
#                 FLIPPED.
#   2. SURVIVED — the entry's sed targets a line that does not exist in
#                 the stub tree (sed is a no-op there), so the finding
#                 is present in both audits → SURVIVED. (In real runs
#                 this is exactly what a family-A seed mutation does in
#                 a container whose seed the registry cannot control.)
#   3. ERROR    — the stub audit exits non-zero → the driver must exit
#                 non-zero, and the scratch tree must be left clean.
#   4. BAD REGISTRY — a malformed registry line → the driver must exit
#                 non-zero.
#   5. DIRTY TREE — the scratch tree is dirty before the run → the
#                 driver must refuse to start (non-zero) and name the
#                 dirty paths, and must not mutate them.
#   6. KILL MID-RUN (the trap's negative variant) — a slow stub audit
#                 holds the driver inside entry 1's post-sed audit; the
#                 harness SIGTERMs the driver mid-run. Without the
#                 INT/TERM trap the driver would die with entry 1's sed
#                 still applied (the per-entry inline restore never
#                 runs), leaving the scratch tree dirty. The guarantee
#                 under test: after the kill, the tree is byte-identical
#                 to its pre-run state (git status empty + no mutated
#                 marker in the file). This scenario FAILS against a
#                 driver with the trap removed — that is its purpose.

# Exit 0 when every scenario's expectation holds; non-zero otherwise.
set -u

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
DRIVER="$REPO/test/mutation-coverage.sh"
[[ -f "$DRIVER" ]] || { echo "FAIL - driver missing: $DRIVER" >&2; exit 1; }

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); echo "ok   - $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL - $1"; }

make_repo() {
    # $1 = scratch dir. Creates: registry, stub box-audit.sh, seed.sh.
    local s="$1"
    mkdir -p "$s/repo/test/install-docker/seeded" "$s/repo/scripts" "$s/bin"
    git -C "$s/repo" init -q
    cat > "$s/repo/test/mutations.list" <<'L'
security.fail2ban_banned	scripts/box-audit.sh	s|check_id":"security.fail2ban_banned|check_id":"security.fail2ban_bannedX|
system.cron_d_dropins	test/install-docker/seeded/seed.sh	s|^printf .fake-cron-line|: # F6-registry mutation removes the cron.d drop-in|
L
    cat > "$s/repo/scripts/box-audit.sh" <<'B'
#!/usr/bin/env bash
echo '{"findings":[{"check_id":"security.fail2ban_banned","severity":"alert"}]}'
B
    cat > "$s/repo/test/install-docker/seeded/seed.sh" <<'S'
#!/bin/sh
: # no fake-cron-line in this scratch tree (the mutation is a no-op here)
S
    # Stub docker: exec runs the command verbatim (the driver's
    # audit_json runs the stub audit in $PWD in selftest mode).
    cat > "$s/bin/docker" <<'D'
#!/usr/bin/env bash
if [[ "$1" == "exec" ]]; then
    shift 2
    "$@"
fi
exit 0
D
    chmod +x "$s/bin/docker"
    git -C "$s/repo" add -A
    git -C "$s/repo" -c user.email=selftest@example.com -c user.name=selftest commit -qm base
}

# make_slow_repo: a variant of make_repo whose stub audit is fast on the
# FIRST call (the driver's baseline audit) and SLEEPS on every call
# after — so the driver parks itself inside entry 1's post-mutation
# audit with the sed applied and the per-entry inline restore not yet
# run: exactly the state where a signal without the INT/TERM trap would
# leave the scratch tree mutated. The call counter lives in /tmp (NOT in
# the repo — an untracked in-repo file would itself trip the driver's
# dirty-tree refusal, and the kill scenario must start from a clean
# tree). The stub's committed bytes are fixed; the counter path is
# substituted at write time.
make_slow_repo() {
    local s="$1"
    mkdir -p "$s/repo/test/install-docker/seeded" "$s/repo/scripts" "$s/bin"
    SLOW_COUNTER="/tmp/mc-slow-counter-$$-$RANDOM"
    git -C "$s/repo" init -q
    cat > "$s/repo/test/mutations.list" <<'L'
security.fail2ban_banned	scripts/box-audit.sh	s|check_id":"security.fail2ban_banned|check_id":"security.fail2ban_bannedX|
L
    cat > "$s/repo/scripts/box-audit.sh" <<B
#!/usr/bin/env bash
# Stub audit: first call (baseline) is fast; calls 2+ sleep so the
# driver parks inside entry 1's post-mutation audit (the kill window).
n=0
[[ -f "$SLOW_COUNTER" ]] && n=\$(cat "$SLOW_COUNTER")
n=\$((n + 1))
echo \$n > "$SLOW_COUNTER"
if [[ \$n -ge 2 ]]; then
    sleep 5
fi
echo '{"findings":[{"check_id":"security.fail2ban_banned","severity":"alert"}]}'
B
    cat > "$s/repo/test/install-docker/seeded/seed.sh" <<'S'
#!/bin/sh
: # no fake-cron-line in this scratch tree (the mutation is a no-op here)
S
    cat > "$s/bin/docker" <<'D'
#!/usr/bin/env bash
if [[ "$1" == "exec" ]]; then
    shift 2
    "$@"
fi
exit 0
D
    chmod +x "$s/bin/docker"
    git -C "$s/repo" add -A
    git -C "$s/repo" -c user.email=selftest@example.com -c user.name=selftest commit -qm base
}

# --- scenario 1 + 2: FLIPPED and SURVIVED -------------------------------------
S1="$(mktemp -d /tmp/mc-selftest-flip.XXXXXX)"
make_repo "$S1"
OUT1="$(cd "$S1/repo" && PATH="$S1/bin:$PATH" \
    bash "$DRIVER" --selftest --repo "$S1/repo" 2>&1)"
RC1=$?
if [[ $RC1 -eq 0 ]]; then
    ok "selftest run exits 0 (rc=$RC1)"
else
    fail "selftest run rc=$RC1"
fi
if [[ "$OUT1" == *"security.fail2ban_banned FLIPPED"* ]]; then
    ok "renamed-id mutation → FLIPPED"
else
    fail "expected 'security.fail2ban_banned FLIPPED' in output: $(echo "$OUT1" | tail -3)"
fi
if [[ "$OUT1" == *"system.cron_d_dropins SURVIVED"* && "$OUT1" == *"absent-in-baseline"* ]]; then
    ok "no-op mutation with absent baseline → SURVIVED + absent-in-baseline note"
else
    fail "expected 'system.cron_d_dropins SURVIVED' with absent-in-baseline note: $(echo "$OUT1" | tail -3)"
fi
if git -C "$S1/repo" status --porcelain | grep -q .; then
    fail "scratch tree not clean after selftest run: $(git -C "$S1/repo" status --porcelain)"
else
    ok "scratch tree clean after selftest run"
fi
rm -rf "$S1"

# --- scenario 3: entry audit ERROR → driver exits non-zero --------------------
S3="$(mktemp -d /tmp/mc-selftest-err.XXXXXX)"
make_repo "$S3"
cat > "$S3/repo/scripts/box-audit.sh" <<'B'
#!/usr/bin/env bash
echo "boom" >&2
exit 7
B
git -C "$S3/repo" add -A
git -C "$S3/repo" -c user.email=selftest@example.com -c user.name=selftest commit -qm stub-audit-fails
(cd "$S3/repo" && PATH="$S3/bin:$PATH" \
    bash "$DRIVER" --selftest --repo "$S3/repo" >/dev/null 2>&1)
RC3=$?
if [[ $RC3 -ne 0 ]]; then
    ok "stub audit failure → driver exits non-zero (rc=$RC3)"
else
    fail "entry audit error must exit non-zero, got 0"
fi
if git -C "$S3/repo" status --porcelain | grep -q .; then
    fail "scratch tree not clean after errored selftest run: $(git -C "$S3/repo" status --porcelain)"
else
    ok "scratch tree clean after errored selftest run"
fi
rm -rf "$S3"

# --- scenario 4: malformed registry line → non-zero ----------------------------
S4="$(mktemp -d /tmp/mc-selftest-bad.XXXXXX)"
make_repo "$S4"
printf 'only.two\tfields\n' >> "$S4/repo/test/mutations.list"
git -C "$S4/repo" add -A
git -C "$S4/repo" -c user.email=selftest@example.com -c user.name=selftest commit -qm bad-line
(cd "$S4/repo" && PATH="$S4/bin:$PATH" \
    bash "$DRIVER" --selftest --repo "$S4/repo" >/dev/null 2>&1)
RC4=$?
if [[ $RC4 -ne 0 ]]; then
    ok "malformed registry line → driver exits non-zero (rc=$RC4)"
else
    fail "malformed registry line must exit non-zero, got 0"
fi
rm -rf "$S4"

# --- scenario 5: dirty working tree → driver refuses, names the paths --------
# The refusal runs BEFORE any mutation, so the dirty path must be left
# untouched and named on stderr — a pre-existing mess is never blamed on
# the driver (F6-safety guarantee 2).
S5="$(mktemp -d /tmp/mc-selftest-dirty.XXXXXX)"
make_repo "$S5"
echo "not the driver's to touch" > "$S5/repo/scratch-dirty.txt"
OUT5="$(cd "$S5/repo" && PATH="$S5/bin:$PATH" \
    bash "$DRIVER" --selftest --repo "$S5/repo" 2>&1)"
RC5=$?
if [[ $RC5 -ne 0 ]]; then
    ok "dirty working tree → driver refuses to start (rc=$RC5)"
else
    fail "dirty working tree must refuse with non-zero, got 0"
fi
if [[ "$OUT5" == *"scratch-dirty.txt"* ]]; then
    ok "dirty-tree refusal names the dirty path on stderr"
else
    fail "dirty-tree refusal did not name the dirty path: $(echo "$OUT5" | tail -3)"
fi
if [[ -f "$S5/repo/scratch-dirty.txt" && "$(cat "$S5/repo/scratch-dirty.txt")" == "not the driver's to touch" ]]; then
    ok "dirty-tree refusal leaves the pre-existing file untouched"
else
    fail "dirty-tree refusal touched the pre-existing file"
fi
rm -rf "$S5"

# --- scenario 6: SIGTERM mid-run → trap restores the tree (the teeth) --------
# The slow stub audit holds the driver inside entry 1's post-mutation
# audit (sed applied, per-entry inline restore not yet run) — the exact
# state where a driver WITHOUT the INT/TERM trap dies with the scratch
# tree still mutated. The harness polls for the mutation marker in the
# file (proving the sed has landed), SIGTERMs the driver, then asserts
# the tree is byte-identical to its pre-run state: git status empty AND
# the file restored to its committed bytes. This scenario is RED against
# a trap-less driver (inverted once locally, not committed).
S6="$(mktemp -d /tmp/mc-selftest-kill.XXXXXX)"
make_slow_repo "$S6"   # stub audits sleep from call 2 onward (the /tmp counter)
PRE_BYTES="$(git -C "$S6/repo" show HEAD:scripts/box-audit.sh)"
(
    cd "$S6/repo" || exit 1
    PATH="$S6/bin:$PATH" bash "$DRIVER" --selftest --repo "$S6/repo"
) &
KILL_PID=$!
# Wait until entry 1's sed has landed in the tree (the driver is inside
# the slow audit with the mutation live and no restore run yet). The
# marker is committed content, so its appearance on disk means the sed
# (not some other write) changed the file.
MUT_SEEN=0
for _ in $(seq 1 300); do
    if grep -q "security.fail2ban_bannedX" "$S6/repo/scripts/box-audit.sh" 2>/dev/null; then
        MUT_SEEN=1
        break
    fi
    sleep 0.1
done
if [[ $MUT_SEEN -ne 1 ]]; then
    kill "$KILL_PID" 2>/dev/null || true
    wait "$KILL_PID" 2>/dev/null || true
    rm -f "$SLOW_COUNTER"
    fail "kill scenario: mutation marker never appeared (window missed)"
else
    kill -TERM "$KILL_PID" 2>/dev/null || true
    wait "$KILL_PID" 2>/dev/null
    KILL_RC=$?
    rm -f "$SLOW_COUNTER"
    if [[ $KILL_RC -eq 143 || $KILL_RC -eq 130 ]]; then
        ok "SIGTERM mid-run → driver exits with the signal code (rc=$KILL_RC)"
    else
        fail "SIGTERM mid-run: expected exit 143 (or 130), got $KILL_RC"
    fi
    if git -C "$S6/repo" status --porcelain | grep -q .; then
        fail "trap missing: tree dirty after killed run: $(git -C "$S6/repo" status --porcelain)"
    else
        ok "tree git-status clean after SIGTERM mid-run"
    fi
    RESTORED_BYTES="$(git -C "$S6/repo" show HEAD:scripts/box-audit.sh)"
    MUT_GONE=1
    grep -q "security.fail2ban_bannedX" "$S6/repo/scripts/box-audit.sh" && MUT_GONE=0
    if [[ "$RESTORED_BYTES" == "$PRE_BYTES" && $MUT_GONE -eq 1 ]]; then
        ok "trap restored the mutated file byte-identical after SIGTERM"
    else
        fail "trap missing: mutated file not restored byte-identical after SIGTERM"
    fi
fi
rm -rf "$S6"

# --- scenario 7: --list — prints the registry, exits 0, never touches docker ---
# --list is the cheap CI dry-run: it must list every registry entry and exit
# WITHOUT booting a container. The stub docker here records its own invocation
# in a marker; if --list ever reached the container loop the marker appears
# and the assertion fails. Run with the stub docker on PATH so a stray docker
# call would be caught.
S7="$(mktemp -d /tmp/mc-selftest-list.XXXXXX)"
make_repo "$S7"
# Replace the plain stub with a marker-recording one.
cat > "$S7/bin/docker" <<D
#!/usr/bin/env bash
: > "$S7/dcalled"
exit 0
D
chmod +x "$S7/bin/docker"
OUT7="$(cd "$S7/repo" && PATH="$S7/bin:$PATH" \
    bash "$DRIVER" --list --repo "$S7/repo" 2>&1)"
RC7=$?
if [[ $RC7 -eq 0 ]]; then
    ok "--list exits 0 (rc=$RC7)"
else
    fail "--list rc=$RC7"
fi
if [[ "$OUT7" == *"security.fail2ban_banned"* && "$OUT7" == *"system.cron_d_dropins"* ]]; then
    ok "--list prints every registry check_id"
else
    fail "--list missing registry check_ids: $(echo "$OUT7" | tr '\n' '|')"
fi
if [[ "$OUT7" == *"scripts/box-audit.sh"* && "$OUT7" == *"test/install-docker/seeded/seed.sh"* ]]; then
    ok "--list prints each entry's mutation target"
else
    fail "--list missing mutation targets: $(echo "$OUT7" | tr '\n' '|')"
fi
if [[ "$OUT7" == *"ENTRY "* ]]; then
    fail "--list must not run the entry loop: $(echo "$OUT7" | tr '\n' '|')"
else
    ok "--list does not run the entry loop (no ENTRY lines)"
fi
if [[ -e "$S7/dcalled" ]]; then
    fail "--list invoked docker (a --list dry-run must not)"
else
    ok "--list never invoked docker"
fi
rm -rf "$S7"

# --- scenario 8: --report-fixture mixed (1 FLIPPED + 1 SURVIVED) --------------
# The report renderer is exercised on a fixture result set (no container):
# the per-entry verdict table and the score (flipped/total) must render, and
# the exit code stays 0 regardless of flips (SURVIVED is a signal, not a fail).
S8="$(mktemp -d /tmp/mc-selftest-rpt.XXXXXX)"
mkdir -p "$S8"
{
    printf 'security.fail2ban_banned\tscripts/box-audit.sh\tFLIPPED\n'
    printf 'system.cron_d_dropins\ttest/install-docker/seeded/seed.sh\tSURVIVED\n'
} > "$S8/mixed.tsv"
OUT8="$(bash "$DRIVER" --report-fixture "$S8/mixed.tsv" 2>&1)"
RC8=$?
if [[ $RC8 -eq 0 ]]; then
    ok "--report-fixture mixed exits 0 (rc=$RC8)"
else
    fail "--report-fixture mixed rc=$RC8"
fi
if [[ "$OUT8" == *"security.fail2ban_banned"*"FLIPPED"* && "$OUT8" == *"system.cron_d_dropins"*"SURVIVED"* ]]; then
    ok "--report-fixture renders the per-entry verdict table"
else
    fail "--report-fixture missing verdict table: $(echo "$OUT8" | tr '\n' '|')"
fi
if [[ "$OUT8" == *"total=2"* && "$OUT8" == *"flipped=1"* && "$OUT8" == *"survived=1"* && "$OUT8" == *"score=50.0%"* ]]; then
    ok "--report-fixture mixed score 50.0% (total=2 flipped=1 survived=1)"
else
    fail "--report-fixture mixed score/counts wrong: $(echo "$OUT8" | tr '\n' '|')"
fi
rm -rf "$S8"

# --- scenario 9: --report-fixture survived-only + 0-entry (the negative set) ---
# A survived-only set is a coverage signal, NOT a failure: the renderer must
# report score 0.0% and exit 0 (no FLIPPED line). The 0-entry set must not
# divide by zero (score n/a) and must exit 0.
S9="$(mktemp -d /tmp/mc-selftest-rpt2.XXXXXX)"
mkdir -p "$S9"
{
    printf 'system.failed_units\tscripts/box-audit.sh\tSURVIVED\n'
    printf 'updates.security_delta\tscripts/box-audit.sh\tSURVIVED\n'
} > "$S9/survived.tsv"
: > "$S9/empty.tsv"
OUT9a="$(bash "$DRIVER" --report-fixture "$S9/survived.tsv" 2>&1)"
RC9a=$?
OUT9b="$(bash "$DRIVER" --report-fixture "$S9/empty.tsv" 2>&1)"
RC9b=$?
if [[ $RC9a -eq 0 && "$OUT9a" == *"flipped=0"* && "$OUT9a" == *"survived=2"* && "$OUT9a" == *"score=0.0%"* ]]; then
    ok "--report-fixture survived-only → score 0.0%, exit 0 (a signal, not a failure)"
else
    fail "--report-fixture survived-only wrong (rc=$RC9a): $(echo "$OUT9a" | tr '\n' '|')"
fi
if [[ "$OUT9a" == *"FLIPPED"* ]]; then
    fail "--report-fixture survived-only must not render a FLIPPED line: $(echo "$OUT9a" | tr '\n' '|')"
else
    ok "--report-fixture survived-only has no FLIPPED line"
fi
if [[ $RC9b -eq 0 && "$OUT9b" == *"total=0"* && "$OUT9b" == *"score=n/a"* ]]; then
    ok "--report-fixture 0-entry → total=0 score=n/a, exit 0 (no divide-by-zero)"
else
    fail "--report-fixture 0-entry wrong (rc=$RC9b): $(echo "$OUT9b" | tr '\n' '|')"
fi
rm -rf "$S9"

echo
echo "mutation-coverage selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
