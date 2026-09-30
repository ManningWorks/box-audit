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
#
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

echo
echo "mutation-coverage selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
