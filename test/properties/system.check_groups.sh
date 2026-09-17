#!/usr/bin/env bash
# system.check_groups — issue #32 stale-group self-diagnosis. The
# --check-groups probe answers two questions read-only: does the invoking
# process's own group list contain the boxaudit gid, and which of the
# user's own long-running processes lack it. SEAM: a real boxaudit group
# and a genuinely stale (pre-usermod) process can't be manufactured on a
# bare CI runner, so BOXAUDIT_GROUP and STALE_PROC_MIN_AGE are pointed at
# controllable values instead (env-overridable by design, same shape as
# install.sh's STALE_PROC_MIN_AGE). Asserted here:
#   1. gid-present branch: BOXAUDIT_GROUP=<gid this process HAS> →
#      "no stale-membership problem", never mentions reexec/stale/timer.
#   2. stale branch: BOXAUDIT_GROUP=<gid absent from the list> → STALE
#      GROUP MEMBERSHIP verdict, prescribes daemon-reexec / re-login,
#      cites the 0640 layout, never says "check the systemd timer".
#   3. token-match: the absent gid is constructed to substring-contain a
#      gid the process does have (the 4-vs-142 bug class PR #33 fixed in
#      the installer); only whole-token comparison stays correct.
#   4. --check-groups exits 0 on BOTH branches — staleness is a finding,
#      not a failure (observe-never-remediate).
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "system.check_groups"; exit 1; }

# The invoking process's real supplementary group list. This is the same
# /proc/self/status surface the probe itself reads, so the test knows
# ground truth without needing root or new groups.
GROUPS_LIST="$(awk '/^Groups:/{ $1=""; sub(/^[[:space:]]*/, ""); print; exit }' /proc/self/status)"
[[ -n "$GROUPS_LIST" ]] || { fail "cannot read /proc/self/status Groups: — CI runner anomaly"; props_done "system.check_groups"; exit 1; }

# HAVE_GID: a gid the probe process definitely carries (first token —
# the main thread's groups start with the effective/real gid set, and
# field $2 is what the probe reads).
HAVE_GID="${GROUPS_LIST%% *}"

# STALE_GID: a gid absent from the list, constructed to substring-contain
# HAVE_GID whenever possible so a substring matcher would false-positive
# "present" and the assertions would catch the regression.
STALE_GID="${HAVE_GID}3"
# $GROUPS_LIST is intentionally unquoted: it is a whitespace-separated
# token list and we want one gid per line (grep -qx needs whole lines).
# shellcheck disable=SC2086
while printf '%s\n' $GROUPS_LIST | grep -qx "$STALE_GID"; do
    STALE_GID="${STALE_GID}3"
done

run_probe() {  # run_probe <group-override> <outfile>
    BOXAUDIT_GROUP="$1" bash "$SCRIPT" --check-groups > "$2" 2>&1
    echo $?
}

# 1. gid-present branch ------------------------------------------------------
PRESENT_OUT="$(mktemp)"
STALE_OUT="$(mktemp)"
trap 'rm -f "$PRESENT_OUT" "$STALE_OUT"' EXIT
present_rc="$(run_probe "$HAVE_GID" "$PRESENT_OUT")"
assert_eq "gid-present probe exits 0 (finding, not failure)" "0" "$present_rc"
assert_grep "gid-present branch reports no stale-membership problem" 'no stale-membership problem' "$PRESENT_OUT"
if grep -qE 'daemon-reexec|STALE GROUP MEMBERSHIP|systemd timer' "$PRESENT_OUT"; then
    fail "gid-present branch must not mention reexec/stale/timer"
else
    ok "gid-present branch names neither reexec, stale, nor the timer"
fi

# 2. stale branch ------------------------------------------------------------
stale_rc="$(run_probe "$STALE_GID" "$STALE_OUT")"
assert_eq "stale probe exits 0 (finding, not failure)" "0" "$stale_rc"
assert_grep "stale branch names STALE GROUP MEMBERSHIP" 'STALE GROUP MEMBERSHIP' "$STALE_OUT"
assert_grep "stale branch prescribes daemon-reexec or re-login" 'daemon-reexec|log out and back in' "$STALE_OUT"
assert_grep "stale branch cites the 0640 root:group layout" '0640' "$STALE_OUT"
if grep -qE 'check the systemd timer' "$STALE_OUT"; then
    fail "stale branch must NOT say 'check the systemd timer'"
else
    ok "stale branch never says 'check the systemd timer'"
fi

# 3. token match -------------------------------------------------------------
if grep -q "gid $HAVE_GID)" "$PRESENT_OUT"; then
    ok "gid $HAVE_GID matched whole-token in the present branch"
else
    fail "gid $HAVE_GID should have matched its own token in the present branch"
fi
if grep -q "$STALE_GID" "$STALE_OUT"; then
    ok "stale gid $STALE_GID reported absent (substring collision with $HAVE_GID did not false-positive)"
else
    fail "stale gid $STALE_GID missing from stale output"
fi

# 4. CLI surface -------------------------------------------------------------
HELP_OUT="$(bash "$SCRIPT" --help)"
if [[ "$HELP_OUT" == *"--check-groups"* ]]; then
    ok "--check-groups documented in --help"
else
    fail "--help does not document --check-groups"
fi

props_done "system.check_groups"
