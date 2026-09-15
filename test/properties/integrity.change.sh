#!/usr/bin/env bash
# integrity.change — warns when a crown-jewel file (INTEGRITY_TARGETS:
# /etc/passwd, sshd_config, sudoers, cron dirs, authorized_keys, ...)
# was added, removed, or changed relative to
# /var/lib/box-audit/integrity-baseline.json (sha256 snapshots).
#
# SEAM: the baseline path is hardcoded under /var/lib, the check is
# root-only (non-root runs emit degraded.check and skip integrity —
# itself a boundary property), and a full --json run costs ~7s on a
# sudo-granted box — see resources.disk_high.sh. T03's seeded container
# will tamper with a real crown jewel. Asserted instead:
#   1. schema contract.
#   2. delta semantics — (a) tampering appearing today surfaces as
#      "+ ADDED"; (b) the check_id being present on BOTH days is still
#      not a delta, even though a DIFFERENT crown jewel changed: the
#      diff is presence-based, so persistent-tamper boxes are not
#      re-noised daily (the text/JSON report carries every instance;
#      only the delta is muted).
#   3. fixture integrity — integrity-baseline.json /
#      integrity-changed.json share one key set, differ in exactly one
#      hash, and all values are 64-char lowercase hex: exactly the
#      baseline → changed boundary the container must reproduce.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

FIX="$REPO_ROOT/test/fixtures"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "integrity.change"; exit 1; }

# 1. schema contract
assert_grep "check_id in --print-schema" '"integrity\.change"' "$BA_PROP_SCHEMA_FILE"

# 2a. delta semantics: tampering appears today.
CORPUS="$(mktemp -d)"
trap 'rm -rf "$CORPUS"' EXIT
: > "$CORPUS/none.jsonl"
printf '%s\n' '{"severity": "warn", "check_id": "integrity.change", "section": "integrity", "message": "changed /etc/ssh/sshd_config"}' > "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/none.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/one.jsonl"
assert_exit "--replay --diff 1 (tamper begins) exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff.out"
assert_grep "new integrity.change surfaces as + ADDED" '^\+ ADDED' "$CORPUS/diff.out"
assert_grep "message names the tampered file" 'changed /etc/ssh/sshd_config' "$CORPUS/diff.out"

# 2b. delta semantics: a different crown jewel changes again tomorrow —
# same check_id on both sides, so still no delta entry.
printf '%s\n' '{"severity": "warn", "check_id": "integrity.change", "section": "integrity", "message": "changed /etc/passwd"}' > "$CORPUS/two.jsonl"
props_write_snapshot "$CORPUS/2026-09-14.json" "$CORPUS/one.jsonl"
props_write_snapshot "$CORPUS/2026-09-15.json" "$CORPUS/two.jsonl"
assert_exit "--replay --diff 1 (different file, same id) exits 0" '^0$' bash "$SCRIPT" --replay "$CORPUS" --diff 1
printf '%s' "$OUT" > "$CORPUS/diff2.out"
CHANGES="$(grep -cE '^\+ ADDED|^- GONE' "$CORPUS/diff2.out")"
assert_eq "same-id different-file is not re-reported as a delta" "0" "$CHANGES"

# 3. fixture integrity: baseline/changed pair is one flipped hash apart.
assert_exit "baseline/changed differ in exactly one hash, all 64-char hex" '^0$' \
    python3 - "$FIX/integrity-baseline.json" "$FIX/integrity-changed.json" <<'PY'
import json, sys
base = json.load(open(sys.argv[1]))
changed = json.load(open(sys.argv[2]))
assert set(base) == set(changed), f"key sets differ: {set(base) ^ set(changed)}"
diff = [k for k in base if base[k] != changed[k]]
assert len(diff) == 1, f"expected exactly one changed hash, got {diff}"
hexes = list(base.values()) + list(changed.values())
assert all(len(h) == 64 and all(c in "0123456789abcdef" for c in h) for h in hexes), "bad sha256 shape"
PY

props_done "integrity.change"
