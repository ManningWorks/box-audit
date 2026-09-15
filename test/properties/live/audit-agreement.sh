#!/usr/bin/env bash
# Live-agreement property suite (OPT-IN — not run by run.sh).
#
# This is the test shape the property spec actually wants: invoke the
# script with --json and assert its findings agree with independently
# sampled ground truth from the same box. It is opt-in because one full
# `--json` run costs ~7s on a box with broad NOPASSWD sudo (apt-get
# cache priming, needrestart, SUID find), which would blow the 5-second
# budget run.sh enforces. T03's seeded container should promote this
# file to a fixture-driven suite member.
#
# Run manually on a box you are allowed to audit:
#   bash test/properties/live/audit-agreement.sh
#
# Agreement model, per family: sample the same input the check reads
# (same user, same lens), apply the documented threshold independently,
# and require the JSON findings to agree exactly. Where the check reads
# a lens the sampler cannot replicate (root-only), the test asserts the
# documented degraded behavior instead of guessing.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/assert.sh"

echo "live: running one full --json audit (this can take ~7s on a sudo-granted box)…"

# --- Ground truth: one sample of every check's input lens ------------------
GT_DISK_PCT="$(df / --output=pcent -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -1 | tr -d ' %')"
GT_DISK_PCT="${GT_DISK_PCT:-0}"
GT_SWAP_PCT="$(free 2>/dev/null | awk '/Swap:/ {if ($2 > 0) printf "%.0f", $3/$2*100; else print "0"}')"
GT_SWAP_PCT="${GT_SWAP_PCT:-0}"
GT_LOAD="$(awk '{print $1}' /proc/loadavg 2>/dev/null)"
GT_SSH_FAILS="$(journalctl --since "24 hours ago" --facility=auth --no-pager 2>/dev/null | grep -ciE 'Failed password|Invalid user')"
GT_LISTEN_PORTS="$(ss -tln 2>/dev/null | awk 'NR>1 {print $4}' | grep -oP ':\K\d+$' | sort -u | tr '\n' ' ')"
GT_LISTEN_PORTS="${GT_LISTEN_PORTS% }"
GT_FAILED_UNITS="$(systemctl list-units --type=service --state=failed --no-legend --plain --no-pager 2>/dev/null | grep -c .)"
GT_FAILED_UNITS="${GT_FAILED_UNITS:-0}"
GT_UPGRADABLE="$(apt list --upgradable 2>/dev/null | tail -n +2 | grep -c .)"
GT_UPGRADABLE="${GT_UPGRADABLE:-0}"

# --- The audit under test ---------------------------------------------------
assert_exit "live --json audit exits 0" '^0$' bash "$SCRIPT" --json
JSON_FILE="$(mktemp)"
trap 'rm -f "$JSON_FILE"' EXIT
printf '%s' "$OUT" > "$JSON_FILE"

# findings_json <python-expr over finding f> — run f-expr over every
# finding, print matching ones.
findings_json() {
    BA_JSON_FILE="$JSON_FILE" python3 -c '
import json, os, sys
d = json.load(open(os.environ["BA_JSON_FILE"]))
for f in d.get("findings", []):
    line = eval(sys.argv[1], {"f": f})
    if line:
        print(line)
' "$1"
}

# --- resources.disk_high: warn iff root fs > 85% ----------------------------
EXPECTED_DISK=$(( GT_DISK_PCT > 85 ? 1 : 0 ))
ACTUAL_DISK="$(findings_json 'f["check_id"] == "resources.disk_high"' | wc -l | tr -d ' ')"
assert_eq "disk_high finding count agrees with ground truth (pct=$GT_DISK_PCT)" "$EXPECTED_DISK" "$ACTUAL_DISK"

# --- resources.swap_high: warn iff swap > 70% --------------------------------
EXPECTED_SWAP=$(( GT_SWAP_PCT > 70 ? 1 : 0 ))
ACTUAL_SWAP="$(findings_json 'f["check_id"] == "resources.swap_high"' | wc -l | tr -d ' ')"
assert_eq "swap_high finding count agrees with ground truth (pct=$GT_SWAP_PCT)" "$EXPECTED_SWAP" "$ACTUAL_SWAP"

# --- resources.load_high: warn iff 1-min load > 3.0 --------------------------
# awk exits 0 when above threshold; translate rc → expected finding count.
if awk -v l="$GT_LOAD" 'BEGIN { exit !(l > 3.0) }'; then
    EXPECTED_LOAD=1
else
    EXPECTED_LOAD=0
fi
ACTUAL_LOAD="$(findings_json 'f["check_id"] == "resources.load_high"' | wc -l | tr -d ' ')"
assert_eq "load_high finding count agrees with ground truth (load=$GT_LOAD)" "$EXPECTED_LOAD" "$ACTUAL_LOAD"

# --- security.ssh_fails: warn iff 24h count > 15 -----------------------------
EXPECTED_SSH=$(( GT_SSH_FAILS > 15 ? 1 : 0 ))
ACTUAL_SSH="$(findings_json 'f["check_id"] == "security.ssh_fails"' | wc -l | tr -d ' ')"
assert_eq "ssh_fails finding count agrees with ground truth (count=$GT_SSH_FAILS)" "$EXPECTED_SSH" "$ACTUAL_SSH"

# --- security.new_port: every allowlisted gap is flagged, nothing else -------
# Default allowlist applies when /var/lib/box-audit/ports-allowlist.txt is
# unreadable (non-root): the script's own fallback.
ALLOWED="22 53 80 443 631"
UNEXPECTED="$(for p in $GT_LISTEN_PORTS; do
    grep -qw "$p" <<< "$ALLOWED" || echo "$p"
done | tr '\n' ' ')"
UNEXPECTED="${UNEXPECTED% }"
# Port = first whitespace token of the message ("9999 is open (not in baseline)").
ACTUAL_PORTS="$(findings_json 'f["message"].split()[0] if f["check_id"] == "security.new_port" else ""' | sort -u | tr '\n' ' ')"
ACTUAL_PORTS="${ACTUAL_PORTS% }"
assert_eq "new_port findings agree with listening-not-allowlisted set" "$UNEXPECTED" "$ACTUAL_PORTS"

# --- system.failed_units: warn iff count > 0 ---------------------------------
EXPECTED_FAILED=$(( GT_FAILED_UNITS > 0 ? 1 : 0 ))
ACTUAL_FAILED="$(findings_json 'f["check_id"] == "system.failed_units"' | wc -l | tr -d ' ')"
assert_eq "failed_units finding count agrees with ground truth (count=$GT_FAILED_UNITS)" "$EXPECTED_FAILED" "$ACTUAL_FAILED"

# --- updates.upgradable: info-severity finding iff count > 20 ----------------
EXPECTED_UPG=$(( GT_UPGRADABLE > 20 ? 1 : 0 ))
ACTUAL_UPG="$(findings_json 'f["check_id"] == "updates.upgradable"' | wc -l | tr -d ' ')"
assert_eq "upgradable finding count agrees with ground truth (count=$GT_UPGRADABLE)" "$EXPECTED_UPG" "$ACTUAL_UPG"

# Severity class: upgradable is info (routine), never warn.
UPG_SEV="$(findings_json 'f["check_id"] == "updates.upgradable" and f["severity"] != "info"' | wc -l | tr -d ' ')"
assert_eq "upgradable findings are always info severity" "0" "$UPG_SEV"

# --- maintenance.apt_cache_stale: warn iff stamp > 48h old or missing --------
STAMP=/var/lib/apt/periodic/update-success-stamp
if [[ -f "$STAMP" ]]; then
    STAMP_AGE=$(( $(date +%s) - $(stat -c %Y "$STAMP") ))
    EXPECTED_STALE=$(( STAMP_AGE > 172800 ? 1 : 0 ))
else
    EXPECTED_STALE=1   # missing stamp is itself the warn case
fi
ACTUAL_STALE="$(findings_json 'f["check_id"] == "maintenance.apt_cache_stale"' | wc -l | tr -d ' ')"
assert_eq "apt_cache_stale finding count agrees with ground truth (expected=$EXPECTED_STALE)" "$EXPECTED_STALE" "$ACTUAL_STALE"

# --- maintenance.timer_drift: warn per drifted/never-fired timer --------------
DRIFTED=0
for t in apt-daily.timer apt-daily-upgrade.timer; do
    LT="$(systemctl show "$t" --property=LastTriggerUSec --value 2>/dev/null)"
    if [[ -z "$LT" || "$LT" == "n/a" ]]; then
        DRIFTED=$((DRIFTED + 1))
    else
        EPOCH="$(date -d "$LT" +%s 2>/dev/null || true)"
        if [[ -n "$EPOCH" ]] && (( $(date +%s) - EPOCH > 104400 )); then
            DRIFTED=$((DRIFTED + 1))
        fi
    fi
done
ACTUAL_DRIFT="$(findings_json 'f["check_id"] == "maintenance.timer_drift"' | wc -l | tr -d ' ')"
assert_eq "timer_drift finding count agrees with ground truth (drifted=$DRIFTED)" "$DRIFTED" "$ACTUAL_DRIFT"

# --- integrity.change: root-only; non-root must degrade loudly, never warn ---
if [[ $EUID -ne 0 ]]; then
    INTEG="$(findings_json 'f["check_id"] == "integrity.change"' | wc -l | tr -d ' ')"
    assert_eq "non-root run emits no integrity.change findings" "0" "$INTEG"
    DEGRADED="$(findings_json 'f["check_id"] == "degraded.check" and "integrity" in f["message"]' | wc -l | tr -d ' ')"
    assert_exit "non-root run flags the integrity check as degraded" '^0$' test "$DEGRADED" -ge 1
else
    MESSAGES="$(findings_json 'f["check_id"] == "integrity.change"' | wc -l | tr -d ' ')"
    echo "note: running as root — integrity.change emitted $MESSAGES finding(s); agreement with the baseline needs the container harness"
fi

props_done "live.audit-agreement"
