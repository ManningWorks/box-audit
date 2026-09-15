#!/bin/bash
# box-audit installer/upgrader — one command for fresh installs and upgrades.
#
#   sudo ./install.sh
#
# Idempotent: re-running only touches files that actually changed (byte-compare
# before writing). An existing box-audit.timer keeps its OnCalendar if the user
# customized it (warned, not silently overwritten).
#
# No flags, no config file, no uninstaller. Needs bash + systemd + apt
# (Ubuntu/Debian). See README.md for the manual fallback.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Single source of truth for the version. install.sh copies it to
# VERSION_MARKER, which `box-audit --version` reads at runtime — the script
# itself carries no copy that can drift. The skill frontmatter version is
# kept in sync by hand: the skill ships separately from the script, and
# install.sh never edits skill files.
VERSION="$(<"$REPO_ROOT/VERSION")"
SCRIPT_SRC="$REPO_ROOT/scripts/box-audit.sh"
SCRIPT_DST="/usr/local/bin/box-audit"
VERSION_MARKER_DIR="/usr/local/share/box-audit"
VERSION_MARKER="$VERSION_MARKER_DIR/version"
SERVICE_UNIT="/etc/systemd/system/box-audit.service"
TIMER_UNIT="/etc/systemd/system/box-audit.timer"
LOG_DIR="/var/log/box-audit"

SERVICE_UNIT_CONTENT='[Unit]
Description=box-audit daily system health + security check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
# truncate:, not file: — file: never truncates, so a shorter JSON document
# following a longer one leaves stale bytes glued to the end and the file
# stops parsing. truncate: cuts on service start.
StandardOutput=truncate:/var/log/box-audit/latest.json
StandardError=journal
ExecStart=/usr/local/bin/box-audit --json
# Sudo is invoked internally by the script for fail2ban/docker checks;
# run as root or grant NOPASSWD to /usr/bin/fail2ban-client, /usr/bin/docker.

[Install]
WantedBy=multi-user.target
'

TIMER_UNIT_CONTENT='[Unit]
Description=Run box-audit daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
'

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

# install_file <src|content-mode> ... — compare-then-write helper.
# Skips the write (and the daemon-reload trigger) when the target is already
# byte-identical, so upgrades only touch what changed. Prints "unchanged",
# "updated", or "installed" accordingly.
install_file() {
    local dst="$1" mode="$2" tmp
    tmp="$(mktemp)"
    printf '%s' "$3" > "$tmp"
    if [[ -f "$dst" ]] && cmp -s "$tmp" "$dst"; then
        rm -f "$tmp"
        say "  unchanged: $dst"
        return 1   # signal: no change
    fi
    install -m "$mode" "$tmp" "$dst"
    rm -f "$tmp"
    say "  updated:   $dst"
    return 0
}

[[ $EUID -eq 0 ]] || die "run with sudo (needs /usr/local/bin, /etc/systemd/system, /var/log)"

[[ -f "$SCRIPT_SRC" ]] || die "source script not found: $SCRIPT_SRC (run from a full repo checkout, or fetch it first)"

# Sanity-check the script BEFORE anything lands on the box: a truncated or
# corrupted download fails here rather than at 9am.
bash -n "$SCRIPT_SRC" || die "source script fails syntax check"
grep -q 'report_security' "$SCRIPT_SRC" || die "sanity check failed: 'report_security' missing from source script"
grep -q -- '--json' "$SCRIPT_SRC" || die "sanity check failed: '--json' missing from source script"

if [[ -f "$SCRIPT_DST" ]]; then
    MODE="Upgrading box-audit v$VERSION"
else
    MODE="Installing box-audit v$VERSION"
fi
say "$MODE"

# 1. Script on PATH. The first run must be root so the file-integrity baseline
#    reads all crown-jewel files; we ensure that by running it below via sudo
#    (we are already root here).
if install_file "$SCRIPT_DST" 0755 "$(<"$SCRIPT_SRC")"; then
    SCRIPT_CHANGED=1
else
    SCRIPT_CHANGED=0
fi

# 1b. Version marker — `box-audit --version` reads this at runtime, so it
#     must exist even when the script didn't change (a v0.3 → v0.4 upgrade
#     stamps it the first time). Not a systemd unit, so it doesn't count
#     toward the daemon-reload trigger below.
mkdir -p "$VERSION_MARKER_DIR"
install_file "$VERSION_MARKER" 0644 "$VERSION" || true

say "  running first audit as root (builds the integrity baseline)…"
"$SCRIPT_DST" > /dev/null || true   # exit 1 = findings, which is fine
say "  done. Findings, if any, are the tool working."

# 2. Log dir before the first service run, or the run fails on output.
mkdir -p "$LOG_DIR"

# 3. Units. On upgrades, preserve a customized OnCalendar rather than
#    silently resetting the user's schedule.
TIMER_CHANGED=0
if install_file "$SERVICE_UNIT" 0644 "$SERVICE_UNIT_CONTENT"; then
    TIMER_CHANGED=1
fi

# 3b. Optional push notifier, shipped but not wired in: the default is
#     pull (see README "Getting the report off the box"). Users opt in
#     with a systemd drop-in pointing ExecStartPost at it.
NOTIFY_SRC="$REPO_ROOT/scripts/notify-webhook.sh"
NOTIFY_DST="/usr/local/bin/notify-webhook.sh"
if [[ -f "$NOTIFY_SRC" ]]; then
    if install_file "$NOTIFY_DST" 0755 "$(cat "$NOTIFY_SRC")"; then
        TIMER_CHANGED=1   # any change to installed files warrants a reload
    fi
fi

if [[ -f "$TIMER_UNIT" ]] && ! grep -q '^OnCalendar=daily' "$TIMER_UNIT"; then
    say "  NOTE: existing $TIMER_UNIT has a customized OnCalendar — left untouched."
    grep '^OnCalendar=' "$TIMER_UNIT" | sed 's/^/    /'
    say "  (delete the line or the file to return to the default daily schedule)"
else
    if install_file "$TIMER_UNIT" 0644 "$TIMER_UNIT_CONTENT"; then
        TIMER_CHANGED=1
    fi
fi

# 4. Reload + enable only when something actually changed, so re-runs don't
#    spam the journal or reset the timer's persistent bookkeeping for nothing.
if [[ $SCRIPT_CHANGED -eq 1 || $TIMER_CHANGED -eq 1 ]]; then
    systemctl daemon-reload
    systemctl enable --now box-audit.timer >/dev/null 2>&1 || systemctl enable box-audit.timer >/dev/null
fi

# 5. Verify gate — no pass, no "done". A timer failing silently every morning
#    hands the user false peace of mind, the opposite of what an audit is for.
say "verify gate:"
systemctl start box-audit.service
RESULT="$(systemctl show box-audit.service -p Result --value)"
STATUS="$(systemctl show box-audit.service -p ExecMainStatus --value)"
[[ "$RESULT" == "success" && "$STATUS" == "0" ]] \
    || die "service run failed: Result=$RESULT ExecMainStatus=$STATUS (see journalctl -u box-audit)"

GATE_JSON="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["status"], len(d["findings"]))' "$LOG_DIR/latest.json")" \
    || die "latest.json does not parse — service ran but output is corrupt"
read -r FINDING_STATUS FINDING_COUNT <<<"$GATE_JSON"
systemctl is-active --quiet box-audit.timer || die "timer is not active"
NEXT_RUN="$(systemctl show box-audit.timer -p NextElapseUSecRealtime --value)"

say "  service:   Result=success ExecMainStatus=0"
say "  snapshot:  $LOG_DIR/latest.json — status=$FINDING_STATUS, $FINDING_COUNT finding(s)"
say "  timer:     active, next run $NEXT_RUN"
say "box-audit v$VERSION $([[ -f $SCRIPT_DST ]] && echo ready — report at $LOG_DIR/latest.json)"
