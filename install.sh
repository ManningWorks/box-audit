#!/bin/bash
# box-audit installer/upgrader — one command for fresh installs and upgrades.
#
#   sudo ./install.sh
#
# Idempotent: re-running only touches files that actually changed (byte-compare
# before writing). An existing box-audit.timer keeps its OnCalendar if the user
# customized it (warned, not silently overwritten).
#
# One flag, --ci: for CI runs. Every install step is identical; the only
# difference is that the final status line is also teed to
# /var/log/box-audit/install.log. No config file, no uninstaller. Needs
# bash + systemd + apt (Ubuntu/Debian). See README.md for the manual
# fallback.

set -euo pipefail

# --ci marks a CI run: identical install steps, final status teed to the
# install log. Parsed before anything else so it works under `set -u`.
CI_MODE=0
for arg in "$@"; do
    case "$arg" in
        --ci) CI_MODE=1 ;;
    esac
done

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
# Purpose-built group for non-root users who need to read audit history
# (`box-audit --tail`, `--diff`) without sudo. The box-audit service unit
# runs as root and writes snapshots; the group grants the install-time
# user read access. Integrity baseline stays root-only (0600/0700) because
# it contains /etc/shadow hashes — see report_integrity().
BOXAUDIT_GROUP="boxaudit"

SERVICE_UNIT_CONTENT='[Unit]
Description=box-audit daily system health + security check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# F10 hardening profile — these five directives are ONE inseparable unit,
# not a menu. ProtectSystem=strict read-only-remounts the *shared* /tmp,
# which would silently disable the whole audit (clean exit 0, 0-byte
# latest.json, no error signal); PrivateTmp=yes hands the service a fresh
# *private* writable /tmp that the strict read-only bind-mounts do not
# reach, so it is what rescues strict. The two ReadWritePaths lines are the
# carve-outs strict requires for the persistent log/lib dirs. Apply them
# together, in one change, and never ship strict without a writable /tmp
# (PrivateTmp or a /tmp carve-out) — that coupling is load-bearing. Do not
# add ReadWritePaths=/tmp: provable no-op under PrivateTmp=yes.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/box-audit
ReadWritePaths=/var/lib/box-audit
User=root
# Group=boxaudit + UMask=0037 make every file the service creates
# (latest.json via StandardOutput, history snapshots, sidecar) land as
# root:boxaudit 0640 — readable by the boxaudit group so non-root users
# can run box-audit --tail / --diff without sudo. BOXAUDIT_GROUP and
# scripts/box-audit.sh history_write() own the perms logic.
Group=boxaudit
UMask=0037
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

# Description: warn_stale_group_processes <user> <gid>
#
# Best-effort, warn-only. Linux resolves a process's supplementary group
# list at exec time, so every process <user> started BEFORE the usermod
# keeps its old group list — missing <gid> — until it restarts. That
# stale-group window caused the 2026-09-17 incident: a 9-day-old daemon
# got Permission denied reading group-readable audit artifacts and the
# installer output pointed nowhere. This scan closes that blind spot.
#
# For each pid owned by <user> (pgrep -u, so kernel threads and other
# users are out by construction): if the process is older than
# STALE_PROC_MIN_AGE seconds (default 3600; env-overridable like the
# audit script's LOAD_THRESHOLD-style overrides, so the docker install
# harness can exercise it without waiting an hour) AND its
# /proc/<pid>/status "Groups:" line lacks the new gid, list it — pid,
# age, command. Nothing matching → nothing printed (no empty header).
#
# The gid comparison splits the Groups: value on whitespace and compares
# whole tokens. A regex like [[ "$groups" =~ $gid ]] would substring-
# match gid 142 against 42 and false-positive.
#
# Reads /proc/<pid>/status (the main thread's status file); walking
# task/*/status adds nothing — supplementary groups are per-process.
#
# systemd --user caveat: a process running under the user's user-manager
# (systemd --user) inherits its supplementary groups from the
# user-manager, which started at login. Restarting just the consumer
# process may therefore NOT pick up the new group — a re-login, or
# `systemctl --user daemon-reexec` first, may be needed. Comment-only
# knowledge: the printed warning stays simple and suggests restart /
# re-login.
#
# Best-effort contract: missing pgrep/stat, unreadable /proc entries,
# vanished pids — all skipped silently. Always returns 0; the scan can
# never fail the install.
warn_stale_group_processes() {
    local user="$1" gid="$2"
    [[ -n "$gid" ]] || return 0   # unresolvable gid → scan nothing rather than flag everything
    local min_age="${STALE_PROC_MIN_AGE:-3600}"
    # Non-numeric override would trip set -u arithmetic and kill the
    # install — sanitize back to the default instead.
    [[ "$min_age" =~ ^[0-9]+$ ]] || min_age=3600
    command -v pgrep >/dev/null 2>&1 || return 0
    command -v stat   >/dev/null 2>&1 || return 0
    [[ -d /proc ]] || return 0

    local now pid groups_line groups g has_gid age_secs line
    now="$(date +%s)"
    local stale=()
    for pid in $(pgrep -u "$user" 2>/dev/null); do
        # Groups: line of the main thread's status file. Command failure
        # (vanished pid, /proc race) → skip; a *missing* Groups: line is
        # exotic-kernel territory → skip too. An EMPTY group list is NOT
        # a skip: a process with no supplementary groups genuinely lacks
        # the new gid (usermod -aG adds it as supplementary) and belongs
        # in the warning — daemons commonly run this way (e.g. pid 1).
        groups_line="$(awk '/^Groups:/{ print; exit }' "/proc/$pid/status" 2>/dev/null)" || continue
        [[ -n "$groups_line" ]] || continue
        groups="${groups_line#Groups:}"
        has_gid=0
        for g in $groups; do
            [[ "$g" == "$gid" ]] && { has_gid=1; break; }
        done
        (( has_gid )) && continue
        # Age from the mtime of /proc/<pid> (kernel pokes it at start).
        age_secs=$(( now - $(stat -c %Y "/proc/$pid" 2>/dev/null || echo "$now") ))
        (( age_secs < min_age )) && continue
        # Command from the status file's Name: line — /proc/<pid>/cmdline
        # is NUL-separated and awkward in pure bash, and Name: is what
        # ps shows for kernels threads anyway.
        line="$(awk '/^Name:/{ $1=""; sub(/^ /, ""); print; exit }' "/proc/$pid/status" 2>/dev/null)" || continue
        stale+=("$(printf '   pid %s (%s) — %s' "$pid" "$(humanize_age "$age_secs")" "$line")")
    done
    (( ${#stale[@]} > 0 )) || return 0
    say "⚠ ${#stale[@]} long-running process(es) owned by $user won't see the new group until restarted:"
    local s
    for s in "${stale[@]}"; do say "$s"; done
    say "   (restart these, or log out and back in, before expecting $BOXAUDIT_GROUP group access)"
    return 0
}

# humanize_age <seconds> — "9d", "5h", "3m" style for the warning lines.
humanize_age() {
    local secs="$1"
    if (( secs >= 86400 )); then
        printf '%dd' $(( secs / 86400 ))
    elif (( secs >= 3600 )); then
        printf '%dh' $(( secs / 3600 ))
    else
        printf '%dm' $(( secs / 60 ))
    fi
}

# Description: ensure_boxaudit_group
#
# Idempotent. Creates the BOXAUDIT_GROUP if it doesn't exist
# (--system, so it's not in /etc/gshadow but does show up in
# getent). Adds the invoking user ($SUDO_USER) so they can read
# history without sudo. Silent skip when:
#   - group already exists and SUDO_USER is already a member (re-run);
#   - $SUDO_USER is unset (running directly as root, no invoking user
#     to add — e.g. the CI image build path).
#
# Hard-fail (die) when groupadd fails: the systemd unit references
# Group=boxaudit, so a missing group would make the verify gate fail
# with a misleading systemctl error. Better to surface the real cause
# here.
ensure_boxaudit_group() {
    if ! getent group "$BOXAUDIT_GROUP" >/dev/null; then
        if ! groupadd --system "$BOXAUDIT_GROUP" 2>/dev/null; then
            die "could not create $BOXAUDIT_GROUP group (shadow-utils missing or insufficient privileges). Install requires groupadd to provision the read-access group; the systemd unit references Group=$BOXAUDIT_GROUP and will not start without it."
        fi
        say "  created:  $BOXAUDIT_GROUP group"
    fi
    if [[ -n "${SUDO_USER:-}" ]] && id "$SUDO_USER" >/dev/null 2>&1; then
        if id -nG "$SUDO_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$BOXAUDIT_GROUP"; then
            say "  unchanged: $SUDO_USER is in $BOXAUDIT_GROUP"
        else
            if usermod -aG "$BOXAUDIT_GROUP" "$SUDO_USER" 2>/dev/null; then
                say "  added:    $SUDO_USER to $BOXAUDIT_GROUP"
                say "            (log out and back in, or run \`newgrp $BOXAUDIT_GROUP\`, before using --tail/--diff from this session)"
                # Warn-only scan of the user's pre-usermod processes —
                # see warn_stale_group_processes above for why and how.
                warn_stale_group_processes "$SUDO_USER" "$(getent group "$BOXAUDIT_GROUP" | cut -d: -f3)"
            else
                die "could not add $SUDO_USER to $BOXAUDIT_GROUP. Run 'sudo usermod -aG $BOXAUDIT_GROUP $SUDO_USER' manually, then re-run install.sh."
            fi
        fi
    fi
}

# Description: grant_boxaudit_read_perms
#
# Idempotent. Sets /var/log/box-audit/ and /var/log/box-audit/history/
# to root:$BOXAUDIT_GROUP 0750 and tightens existing files (snapshots,
# latest.json, install.log, sidecar) to 0640 root:$BOXAUDIT_GROUP.
# Safe to re-run: chown + chmod are no-ops when perms already match.
#
# LOG_DIR mode 0750 is set explicitly because mkdir -p inherits the
# process umask (typically 0022 → 0755), which leaves the boxaudit
# group as 'other' (r-x) but doesn't establish the dir as
# intentionally group-gated. 0750 makes the contract visible: only
# root and the boxaudit group can traverse.
grant_boxaudit_read_perms() {
    [[ -d "$LOG_DIR" ]] || return 0
    chown "root:$BOXAUDIT_GROUP" "$LOG_DIR" "$LOG_DIR/history" 2>/dev/null || true
    chmod 0750 "$LOG_DIR" "$LOG_DIR/history" 2>/dev/null || true
    # Tighten any existing artifacts to 0640 root:$BOXAUDIT_GROUP. The
    # list is small and explicit — expanding it for every new file
    # type keeps the perm model auditable from one place. Files
    # written after this function runs (e.g. latest.json from the
    # verify-gate systemctl start) are handled by the systemd unit's
    # Group=boxaudit + UMask=0037, which lands them at the right perm
    # without any extra wiring.
    local f
    for f in "$LOG_DIR/latest.json" "$LOG_DIR/install.log" \
             "$LOG_DIR/history"/*.json \
             "$LOG_DIR/history"/.latest-counts.json; do
        [[ -f "$f" ]] || continue
        chown "root:$BOXAUDIT_GROUP" "$f" 2>/dev/null || true
        chmod 0640 "$f" 2>/dev/null || true
    done
}

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
    IS_FRESH_INSTALL=0
else
    MODE="Installing box-audit v$VERSION"
    IS_FRESH_INSTALL=1
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

# 1c. Per-box config dir — only on fresh install. On upgrades the user
#     may have customized allowlists, and we don't touch those. The script
#     already creates /var/lib/box-audit/ when it needs an integrity
#     baseline; install.sh pre-creates it here so the helper-config files
#     land in one place either way.
if [[ $IS_FRESH_INSTALL -eq 1 ]]; then
    mkdir -p /var/lib/box-audit
    chmod 0755 /var/lib/box-audit
    # Seed the allowlists only if they're missing. We don't introspect the
    # running box to learn its ports/timers — the defaults below are a
    # common Ubuntu desktop baseline, and `box-audit --init` (run later)
    # replaces these with the box's actual state. The point is to start
    # with values that produce zero false positives on a fresh install.
    if [[ ! -f /var/lib/box-audit/ports-allowlist.txt ]]; then
        printf '%s\n' \
            '# Ports that box-audit will NOT flag as "unexpected open".' \
            '# One port per line. Edit with: sudo box-audit --accept-port <N>' \
            '# Or replace the whole file with: sudo box-audit --init' \
            '22' '53' '80' '443' '631' \
            > /var/lib/box-audit/ports-allowlist.txt
    fi
    if [[ ! -f /var/lib/box-audit/timers-baseline.txt ]]; then
        printf '%s\n' \
            '# Systemd timers that box-audit considers standard on Ubuntu.' \
            '# Add others with: sudo box-audit --accept-timer <name>' \
            '# Or rebuild from current system state: sudo box-audit --init' \
            'anacron.timer' 'apport-autoreport.timer' 'apt-daily.timer' \
            'apt-daily-upgrade.timer' 'dpkg-db-backup.timer' \
            'e2scrub_all.timer' 'fstrim.timer' 'fwupd-refresh.timer' \
            'logrotate.timer' 'man-db.timer' 'motd-news.timer' \
            'snapd.snap-repair.timer' 'sysstat-collect.timer' \
            'sysstat-summary.timer' 'systemd-tmpfiles-clean.timer' \
            'ua-timer.timer' 'update-notifier-download.timer' \
            'update-notifier-motd.timer' \
            > /var/lib/box-audit/timers-baseline.txt
    fi
    if [[ ! -f /var/lib/box-audit/outbound-threshold.conf ]]; then
        printf '%s\n' \
            '# Threshold (single integer) for the OUTBOUND non-LAN IPs check.' \
            '# Set with: sudo box-audit --outbound-threshold <N>' \
            '25' \
            > /var/lib/box-audit/outbound-threshold.conf
    fi
    if [[ ! -f /var/lib/box-audit/cron-d-allowlist.txt ]]; then
        printf '%s\n' \
            '# cron.d entries that box-audit will NOT flag as unexpected.' \
            '# One name per line (the entry filename, no .cron.d/ prefix).' \
            '# Edit with: sudo box-audit --accept-cron-d <name>' \
            '# Or rebuild from current /etc/cron.d/ contents with: sudo box-audit --init' \
            'anacron' 'e2scrub_all' 'sysstat' '0hourly' \
            > /var/lib/box-audit/cron-d-allowlist.txt
    fi
    if [[ ! -f /var/lib/box-audit/suid-threshold.conf ]]; then
        printf '%s\n' \
            '# Threshold (single integer) for the SUID count check.' \
            '# Set with: sudo box-audit --suid-threshold <N>' \
            '30' \
            > /var/lib/box-audit/suid-threshold.conf
    fi
    chmod 0644 /var/lib/box-audit/ports-allowlist.txt \
              /var/lib/box-audit/timers-baseline.txt \
              /var/lib/box-audit/outbound-threshold.conf \
              /var/lib/box-audit/cron-d-allowlist.txt \
              /var/lib/box-audit/suid-threshold.conf
fi

say "  running first audit as root (builds the integrity baseline)…"
"$SCRIPT_DST" > /dev/null || true   # exit 1 = findings, which is fine
say "  done. Findings, if any, are the tool working."

# 2. Log dir before the first service run, or the run fails on output.
mkdir -p "$LOG_DIR"
# History dir for delta-mode / --tail / --diff. Same dir tree, separate
# subdirectory so logrotate configs targeting /var/log/box-audit/ don't
# sweep daily snapshots. The script writes here on every --json run.
mkdir -p "$LOG_DIR/history"

# 2b. Non-root read access for history snapshots. Create the
# `boxaudit` group, add the installing user, and tighten perms on any
# existing artifacts (upgrade path). This is what makes
# `box-audit --tail` / `--diff` work without sudo for the operator
# who installed the tool. The integrity baseline is root-only (0600)
# — see report_integrity() for why.
say "  group setup:"
ensure_boxaudit_group
grant_boxaudit_read_perms

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
if [[ $CI_MODE -eq 1 ]]; then
    say "box-audit v$VERSION $([[ -f $SCRIPT_DST ]] && echo ready — report at $LOG_DIR/latest.json)" | tee -a /var/log/box-audit/install.log
else
    say "box-audit v$VERSION $([[ -f $SCRIPT_DST ]] && echo ready — report at $LOG_DIR/latest.json)"
fi
# Tighten install.log + latest.json perms to match the rest of the
# artifact tree. Both files are written late in the install
# (install.log via tee at the very end, latest.json via the verify
# gate's systemctl start), so the earlier grant_boxaudit_read_perms
# call hasn't seen them yet. The systemd unit's Group=boxaudit +
# UMask=0037 handles future runs; these explicit chowns cover the
# file produced by *this* install invocation.
chown "root:$BOXAUDIT_GROUP" /var/log/box-audit/install.log /var/log/box-audit/latest.json 2>/dev/null || true
chmod 0640 /var/log/box-audit/install.log /var/log/box-audit/latest.json 2>/dev/null || true
