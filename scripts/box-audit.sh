#!/bin/bash
# System health + security audit for personal Linux boxes.
# Runs as root (typically via the box-audit.service systemd unit).
# Uses /usr/bin/sudo -n for fail2ban-client and docker. Configure sudoers
# to grant NOPASSWD on those commands (e.g.
#   /etc/sudoers.d/box-audit:
#     ALL ALL=(root) NOPASSWD: /usr/bin/fail2ban-client, /usr/bin/docker
# ); the README's "Compatibility" section calls this out.

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Safer defaults: -u (unset var = error), -o pipefail (catch silent pipe failures),
# -o errtrace (ERR trap fires in functions/shell). NOT -e — many of our greps
# legitimately return no matches, and -e would abort the script on those.
set -uo pipefail -o errtrace

# Thresholds
DISK_THRESHOLD=85
SWAP_THRESHOLD=70
LOAD_THRESHOLD=3.0
SSH_FAIL_THRESHOLD=15
SUDO_FAIL_THRESHOLD=100
UPDATE_THRESHOLD=20
APT_CACHE_STALE_SECS=172800   # 48h — flag if apt cache hasn't refreshed
TIMER_DRIFT_SECS=104400       # 26h — flag if apt-daily.timer hasn't fired

# How long any single external command is allowed to run before we give up
# on it and report it as degraded, rather than let cron hang indefinitely.
# --preserve-status means timeout returns the inner command's exit code
# (124 still means "we killed it"), so check logic can rely on real codes.
CMD_TIMEOUT=10
T="/usr/bin/timeout --preserve-status $CMD_TIMEOUT"

# --- File-integrity check (Lynis FINT-43xx analogue) ---------------------
# Daily-delta check on a curated "crown jewels" list: hashes are stored
# in a baseline JSON on first run, and any deviation on subsequent runs
# is reported as a finding. Catches tampering with /etc/passwd, sudoers,
# sshd_config, cron drop-ins, and authorized_keys — the files an attacker
# touches first when establishing persistence.
#
# Files that don't exist (e.g. /etc/hosts.allow) are skipped silently.
# Directories (e.g. /etc/cron.d/) are hashed by concatenating sorted
# sha256 of all their regular files, so additions and removals both
# surface.
#
# Baseline path is under /var/lib so systemd-tmpfiles doesn't sweep it.
# The script runs as root, so /var/lib/box-audit/ is created with mode
# 0755 on first run if it doesn't already exist.
INTEGRITY_BASELINE_DIR="/var/lib/box-audit"
INTEGRITY_BASELINE_FILE="$INTEGRITY_BASELINE_DIR/integrity-baseline.json"
INTEGRITY_TARGETS=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/sudoers"
    "/etc/sudoers.d"
    "/etc/ssh/sshd_config"
    "/etc/cron.d"
    "/etc/cron.daily"
    "/etc/cron.hourly"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/etc/hosts"
    "/etc/hosts.allow"
    "/etc/hosts.deny"
    "/root/.ssh/authorized_keys"
)

# --- CLI flags -----------------------------------------------------------
# --json   : emit machine-readable JSON to stdout (one object with findings[])
#            instead of the human-readable Telegram-formatted text. Use when
#            piping into a webhook / Slack / Discord / Pushover / etc. so the
#            downstream tool can format the message itself.
# --help   : show usage and exit 0.
# --version: print the script version and exit 0. install.sh copies the
#            repo's VERSION file to /usr/local/share/box-audit/version at
#            install time; reading it from there keeps VERSION the single
#            source of truth — the script carries no copy that can drift.
#            "unknown" is the fallback for a checkout that never went
#            through install.sh.
BOX_AUDIT_VERSION="unknown"
if [[ -r /usr/local/share/box-audit/version ]]; then
    _BA_VERSION="$(</usr/local/share/box-audit/version)"
    BOX_AUDIT_VERSION="${_BA_VERSION//[$'\r\n ']/}"
fi
OUTPUT_MODE="text"   # "text" (default) or "json"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_MODE="json"; shift ;;
        --text) OUTPUT_MODE="text"; shift ;;
        -h|--help)
            /usr/bin/cat <<EOF
Usage: $(/usr/bin/basename "$0") [OPTIONS]
                [--init|--accept-port N|--accept-timer NAME|
                 --outbound-threshold N]

  (default)   Human-readable report suitable for Telegram / Discord.
  --json      Machine-readable JSON to stdout, e.g. for webhook delivery.
  --version   Print version ($BOX_AUDIT_VERSION) and exit.

  Manage per-box config under /var/lib/box-audit/ (run as root):
  --init                       Snapshot the current box into the config files
                               (ports listening now, timers active now,
                               outbound threshold = 25).
  --accept-port N              Append port N to ports-allowlist.txt.
  --accept-timer NAME          Append timer NAME to timers-baseline.txt.
  --outbound-threshold N       Write outbound-threshold.conf (single integer).

Exit codes: 0 = all clear (or manage-op success), 1 = findings present,
             2 = bad CLI flag. (--json mode always exits 0; see status field.)
EOF
            exit 0
            ;;
        --version)
                    /usr/bin/echo "box-audit $BOX_AUDIT_VERSION"
                    exit 0
                    ;;
                --init)
                    MANAGE_MODE="init"; shift ;;
                --accept-port)
                    [[ $# -ge 2 ]] || { echo "box-audit: --accept-port requires an integer" >&2; exit 2; }
                    MANAGE_MODE="accept-port"; MANAGE_ARG="$2"; shift 2 ;;
                --accept-timer)
                    [[ $# -ge 2 ]] || { echo "box-audit: --accept-timer requires a name" >&2; exit 2; }
                    MANAGE_MODE="accept-timer"; MANAGE_ARG="$2"; shift 2 ;;
                --outbound-threshold)
                    [[ $# -ge 2 ]] || { echo "box-audit: --outbound-threshold requires an integer" >&2; exit 2; }
                    MANAGE_MODE="outbound-threshold"; MANAGE_ARG="$2"; shift 2 ;;
                *) /usr/bin/echo "Unknown arg: $1 (try --help)" >&2; exit 2 ;;
            esac
        done

        # --- Per-box config lookups -----------------------------------------------
        # /var/lib/box-audit/ holds per-box state: ports-allowlist.txt,
        # timers-baseline.txt, outbound-threshold.conf. The helpers below read
        # them, falling back to small built-in defaults when the file is missing
        # (fresh install before --init ran; or just-installed agent-path clone).
        # Each first-miss per run prints a one-time stderr note telling the user
        # how to populate them.
        CONFIG_DIR="/var/lib/box-audit"
        PORTS_FILE="$CONFIG_DIR/ports-allowlist.txt"
        TIMERS_FILE="$CONFIG_DIR/timers-baseline.txt"
        OUTBOUND_FILE="$CONFIG_DIR/outbound-threshold.conf"
        CONFIG_NOTICE_PRINTED=0
        note_default_used() {
            [[ $CONFIG_NOTICE_PRINTED -eq 0 ]] || return 0
            CONFIG_NOTICE_PRINTED=1
            echo "box-audit: no /var/lib/box-audit config, using built-in defaults — run 'sudo box-audit --init' to learn your box" >&2
        }
        get_ports_allowlist() {
            if [[ -r "$PORTS_FILE" ]]; then
                # One port per non-comment, non-blank line. Trim whitespace.
                /usr/bin/grep -vE '^[[:space:]]*(#|$)' "$PORTS_FILE" 2>/dev/null \
                    | /usr/bin/sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
                    | /usr/bin/tr '\n' ' ' \
                    | /usr/bin/sed -E 's/[[:space:]]+$//'
            else
                note_default_used
                echo "22 53 80 443 631"
            fi
        }
        get_timers_baseline() {
            if [[ -r "$TIMERS_FILE" ]]; then
                /usr/bin/grep -vE '^[[:space:]]*(#|$)' "$TIMERS_FILE" 2>/dev/null \
                    | /usr/bin/sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/\.timer$//'
            else
                note_default_used
                echo "anacron apport-autoreport apt-daily apt-daily-upgrade dpkg-db-backup e2scrub_all fstrim fwupd-refresh logrotate man-db motd-news snapd-snap-repair sysstat-collect sysstat-summary systemd-tmpfiles-clean ua-timer update-notifier-download update-notifier-motd"
            fi
        }
        get_outbound_threshold() {
            if [[ -r "$OUTBOUND_FILE" ]]; then
                local v
                v=$(/usr/bin/grep -vE '^[[:space:]]*(#|$)' "$OUTBOUND_FILE" 2>/dev/null | /usr/bin/head -1 | /usr/bin/tr -d ' \r\n')
                if [[ "$v" =~ ^[1-9][0-9]*$ ]]; then
                    echo "$v"; return 0
                fi
            fi
            note_default_used
            echo "25"
        }
        main_manage() {
            # Validate the argument FIRST so a bad value is reported regardless of
            # EUID; the root check below then becomes a permission gate, not a
            # syntax gate. (Without this, a non-root user invoking e.g.
            # `--accept-port foo` sees "needs root" instead of "invalid integer".)
            case "$MANAGE_MODE" in
                accept-port)
                    if ! [[ "$MANAGE_ARG" =~ ^[0-9]+$ ]] || (( MANAGE_ARG < 1 || MANAGE_ARG > 65535 )); then
                        echo "box-audit: --accept-port requires an integer 1..65535, got '$MANAGE_ARG'" >&2
                        exit 2
                    fi
                    ;;
                accept-timer)
                    if [[ -z "$MANAGE_ARG" || "$MANAGE_ARG" =~ [[:space:]/] ]]; then
                        echo "box-audit: --accept-timer requires a name (no spaces or slashes), got '$MANAGE_ARG'" >&2
                        exit 2
                    fi
                    ;;
                outbound-threshold)
                    if ! [[ "$MANAGE_ARG" =~ ^[1-9][0-9]*$ ]]; then
                        echo "box-audit: --outbound-threshold requires a positive integer, got '$MANAGE_ARG'" >&2
                        exit 2
                    fi
                    ;;
            esac
            [[ $EUID -eq 0 ]] || { echo "box-audit: manage commands require root (sudo)" >&2; exit 1; }
            /usr/bin/mkdir -p "$CONFIG_DIR" || { echo "box-audit: cannot create $CONFIG_DIR" >&2; exit 1; }
            case "$MANAGE_MODE" in
                init)
                    /usr/bin/ss -tlnH 2>/dev/null \
                        | /usr/bin/awk '{print $4}' | /usr/bin/grep -oP ':\K\d+$' \
                        | /usr/bin/sort -un > "$PORTS_FILE"
                    /usr/bin/systemctl list-timers --all --no-pager --no-legend --output json 2>/dev/null \
                        | /usr/bin/python3 -c '
        import sys, json
        for row in json.load(sys.stdin):
            u = row.get("unit", "")
            if u.endswith(".timer"):
                print(u)' > "$TIMERS_FILE"
                    /usr/bin/printf '25\n' > "$OUTBOUND_FILE"
                    echo "box-audit: seeded $PORTS_FILE, $TIMERS_FILE, $OUTBOUND_FILE"
                    ;;
                accept-port)
                    [[ -f "$PORTS_FILE" ]] || /usr/bin/install -D -m 0644 /dev/null "$PORTS_FILE"
                    /usr/bin/grep -qxF "$MANAGE_ARG" "$PORTS_FILE" 2>/dev/null \
                        || /usr/bin/printf '%s\n' "$MANAGE_ARG" >> "$PORTS_FILE"
                    echo "box-audit: added port $MANAGE_ARG to $PORTS_FILE"
                    ;;
                accept-timer)
                    local tname="${MANAGE_ARG%.timer}"
                    [[ -f "$TIMERS_FILE" ]] || /usr/bin/install -D -m 0644 /dev/null "$TIMERS_FILE"
                    /usr/bin/grep -qxF "${tname}.timer" "$TIMERS_FILE" 2>/dev/null \
                        || /usr/bin/printf '%s.timer\n' "$tname" >> "$TIMERS_FILE"
                    echo "box-audit: added timer ${tname}.timer to $TIMERS_FILE"
                    ;;
                outbound-threshold)
                    /usr/bin/printf '%s\n' "$MANAGE_ARG" > "$OUTBOUND_FILE"
                    echo "box-audit: set outbound threshold to $MANAGE_ARG (in $OUTBOUND_FILE)"
                    ;;
                *)
                    echo "box-audit: unknown manage mode '$MANAGE_MODE'" >&2
                    exit 2
                    ;;
            esac
            exit 0
        }
        if [[ -n "${MANAGE_MODE:-}" ]]; then
            main_manage
        fi

        # --- JSON collector -------------------------------------------------------
# Each report_*() function can push findings via json_push <severity> <id> <message>
# In text mode this is a no-op; in json mode it's collected and emitted as
# a single {"findings":[...]} object.
JSON_FINDINGS=""
JSON_COUNT=0

json_push() {
    # $1=severity (info|warn|error|degraded), $2=id (e.g. "disk.high"), $3=message
    local severity="$1" id="$2" msg="$3"
    JSON_COUNT=$((JSON_COUNT + 1))
    # Build the entry by hand to avoid a hard jq/python3 dependency.
    # Strings are escaped for JSON (backslash + double-quote only — the only
    # characters our findings actually contain).
    local safe_msg="${msg//\\/\\\\}"
    safe_msg="${safe_msg//\"/\\\"}"
    local safe_id="${id//\\/\\\\}"
    safe_id="${safe_id//\"/\\\"}"
    local entry="{\"severity\":\"${severity}\",\"id\":\"${safe_id}\",\"message\":\"${safe_msg}\"}"
    if [[ -z "$JSON_FINDINGS" ]]; then
        JSON_FINDINGS="$entry"
    else
        JSON_FINDINGS="${JSON_FINDINGS},${entry}"
    fi
}

# Bind the lock to the script name (stable across bash -c invocations
# where $0 would otherwise be "bash"). Falls back to $0 if BASH_SOURCE
# is unset (e.g. when sourced).
#
# /tmp is the lockfile location: world-writable, no sticky-bit headaches.
# The single-instance concern is only about the same user running the
# script twice — cross-user races are already prevented by the daily
# systemd timer firing on a fixed schedule. A foreign-owned lockfile is
# removed when possible; if the sticky bit blocks that, the guard is
# skipped with a warning rather than failing the run (see below).
LOCK_DIR="/tmp"
LOCK_FILE="$LOCK_DIR/sysadmin-healthcheck-box-audit.lock"
LOCK_ENABLED="yes"
# Track anything that couldn't run properly, so a silent/missing result
# doesn't get reported as "all clear".
#
# Degraded findings are collected in a temp FILE, not a shell variable:
# every report_* function runs inside a command substitution, which is a
# subshell — appending to a global there mutates a copy that's thrown
# away when the substitution returns. A file survives subshell boundaries
# and main() reads it once at assembly time.
DEGRADED_FILE=""
DEGRADED=""
flag_degraded() {
    /usr/bin/printf '%s\n' "$1" >> "$DEGRADED_FILE" 2>/dev/null
}

# --- Single-instance guard -------------------------------------------------
# Prevents an overlapping run (e.g. a slow journalctl on a big journal)
# from stacking up under cron. Skipped if no writable lock dir was found.
#
# Stale-lockfile handling: if the lockfile exists and is owned by a
# different user (e.g. root's systemd run left it behind while an
# interactive user is testing), we try to delete it. If we can't
# (sticky dir + not owner), we skip the lock for this run — the daily
# systemd timer firing on a fixed schedule means cross-user races are
# not a real risk; this guard exists to prevent the same user from
# running two instances.
if [[ "$LOCK_ENABLED" == "yes" ]]; then
    if [[ -f "$LOCK_FILE" ]] && [[ ! -O "$LOCK_FILE" ]]; then
        /usr/bin/rm -f "$LOCK_FILE" 2>/dev/null || true
    fi
    if [[ ! -f "$LOCK_FILE" ]] || [[ -O "$LOCK_FILE" ]]; then
        # We can open it (either freshly creating or overwriting our own).
        exec 200>"$LOCK_FILE"
        if ! /usr/bin/flock -n 200; then
            echo "sysadmin-healthcheck: another instance is already running, exiting" >&2
            exit 0
        fi
    else
        echo "sysadmin-healthcheck: WARNING — lockfile owned by another user, continuing without single-instance guard" >&2
    fi
else
    echo "sysadmin-healthcheck: WARNING — no writable lock dir, skipping single-instance guard" >&2
fi

# --- Dependency / privilege verification ------------------------------------
# If a required binary is missing, or sudo isn't actually usable
# non-interactively, the relevant checks below will silently return empty
# results and look identical to "no issues". Catch that here instead.

# sudo_ok <command-path> — is `sudo -n <this exact command>` usable?
# Probing one sudo command (e.g. fail2ban-client) does NOT prove others
# (docker, apt-get, needrestart) are allowed: scoped sudoers lists each
# command separately. Each check gates on its own command's probe.
# Results are cached — declare the assoc array once at source time.
declare -A SUDO_OK_CACHE
sudo_ok() {
    local cmd="$1"
    if [[ -z "${SUDO_OK_CACHE[$cmd]:-}" ]]; then
        if /usr/bin/sudo -n "$cmd" --version >/dev/null 2>&1 \
           || /usr/bin/sudo -n "$cmd" status >/dev/null 2>&1 \
           || /usr/bin/sudo -n "$cmd" --help >/dev/null 2>&1; then
            SUDO_OK_CACHE[$cmd]=1
        else
            SUDO_OK_CACHE[$cmd]=0
        fi
    fi
    [[ "${SUDO_OK_CACHE[$cmd]}" == "1" ]]
}

check_deps() {
    local bin
    for bin in df free awk ss systemctl journalctl apt find sudo fail2ban-client docker timeout flock stat python3; do
        if ! command -v "$bin" >/dev/null 2>&1; then
            flag_degraded "'$bin' not found on PATH — related checks skipped"
        fi
    done

    if command -v sudo >/dev/null 2>&1; then
        # Probe each sudo command the script actually uses. Under scoped
        # sudoers these succeed/fail independently, so one shared canary
        # would mask per-command gaps (e.g. docker allowed, apt-get not).
        if ! sudo_ok /usr/bin/fail2ban-client; then
            flag_degraded "passwordless sudo for fail2ban-client not working — fail2ban check skipped"
        fi
        if ! sudo_ok /usr/bin/docker; then
            flag_degraded "passwordless sudo for docker not working — container health check skipped"
        fi
    fi

    # needrestart is optional but lets us detect long-running daemons linked
    # against an old libc. If absent, the corresponding check is a no-op.
    if ! command -v needrestart >/dev/null 2>&1; then
        flag_degraded "needrestart not installed — running-with-old-libc check skipped (apt install needrestart)"
    fi
}

report() {
    printf '\n=== SYSTEM HEALTH REPORT - %s ===\n' "$(date '+%Y-%m-%d %H:%M')"
    printf '%b\n' "$1"
}

gc() {
    grep -ciE "$1" 2>/dev/null | tr -d ' \n' || echo "0"
}

report_resources() {
    local disk_pct df_output swap_pct load out=""
    disk_pct=$(df / --output=pcent -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -1 | tr -d ' %')
    disk_pct=${disk_pct:-0}
    df_output=$(df -h / --output=source,size,used,avail,pcent -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -1)
    swap_pct=$(free | awk '/Swap:/ {if($2>0) printf "%.0f", $3/$2*100; else print "0"}')
    swap_pct=${swap_pct:-0}
    load=$(awk '{print $1}' /proc/loadavg)

    [[ $disk_pct -gt $DISK_THRESHOLD ]] && out="$out\n⚠️ DISK: ${df_output} (${disk_pct}% used)"
    [[ $swap_pct -gt $SWAP_THRESHOLD ]] && out="$out\n⚠️ SWAP: ${swap_pct}% used"
    awk -v l="$load" -v thresh="$LOAD_THRESHOLD" 'BEGIN{exit !(l>thresh)}' && out="$out\n⚠️ LOAD: $load (high)"

    [[ $disk_pct -gt $DISK_THRESHOLD ]] && json_push warn disk.high "${df_output} (${disk_pct}% used)"
    [[ $swap_pct -gt $SWAP_THRESHOLD ]] && json_push warn swap.high "${swap_pct}% used"
    awk -v l="$load" -v thresh="$LOAD_THRESHOLD" 'BEGIN{exit !(l>thresh)}' && json_push warn load.high "load ${load} (threshold ${LOAD_THRESHOLD})"

    echo "$out"
}

report_security() {
    local out=""

    # fail2ban banned IPs
    if /usr/bin/sudo -n /usr/bin/fail2ban-client status >/dev/null 2>&1; then
        local currently_banned
        currently_banned=$($T /usr/bin/sudo /usr/bin/fail2ban-client status sshd 2>/dev/null | awk '/Currently banned/ {print $4}' | tr -d ' ')
        local f2b_status=${PIPESTATUS[0]}
        if [[ $f2b_status -ne 0 ]]; then
            flag_degraded "fail2ban-client check failed or timed out (exit $f2b_status)"
        elif [[ -n "$currently_banned" ]] && [[ "$currently_banned" != "0" ]]; then
            out="$out\n🚨 fail2ban: $currently_banned IP(s) banned on sshd"
        fi
    fi

    # SSH failures (last 24h)
    local ssh_fails
    ssh_fails=$($T /usr/bin/journalctl --since "24 hours ago" --facility=auth --no-pager 2>/dev/null | gc "Failed password|Invalid user")
    [[ $ssh_fails -gt $SSH_FAIL_THRESHOLD ]] && out="$out\n⚠️ SSH: $ssh_fails failed auth attempts (24h)"

    # sudo spam threshold (known gateway behavior, flag only if excessive)
    local sudo_fails
    sudo_fails=$($T /usr/bin/journalctl --since "24 hours ago" --facility=auth --priority=err --no-pager 2>/dev/null | gc "sudo.*true")
    [[ $sudo_fails -gt $SUDO_FAIL_THRESHOLD ]] && out="$out\n⚠️ sudo: $sudo_fails auth failures (24h)"

    # Open ports - flag unexpected ones, and who's listening on them
    # 22(SSH) 53(DNS) 631(IPP) 5006(Actual) 5173(Vite) 8384(Syncthing HTTP)
    # 9377(?) 22000(Syncthing BEP) 3000/3001(Next.js) 61271(?) 34042(Tailscale DERP)
    # 8787(Hermes WebUI - hermes-webui/server.py, HERMES_WEBUI_PORT)
    local known_ports
    known_ports="$(get_ports_allowlist)"
    local ss_output
    ss_output=$($T /usr/bin/ss -tlnp 2>/dev/null | grep LISTEN)
    local open_ports
    open_ports=$(echo "$ss_output" | awk '{print $4}' | grep -oP ':\K\d+$' | sort -u | tr '\n' ' ')
    for port in $open_ports; do
        local known=0
        for kp in $known_ports; do
            [[ "$port" == "$kp" ]] && known=1 && break
        done
        if [[ $known -eq 0 ]]; then
            local proc
            proc=$(echo "$ss_output" | grep ":${port} " | grep -oP 'users:\(\("\K[^"]+' | head -1)
            out="$out\n🆕 PORT: $port is open (not in baseline)${proc:+ [$proc]}"
        fi
    done

    # Outbound connection anomaly — established connections to non-RFC1918,
    # non-Tailscale IPs. Catches post-compromise C2 / data exfil from a
    # process that has nothing legitimate to phone home.
    #
    # Allowed "remote" categories:
    #   - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16  (RFC1918 private)
    #   - 100.64.0.0/10                              (Tailscale CGNAT)
    #   - 127.0.0.0/8                                (loopback)
    #   - link-local 169.254.0.0/16                  (DHCP fallback, unlikely outbound)
    #   - IPv6 loopback + ULA fc00::/7 + link-local fe80::/10
    #
    # Anything else gets reported with the remote port so you can decide
    # whether it's legit (e.g. syncthing discovery on 22067, Telegram API).
    # Threshold of 25 to avoid alarm fatigue on a chatty gateway/hermes
    # process that legitimately opens many short-lived HTTPS sockets.
    local outbound_remote_count=0
    local outbound_remote_sample=""
    local ss_out
    ss_out=$($T /usr/bin/ss -tnp state established 2>/dev/null)
    if [[ -n "$ss_out" ]]; then
        # IPv4: column 5 holds remote addr:port.
        local remote_ips
        remote_ips=$(echo "$ss_out" | awk 'NR>1 {print $5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
        # IPv6: same column, but addresses are hex with colons and often a
        # %if suffix ([2001:db8::1]:443 or [fe80::1%eth0]:22). Grab the
        # bracketed address, strip port/brackets/interface. Without this,
        # a compromised process phoning home over IPv6 is invisible to the
        # check on any dual-stack box.
        local remote_ips6
        remote_ips6=$(echo "$ss_out" | awk 'NR>1 {print $5}' \
            | grep -oE '^\[[0-9a-fA-F:]+(%[a-z0-9]+)?\]' \
            | /usr/bin/sed -E 's/^\[//; s/\]$//' | sort -u)
        local suspicious_ips=""
        local ip
        for ip in $remote_ips; do
            # Skip RFC1918 + CGNAT + loopback
            if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] \
               || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] \
               || [[ "$ip" =~ ^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\. ]] \
               || [[ "$ip" =~ ^127\. ]]; then
                continue
            fi
            suspicious_ips="$suspicious_ips $ip"
        done
        for ip in $remote_ips6; do
            # Lowercase for consistent matching, strip zone id (fe80::1%eth0)
            ip="${ip%%%*}"
            ip="${ip,,}"
            # Skip loopback (::1), link-local fe80::/10, ULA fc00::/7,
            # and IPv4-mapped ::ffff:x.x.x.x (already handled above).
            if [[ "$ip" == "::1" ]] \
               || [[ "$ip" =~ ^fe[89ab] ]] \
               || [[ "$ip" =~ ^f[cd] ]] \
               || [[ "$ip" =~ ^::ffff: ]]; then
                continue
            fi
            suspicious_ips="$suspicious_ips $ip"
        done
        outbound_remote_count=$(echo "$suspicious_ips" | /usr/bin/wc -w)
        outbound_remote_count=${outbound_remote_count:-0}
        outbound_remote_sample=$(echo "$suspicious_ips" | /usr/bin/tr ' ' '\n' | /usr/bin/grep -v '^$' | /usr/bin/head -5 | /usr/bin/tr '\n' ',' | /usr/bin/sed 's/,$//')
    fi
    [[ $outbound_remote_count -gt $(get_outbound_threshold) ]] && out="$out\n🌐 OUTBOUND: $outbound_remote_count non-LAN remote IP(s) connected: $outbound_remote_sample"

    # SUID binary count — catches a rootkit that dropped a SUID binary to
    # escalate. Standard Ubuntu desktop has ~18-25 SUID files (passwd,
    # mount, su, sudo, etc.). A real jump means somebody added one.
    # Skip /var/lib/docker: overlay2 layers carry SUID bits from base
    # images (passwd, util-linux, openssh) that don't add to the host's
    # attack surface, and their counts mask real findings (37 → 17 here).
    # `-path '/var/lib/docker' -prune -o` drops the whole tree before the
    # perm filter runs.
    local suid_count
    suid_count=$($T /usr/bin/find / -xdev -path '/var/lib/docker' -prune -o -perm -4000 -type f -print 2>/dev/null | /usr/bin/wc -l)
    suid_count=${suid_count:-0}
    # Baseline 18 measured 2026-09-14 on this box; flag if > 30 (50%+ growth).
    [[ $suid_count -gt 30 ]] && out="$out\n🔓 SUID: $suid_count SUID binaries on disk (baseline ~18-25) — review for unauthorised additions"

    echo "$out"
}

report_system() {
    local out=""

    # Failed systemd units
    local failed_list failed_units
    failed_list=$($T /usr/bin/systemctl list-units --type=service --state=failed --no-legend --plain --no-pager 2>/dev/null)
    failed_units=$(echo "$failed_list" | grep -c . | tr -d ' \n')
    failed_units=${failed_units:-0}
    [[ $failed_units -gt 0 ]] && {
        local units
        units=$(echo "$failed_list" | awk '{print $1}' | head -5 | tr '\n' ' ')
        out="$out\n🔴 SYSTEMD: $failed_units failed service(s): $units"
    }

    # Persistence check — non-standard systemd timers + user crontabs.
    # Catches an attacker adding a cron job or timer to re-establish access
    # Anything outside that gets flagged with its name. The list itself
        # is per-box (see /var/lib/box-audit/timers-baseline.txt) so this
        # audit learns what's "standard" on *this* box instead of carrying
        # a hardcoded Ubuntu Desktop list everywhere.
        #
        # Use JSON output and jq so we extract the actual `unit` field rather
        # than miscounting the human-readable columns (which include the
        # activates-target .service on the same line).
        local timer_list custom_timers timer_name
        timer_list=$($T /usr/bin/systemctl list-timers --all --no-pager --no-legend --output json 2>/dev/null \
            | /usr/bin/python3 -c "import sys,json
    data = json.load(sys.stdin)
    for row in data:
        u = row.get('unit','')
        if u.endswith('.timer'):
            print(u)" 2>/dev/null)
        # Build the per-box allowlist as a pipe-separated regex pattern. The
            # baseline is one name per line, no .timer suffix; systemd reports
            # the .timer suffix; the regex below optionally matches the suffix.
            # Empty pattern means nothing matches (every timer is "custom") which
            # is the right fresh-install behaviour: alert on everything until
            # --init runs.
            local timer_baseline
            timer_baseline="$(get_timers_baseline)"
            local timer_pat=""
            if [[ -n "$timer_baseline" ]]; then
                # join names with '|'
                timer_pat="$(printf '%s' "$timer_baseline" | /usr/bin/tr '\n' '|')"
                # trim trailing '|' from the join
                timer_pat="${timer_pat%%|}"
            fi
        custom_timers=""
        while IFS= read -r timer_name; do
            [[ -z "$timer_name" ]] && continue
            # box-audit.timer (or any name the script is installed under) is
            # this very audit — flagging it would self-report on every run.
            [[ "$timer_name" == *"box-audit"* || "$timer_name" == *"healthcheck"* ]] && continue
            if [[ -n "$timer_pat" ]]; then
                # Extended regex alternation. get_timers_baseline returns
                # names without the .timer suffix; systemd reports them
                # with the suffix. Match either form.
                if [[ "$timer_name" =~ ^($timer_pat)(\.timer)?$ ]]; then
                    :   # standard, ignore
                else
                    custom_timers="$custom_timers $timer_name"
                fi
            else
                custom_timers="$custom_timers $timer_name"
            fi
        done <<< "$timer_list"
    local custom_count
    custom_count=$(echo "$custom_timers" | /usr/bin/wc -w)
    custom_count=${custom_count:-0}
    [[ $custom_count -gt 0 ]] && {
        out="$out\n⏰ CUSTOM-TIMERS: $custom_count non-standard timer(s): $(echo "$custom_timers" | /usr/bin/tr ' ' '\n' | /usr/bin/grep -v '^$' | /usr/bin/head -3 | /usr/bin/tr '\n' ',' | /usr/bin/sed 's/,$//')"
    }

    # User crontab — flag if a non-empty user crontab exists. (You schedule
    # via Hermes cron, not system cron, so anything here is suspicious.)
    # `crontab -l` with no crontab prints "no crontab for <user>" to stdout,
    # which a naive grep counts as 1 line. Filter that out first.
    local user_cron_raw user_cron_entries
    user_cron_raw=$($T /usr/bin/crontab -l 2>/dev/null | /usr/bin/grep -vE '^no crontab for ')
    user_cron_entries=$(echo "$user_cron_raw" | /usr/bin/grep -cvE '^[[:space:]]*(#|$)')
    user_cron_entries=${user_cron_entries:-0}
    [[ $user_cron_entries -gt 0 ]] && out="$out\n📅 USER-CRON: $user_cron_entries entry/entries in $USER's crontab (Hermes schedules via its own cron — investigate)"

    # /etc/cron.d/ — flag unknown drop-ins beyond the standard 3.
    local cron_d_files
    cron_d_files=$($T /usr/bin/ls /etc/cron.d/ 2>/dev/null | /usr/bin/sort -u)
    local unexpected_cron=""
    local f
    for f in $cron_d_files; do
        case "$f" in
            anacron|e2scrub_all|sysstat|0hourly) ;;  # standard
            *) unexpected_cron="$unexpected_cron $f" ;;
        esac
    done
    local ucron_count
    ucron_count=$(echo "$unexpected_cron" | /usr/bin/wc -w)
    ucron_count=${ucron_count:-0}
    [[ $ucron_count -gt 0 ]] && out="$out\n📅 /etc/cron.d/: unexpected drop-in(s): $(echo "$unexpected_cron" | /usr/bin/tr ' ' '\n' | /usr/bin/grep -v '^$' | /usr/bin/tr '\n' ',' | /usr/bin/sed 's/,$//')"

    # Docker containers - use Docker's own health filter (containers with no
    # HEALTHCHECK defined are correctly ignored, not false-flagged)
    if sudo_ok /usr/bin/docker; then
        local unhealthy unhealthy_names
        unhealthy_names=$($T /usr/bin/sudo /usr/bin/docker ps --filter health=unhealthy --format '{{.Names}}' 2>/dev/null)
        unhealthy=$(echo "$unhealthy_names" | grep -c . | tr -d ' \n')
        unhealthy=${unhealthy:-0}
        [[ $unhealthy -gt 0 ]] && out="$out\n🔴 DOCKER: $unhealthy unhealthy container(s): $(echo "$unhealthy_names" | tr '\n' ' ')"
    fi

    # Apport crashes
    local crash_count
    crash_count=$(find /var/crash -maxdepth 1 -type f 2>/dev/null | wc -l)
    crash_count=${crash_count:-0}
    [[ $crash_count -gt 0 ]] && {
        local crash_files
        crash_files=$(find /var/crash -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | head -3 | tr '\n' ' ')
        out="$out\n💥 CORES: $crash_count crash dump(s): $crash_files"
    }

    # Kernel errors
    local kerr
    kerr=$($T /usr/bin/journalctl --since "24 hours ago" --priority=err --kernel --no-pager 2>/dev/null | grep -c "" | tr -d ' \n' || echo "0")
    kerr=${kerr:-0}
    [[ $kerr -gt 0 ]] && out="$out\n🔴 KERNEL: $kerr error(s) in last 24h"

    echo "$out"
}

report_updates() {
    local out=""
    local updatable security kernel_security distro third_party

    # Force a cache refresh before reading `apt list --upgradable`.
    # Yesterday's incident: cache went stale, unattended-upgrades ran but
    # saw an empty queue, our cron reported "0 security" while 28 were
    # actually pending. This protects against that class of bug.
    # Wrapped in -n sudo with a 30s budget so a slow mirror doesn't hang cron.
    # Gated on its own probe: sudoers allowing fail2ban-client says nothing
    # about apt-get. The failure message names WHY — a timeout (exit 124)
    # means a slow mirror and the counts are still usable; anything else
    # means apt itself errored and the counts may be badly stale.
    if sudo_ok /usr/bin/apt-get; then
        local apt_err apt_rc
        apt_err=$(/usr/bin/timeout --preserve-status 30 /usr/bin/sudo -n /usr/bin/apt-get -qq update 2>&1 >/dev/null)
        apt_rc=$?
        if [[ $apt_rc -ne 0 ]]; then
            if [[ $apt_rc -eq 124 ]]; then
                flag_degraded "apt update priming timed out after 30s (slow mirror?) — update counts may be stale"
            else
                flag_degraded "apt update priming failed (exit $apt_rc): $(echo "$apt_err" | /usr/bin/tail -1 | /usr/bin/cut -c1-120)"
            fi
        fi
    else
        flag_degraded "passwordless sudo for apt-get unavailable — skipping apt cache priming (update counts may be stale)"
    fi

    # Cache apt output once
    local apt_output
    apt_output=$($T /usr/bin/apt list --upgradable 2>/dev/null | tail -n +2)
    updatable=$(echo "$apt_output" | grep -c . | tr -d ' \n')
    updatable=${updatable:-0}
    security=$(echo "$apt_output" | grep -ci security | tr -d ' \n' || echo "0")
    security=${security:-0}

    # Kernel CVEs need a reboot to take effect — separate them so they don't
    # get lost in the noise of generic "security" updates.
    kernel_security=$(echo "$apt_output" | grep -ciE "^linux-(image|generic|headers|modules|hwe|aws|gcp|azure|kvm|raspi|nvidia|tools)" | tr -d ' \n' || echo "0")
    kernel_security=${kernel_security:-0}

    # Classify remaining by origin so the user knows what's left and why
    # unattended-upgrades didn't auto-install it.
    distro=$(echo "$apt_output" | grep -ciE "/noble(-updates|-security)? " | tr -d ' \n' || echo "0")
    distro=${distro:-0}
    third_party=$(echo "$apt_output" | grep -ciE "/(unknown|docker|github|tailscale|brave|vscode|signal|element|spotify|slack) " | tr -d ' \n' || echo "0")
    third_party=${third_party:-0}

    [[ $updatable -gt $UPDATE_THRESHOLD ]] && out="$out\n📦 UPDATES: $updatable packages upgradable (distro: $distro · 3rd-party: $third_party)"
    [[ $security -gt 0 ]] && out="$out\n🔒 SECURITY: $security security update(s) pending"
    [[ $kernel_security -gt 0 ]] && out="$out\n🛡️ KERNEL-CVE: $kernel_security kernel security package(s) — reboot required to apply"

    echo "$out"
}

report_maintenance() {
    local out=""

    # Reboot required — surface the WHY by reading reboot-required.pkgs.
    # This file names the packages whose on-disk version requires a reboot
    # to be loaded by running processes (typically libc6, openssh, kernel).
    if [[ -f /var/run/reboot-required ]]; then
        local since
        since=$(/usr/bin/stat -c %y /var/run/reboot-required 2>/dev/null | /usr/bin/cut -d. -f1)
        local reason=""
        if [[ -f /var/run/reboot-required.pkgs ]]; then
            reason=$(/usr/bin/tr '\n' ' ' < /var/run/reboot-required.pkgs | /usr/bin/sed 's/ $//')
        fi
        out="$out\n🔁 REBOOT: required since ${since}${reason:+ ($reason)}"
    fi

    # apt cache freshness — /var/lib/apt/periodic/update-success-stamp is
    # touched by apt-daily.timer whenever `apt update` succeeds. If it's
    # older than APT_CACHE_STALE_SECS, the script's `apt list --upgradable`
    # output could be missing recent security updates.
    if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
        local age=$(( $(/usr/bin/date +%s) - $(/usr/bin/stat -c %Y /var/lib/apt/periodic/update-success-stamp) ))
        if [[ $age -gt $APT_CACHE_STALE_SECS ]]; then
            out="$out\n⏳ APT-CACHE: stale (${age}s / $((APT_CACHE_STALE_SECS / 3600))h since last apt update)"
        fi
    else
        out="$out\n⏳ APT-CACHE: no update-success-stamp found — apt update has never succeeded?"
    fi

    # Timer health — apt-daily.timer and apt-daily-upgrade.timer should fire
    # at least daily. If either hasn't, unattended-upgrades isn't running.
    for t in apt-daily.timer apt-daily-upgrade.timer; do
        local last_trigger
        last_trigger=$($T /usr/bin/systemctl show "$t" --property=LastTriggerUSec --value 2>/dev/null)
        if [[ "$last_trigger" == "n/a" ]] || [[ -z "$last_trigger" ]]; then
            out="$out\n⏰ TIMER: $t has never fired"
        else
            # LastTriggerUSec is a human-readable timestamp in modern systemd.
            # Convert to epoch seconds and compare against now.
            local last_epoch
            last_epoch=$($T /usr/bin/date -d "$last_trigger" +%s 2>/dev/null)
            if [[ -n "$last_epoch" ]] && [[ "$last_epoch" =~ ^[0-9]+$ ]]; then
                local drift=$(( $(/usr/bin/date +%s) - last_epoch ))
                if [[ $drift -gt $TIMER_DRIFT_SECS ]]; then
                    out="$out\n⏰ TIMER: $t hasn't fired in ${drift}s ($((drift / 3600))h)"
                fi
            fi
        fi
    done

    # Unattended-upgrades itself — two signals, two roles. The log's mtime
    # is the load-bearing one: if the service ran on schedule, the file was
    # touched within TIMER_DRIFT_SECS. The phrase check on the last INFO
    # line only classifies WHAT kind of run it was. Mid-run lines
    # ("Starting", "Initial whitelist") are steady state, not anomalies —
    # greping only the last line flagged a run in progress as broken.
    local uu_log=/var/log/unattended-upgrades/unattended-upgrades.log
    if [[ -f "$uu_log" ]]; then
        local uu_last uu_age
        # DEBUG lines come after the meaningful INFO ones, so grab the last INFO.
        uu_last=$($T /usr/bin/grep -E "^20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3} INFO " "$uu_log" 2>/dev/null | /usr/bin/tail -n 1)
        uu_age=$(( $(/usr/bin/date +%s) - $(/usr/bin/stat -c %Y "$uu_log") ))
        if [[ -z "$uu_last" ]]; then
            out="$out\n⏰ UNATTENDED-UPGRADES: no INFO line found in log"
        elif [[ $uu_age -gt $TIMER_DRIFT_SECS ]]; then
            out="$out\n⏰ UNATTENDED-UPGRADES: log not updated in ${uu_age}s — service may be broken"
        # NOTE: do NOT use 'echo "$uu_last" | grep -qE ...' here — the echo's
        # stdout leaks into the function's stdout, polluting the captured
        # report with the raw log line. Use a here-string so $uu_last goes
        # straight to grep's stdin without an echo.
        elif ! grep -qE "All upgrades installed|No packages found that can be upgraded unattended|kept packages can't be calculated in dry-run mode|Initial whitelist \(not strict\)" <<<"$uu_last"; then
            # Strip the timestamp prefix so the snippet fits Telegram's char
            # budget and answers "old artifact?" vs "current anomaly" at a glance.
            out="$out\n⏰ UNATTENDED-UPGRADES: last INFO line unexpected — $(echo "$uu_last" | /usr/bin/sed -E 's/^[^ ]+ +[0-9:,-]+ INFO //' | /usr/bin/cut -c1-100)"
        elif [[ $uu_age -gt $APT_CACHE_STALE_SECS ]] && grep -qE "Starting unattended upgrades script|Initial whitelist" <<<"$uu_last"; then
            # Log is fresh and the last line is a mid-run marker: a run is
            # in progress (or the last one died mid-flight). Freshness
            # already cleared it above, so this is informational only.
            :  # no finding — a run in progress is normal at audit time
        fi
    else
        out="$out\n⏰ UNATTENDED-UPGRADES: log file missing"
    fi

    # needrestart — find daemons linked against an older libc / running an old
    # kernel. These are running with the OLD security state in memory even
    # though the new libc6 is on disk. `-p` is nagios plugin mode: exit 2 =
    # CRITICAL (kernel or services need restart), 1 = WARNING, 0 = OK.
    # We split kernel and services because kernel needs a reboot (different
    # action) while services can be restarted individually.
    local needrestart_bin
    needrestart_bin=$(command -v needrestart)
    if [[ -n "$needrestart_bin" ]] && sudo_ok "$needrestart_bin"; then
        local nr_out nr_rc
        nr_out=$($T /usr/bin/sudo -n "$needrestart_bin" -b -p 2>/dev/null)
        nr_rc=$?
        if [[ $nr_rc -eq 2 ]]; then
            # Parse out kernel version drift and service count
            local kernel_line services_count
            kernel_line=$(echo "$nr_out" | /usr/bin/grep -oE 'Kernel: [^,()]+' | /usr/bin/head -1)
            services_count=$(echo "$nr_out" | /usr/bin/grep -oE 'Services: [0-9]+' | /usr/bin/grep -oE '[0-9]+')
            # Kernel mismatch means a newer kernel is installed but we're
            # still booting the old one — real reboot-required state.
            if [[ -n "$kernel_line" ]]; then
                out="$out\n🛡️ KERNEL-RESTART: $kernel_line (newer kernel on disk, current kernel still running)"
            fi
            if [[ -n "$services_count" ]] && [[ "$services_count" -gt 0 ]]; then
                out="$out\n🔄 SERVICES-RESTART: $services_count service(s) running pre-upgrade libs (e.g. sshd, fail2ban) — restart or reboot"
            fi
        elif [[ $nr_rc -eq 1 ]]; then
            # WARNING state (e.g. microcode outdated, sessions active) — surface too.
            local warning_msg
            warning_msg=$(echo "$nr_out" | /usr/bin/head -1)
            [[ -n "$warning_msg" ]] && out="$out\n⚠️ NEEDRESTART-WARN: $warning_msg"
        elif [[ $nr_rc -gt 2 ]]; then
            flag_degraded "needrestart returned $nr_rc (expected 0, 1, or 2)"
        fi
    fi

    echo "$out"
}

# --- File-integrity baseline -----------------------------------------------
# Compute a sha256 for a single path. Files: direct sha256sum. Dirs:
# sha256 of sorted sha256sums of regular files inside. Missing: empty
# string (caller treats as "skip silently").
#
# Args: $1 = path
# Echoes: "<sha256>" on stdout, exits 0 even on missing files (caller
# checks emptiness).
integrity_hash_path() {
    local p="$1"
    if [[ -f "$p" ]]; then
        /usr/bin/sha256sum "$p" 2>/dev/null | /usr/bin/awk '{print $1}'
    elif [[ -d "$p" ]]; then
        # Concatenated sha256 of sorted per-file sha256sums. find -type f
        # catches regular files only; -print0 + sort -z keeps paths with
        # spaces correct.
        /usr/bin/find "$p" -type f -print0 2>/dev/null \
            | /usr/bin/sort -z \
            | /usr/bin/xargs -0 /usr/bin/sha256sum 2>/dev/null \
            | /usr/bin/sha256sum \
            | /usr/bin/awk '{print $1}'
    fi
}

# Build the current integrity snapshot as a JSON object printed to stdout.
# Each key is the path; value is sha256 hex. Missing paths are omitted
# (so the baseline tracks only what exists today).
integrity_snapshot() {
    {
        /usr/bin/printf '{'
        local first=1 path hash
        for path in "${INTEGRITY_TARGETS[@]}"; do
            hash=$(integrity_hash_path "$path")
            [[ -z "$hash" ]] && continue
            if [[ $first -eq 1 ]]; then first=0; else /usr/bin/printf ','; fi
            /usr/bin/printf '"%s":"%s"' "$path" "$hash"
        done
        /usr/bin/printf '}'
    }
}

# Compare current snapshot against the baseline on disk and emit findings
# for any added, removed, or changed paths. On first run (no baseline),
# write the current snapshot as the baseline and emit nothing — the user
# shouldn't see "all crown jewels changed" on day one.
report_integrity() {
    local out=""

    # Non-root runs can't read /etc/shadow, /etc/gshadow, /etc/sudoers, or
    # /root/.ssh/authorized_keys. integrity_hash_path returns empty for
    # those, which drops them from the snapshot — the diff then reports
    # them as "removed" AND the poisoned snapshot overwrites the baseline,
    # so the next root run reports them all as "added". Skip the whole
    # check instead of corrupting it.
    if [[ $EUID -ne 0 ]]; then
        flag_degraded "not running as root — file-integrity check skipped (it would poison the baseline with false removals)"
        echo ""
        return
    fi

    if [[ ! -d "$INTEGRITY_BASELINE_DIR" ]]; then
        /usr/bin/mkdir -p "$INTEGRITY_BASELINE_DIR" 2>/dev/null || {
            flag_degraded "could not create $INTEGRITY_BASELINE_DIR — integrity check skipped"
            echo ""
            return
        }
        /usr/bin/chmod 0700 "$INTEGRITY_BASELINE_DIR"
    fi

    local current
    current=$(integrity_snapshot)

    if [[ ! -f "$INTEGRITY_BASELINE_FILE" ]]; then
        # First run — persist and stay silent. The baseline contains hashes
        # of /etc/shadow and /etc/gshadow, which makes it an offline
        # password-guessing oracle for anyone who can read it: 0600, not
        # world-readable.
        umask 077
        /usr/bin/printf '%s' "$current" > "$INTEGRITY_BASELINE_FILE" 2>/dev/null \
            || flag_degraded "could not write integrity baseline"
        echo ""
        return
    fi

    # Diff current against baseline. Pass the baseline path through the
    # INTEGRITY_BASELINE_FILE env var so we don't have to escape it
    # through multiple quoting layers. Python reads the snapshot from
    # stdin (the pipe) and reads the baseline from disk. Note: we use
    # python3 -c here, not <<HEREDOC, because a heredoc inside $(...)
    # would consume stdin and shadow the printf pipe — this is the bug
    # the previous version hit.
    local diff
    diff=$(INTEGRITY_BASELINE_FILE="$INTEGRITY_BASELINE_FILE" \
        /usr/bin/printf '%s' "$current" \
        | INTEGRITY_BASELINE_FILE="$INTEGRITY_BASELINE_FILE" /usr/bin/python3 -c '
import sys, json, os
cur = json.load(sys.stdin)
try:
    with open(os.environ["INTEGRITY_BASELINE_FILE"]) as f:
        base = json.load(f)
except Exception:
    base = {}
changes = []
all_paths = set(cur) | set(base)
for p in sorted(all_paths):
    c = cur.get(p)
    b = base.get(p)
    if c is None and b is not None:
        changes.append(("removed", p))
    elif b is None and c is not None:
        changes.append(("added", p))
    elif c != b:
        changes.append(("changed", p))
for kind, path in changes:
    print(kind + chr(9) + path)
' 2>/dev/null)

    if [[ -n "$diff" ]]; then
        local n=0
        while IFS=$'\t' read -r kind path; do
            [[ -z "$kind" ]] && continue
            case "$kind" in
                added)   out="$out\n🔒 INTEGRITY: added $path" ;;
                removed) out="$out\n🔒 INTEGRITY: removed $path" ;;
                changed) out="$out\n🔒 INTEGRITY: changed $path" ;;
            esac
            n=$((n + 1))
        done <<< "$diff"
        # Persist the new snapshot so the next run's baseline is current.
        # umask 077 keeps it 0600 (same reasoning as the first-run write);
        # the chmod also repairs any pre-existing world-readable baseline
        # from an earlier version of this script.
        umask 077
        /usr/bin/printf '%s' "$current" > "$INTEGRITY_BASELINE_FILE" 2>/dev/null
        /usr/bin/chmod 0600 "$INTEGRITY_BASELINE_FILE" 2>/dev/null
        if [[ $n -gt 1 ]]; then
            out="$out\n🔒 INTEGRITY: $n crown-jewel change(s) total (baseline updated)"
        fi
    fi

    echo "$out"
}

main() {
    # Temp file for degraded findings — see the comment at flag_degraded().
    # Left empty if mktemp fails; flag_degraded's append then no-ops and
    # the run proceeds without degraded reporting (same as before).
    DEGRADED_FILE=$(/usr/bin/mktemp 2>/dev/null) || true

    check_deps

    local resources security system updates maintenance integrity exit_code=0
    resources=$(report_resources)
    security=$(report_security)
    system=$(report_system)
    updates=$(report_updates)
    maintenance=$(report_maintenance)
    integrity=$(report_integrity)

    # Assemble degraded findings from the temp file (survived subshells)
    if [[ -n "$DEGRADED_FILE" ]] && [[ -s "$DEGRADED_FILE" ]]; then
        while IFS= read -r degraded_line; do
            [[ -z "$degraded_line" ]] && continue
            DEGRADED="$DEGRADED\n❓ DEGRADED: $degraded_line"
        done < "$DEGRADED_FILE"
        /usr/bin/rm -f "$DEGRADED_FILE"
    fi
    DEGRADED_FILE=""

    local full_report="${resources}${security}${system}${updates}${maintenance}${integrity}${DEGRADED}"

    if [[ "$OUTPUT_MODE" == "json" ]]; then
        # Build JSON. Walk the assembled text report line-by-line; for each
        # non-empty line, parse the leading emoji as severity and emit a
        # structured finding. Lines without an emoji (e.g. blank lines or
        # the SYSTEM HEALTH header) are skipped. The original text is also
        # kept in raw_output for downstream consumers that prefer it.
        local safe_report="${full_report}"
        # report_* functions emit echo $out which preserves \n as escapes
        # (no actual newlines). Convert them so we can iterate per finding.
        local report_for_parsing="${safe_report//\\n/$'\n'}"
        local findings_count=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            # DEGRADED entries get their own severity instead of the
            # generic emoji classification — they mean "a check could
            # not run", which is more actionable than info/warn.
            if [[ "$line" == *"❓ DEGRADED:"* ]]; then
                local degraded_msg="${line#*❓ DEGRADED: }"
                json_push "degraded" "degraded.check" "$degraded_msg"
                findings_count=$((findings_count + 1))
                continue
            fi
            # Strip leading emoji + space; everything after is the message
            local msg="${line}"
            local id_prefix="info"
            case "$msg" in
                "🚨"*) id_prefix="alert" ;;
                "🔒"*|"🛡️"*|"🔴"*|"💥"*|"🌐"*|"🔓"*|"⏰"*) id_prefix="warn" ;;
                "⚠️"*) id_prefix="warn" ;;
                "📅"*|"📦"*|"🆕"*|"🔄"*|"🔁"*) id_prefix="info" ;;
            esac
            msg=$(echo "$msg" | /usr/bin/sed -E 's/^[^ ]+ //')
            # Generate a stable-ish id from the first few words of the message
            local id
            id=$(echo "$msg" | /usr/bin/awk '{for(i=1;i<=3 && i<=NF;i++) printf "%s_", tolower($i); print ""}' | /usr/bin/sed 's/_$//' | /usr/bin/tr -d ',' | /usr/bin/cut -c1-50)
            json_push "$id_prefix" "$id" "$msg"
            findings_count=$((findings_count + 1))
        done <<< "$report_for_parsing"

        local safe_report_json
        # Convert the \n escapes to real newlines BEFORE json.dumps — the
        # escaped two-char sequences would otherwise survive into the JSON
        # string as literal backslash-n garbage for downstream formatters.
        local report_real_newlines="${safe_report//\\n/$'\n'}"
        safe_report_json=$(/usr/bin/printf '%s' "$report_real_newlines" | /usr/bin/python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
        local status="ok"
        [[ "$findings_count" -gt 0 ]] && status="findings"
        /usr/bin/printf '{"status":"%s","timestamp":"%s","host":"%s","findings":[%s],"raw_output":%s}\n' \
            "$status" \
            "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "$(/usr/bin/hostname)" \
            "$JSON_FINDINGS" \
            "$safe_report_json"
        # Always exit 0 in JSON mode — the JSON itself encodes "status:ok"
        # vs "status:findings", so callers can branch on that instead of
        # the exit code. This matters because pipefail in shells / systemd
        # units would otherwise treat exit-1 (findings) as a failure even
        # though the JSON was produced correctly.
        exit_code=0
    else
        if [[ -z "$full_report" ]]; then
            printf '\n=== SYSTEM HEALTH - %s ===\n' "$(date '+%Y-%m-%d %H:%M')"
            echo "✅ All clear — no issues detected"
        else
            report "$full_report"
            exit_code=1
        fi
    fi

    return $exit_code
}

main
