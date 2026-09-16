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
# Repo root for dev-checkout fallbacks. Same shape as install.sh:27 so a
# checkout run directly (no install.sh) still resolves its own VERSION file
# without depending on the install marker at /usr/local/share/box-audit/version.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

BOX_AUDIT_VERSION="unknown"
if [[ -r /usr/local/share/box-audit/version ]]; then
    _BA_VERSION="$(</usr/local/share/box-audit/version)"
    BOX_AUDIT_VERSION="${_BA_VERSION//[$'\r\n ']/}"
elif [[ -r "$REPO_ROOT/VERSION" ]]; then
    _BA_VERSION="$(<"$REPO_ROOT/VERSION")"
    BOX_AUDIT_VERSION="${_BA_VERSION//[$'\r\n ']/}"
fi
OUTPUT_MODE="text"   # "text" (default) or "json"

# --- Build the version suffix at runtime ----------------------------------
# The release VERSION file (single source of truth) carries only the bare
# semantic version — the script appends +replay when this binary supports
# the --replay mode. Editing the file on every replay change would be a
# churn trap; a constant here makes it auditable in one place.
REPLAY_IMPLEMENTED=1
VERSION_SUFFIX=""
[[ -n "${REPLAY_IMPLEMENTED}" ]] && VERSION_SUFFIX="+replay"
BOX_AUDIT_VERSION_DISPLAY="${BOX_AUDIT_VERSION}${VERSION_SUFFIX}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_MODE="json"; shift ;;
        --text) OUTPUT_MODE="text"; shift ;;
        -h|--help)
            /usr/bin/cat <<EOF
Usage: $(/usr/bin/basename "$0") [OPTIONS]
                [--init|--accept-port N|--accept-timer NAME|
                 --outbound-threshold N|--tail [N]|--diff [N]|
                 --print-schema]

  (default)   Human-readable report suitable for Telegram / Discord.
  --json      Machine-readable JSON to stdout, e.g. for webhook delivery.
  --version   Print version ($BOX_AUDIT_VERSION_DISPLAY) and exit.

  Manage per-box config under /var/lib/box-audit/ (run as root):
  --init                       Snapshot the current box into the config files
                               (ports listening now, timers active now,
                               cron.d allowlist, outbound threshold = 25,
                               SUID threshold = 30).
  --accept-port N              Append port N to ports-allowlist.txt.
  --accept-timer NAME          Append timer NAME to timers-baseline.txt.
  --outbound-threshold N       Write outbound-threshold.conf (single integer).

  History (read-only):
  --tail [N]                   List the last N daily snapshots (default 7).
  --diff [N]                   Findings added/gone since N days ago (default 1).
  --replay [DIR]               Treat DIR as the history root (read-only). Use
                               alone for a today-only run summary; with
                               --diff [N] for an N-positions-earlier diff.
  --print-schema               Emit the severity + check_id mapping as JSON.

Exit codes: 0 = all clear (or manage-op success), 1 = findings present,
             2 = bad CLI flag. (--json mode always exits 0; see status field.)
EOF
            exit 0
            ;;
        --version)
                    /usr/bin/echo "box-audit $BOX_AUDIT_VERSION_DISPLAY"
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
                        --tail)
                    # Optional arg: consume $2 only when it exists AND is not
                    # another flag. Bare `--tail` defaults to 7 (help text,
                    # cli.md, and this parser must agree). The old form —
                    # `[[ $# -ge 2 ]] || TAIL_MODE="7"; TAIL_MODE="$2"` — was
                    # two statements, so bare `--tail` read unbound $2 and
                    # died under `set -u`.
                    if [[ $# -ge 2 && "$2" != -* ]]; then
                        TAIL_MODE="$2"; shift 2
                    else
                        TAIL_MODE="7"; shift
                    fi ;;
                --diff)
                    # Same optional-arg pattern; bare `--diff` defaults to 1
                    # (docs said so; the parser used to demand an argument).
                    if [[ $# -ge 2 && "$2" != -* ]]; then
                        DIFF_MODE="$2"; shift 2
                    else
                        DIFF_MODE="1"; shift
                    fi ;;
                --replay)
                    # Same optional-arg pattern; bare `--replay` is rejected
                    # explicitly below because the dir is the whole point.
                    # The one-statement if/then/else/shift form is required
                    # under `set -u` — the two-statement default form
                    # (`[[ $# -ge 2 ]] || VAR=default; VAR="$2"`) reads
                    # unbound $2 on a bare flag.
                    if [[ $# -ge 2 && "$2" != -* ]]; then
                        REPLAY_DIR="$2"; shift 2
                    else
                        echo "box-audit: --replay requires a directory argument" >&2
                        exit 2
                    fi ;;
                                --print-schema)
                                    PRINT_SCHEMA=1; shift ;;
                *) /usr/bin/echo "Unknown arg: $1 (try --help)" >&2; exit 2 ;;
            esac
        done

        # --- Per-box config lookups -----------------------------------------------
        # /var/lib/box-audit/ holds per-box state: ports-allowlist.txt,
        # timers-baseline.txt, outbound-threshold.conf. The helpers below read
        # them, falling back to small built-in defaults when the file is missing
        # (fresh install before --init ran; or just-installed agent-path clone).
        # Each first-miss per run prints a one-time stderr note telling the user
        # how to populate them. The gate is a sentinel file (see
        # note_default_used) because all helpers are called via $(...)
        # command substitution — an in-process variable would be lost when
        # the subshell exits.
        CONFIG_DIR="/var/lib/box-audit"
        PORTS_FILE="$CONFIG_DIR/ports-allowlist.txt"
        TIMERS_FILE="$CONFIG_DIR/timers-baseline.txt"
        OUTBOUND_FILE="$CONFIG_DIR/outbound-threshold.conf"
        CRON_D_ALLOWLIST_FILE="$CONFIG_DIR/cron-d-allowlist.txt"
        SUID_THRESHOLD_FILE="$CONFIG_DIR/suid-threshold.conf"
        note_default_used() {
            # Gate via a sentinel file rather than an in-process variable.
            # The five helpers are all called via $(...) command substitution,
            # which runs in a subshell — any variable set inside is discarded
            # when the subshell exits, so an in-process gate like
            # CONFIG_NOTICE_PRINTED resets between calls. The sentinel survives
            # across runs and across subshells; --init clears it so a fresh
            # learn-box pass starts clean.
            local _sentinel="/var/lib/box-audit/.defaults-notice-printed"
            [[ -f "$_sentinel" ]] && return 0
            : > "$_sentinel"
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
        get_cron_d_allowlist() {
            if [[ -r "$CRON_D_ALLOWLIST_FILE" ]]; then
                # One name per non-comment, non-blank line. Trim whitespace.
                /usr/bin/grep -vE '^[[:space:]]*(#|$)' "$CRON_D_ALLOWLIST_FILE" 2>/dev/null \
                    | /usr/bin/sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
                    | /usr/bin/tr '\n' ' ' \
                    | /usr/bin/sed -E 's/[[:space:]]+$//'
            else
                note_default_used
                echo "anacron e2scrub_all sysstat 0hourly"
            fi
        }
        get_suid_threshold() {
            if [[ -r "$SUID_THRESHOLD_FILE" ]]; then
                local v
                v=$(/usr/bin/grep -vE '^[[:space:]]*(#|$)' "$SUID_THRESHOLD_FILE" 2>/dev/null | /usr/bin/head -1 | /usr/bin/tr -d ' \r\n')
                if [[ "$v" =~ ^[1-9][0-9]*$ ]]; then
                    echo "$v"; return 0
                fi
            fi
            note_default_used
            echo "30"
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
                    # cron.d allowlist: learn the box's actual current
                    # /etc/cron.d/ contents, but make sure the four standard
                    # names are present too.
                    {
                        /usr/bin/ls /etc/cron.d/ 2>/dev/null | /usr/bin/sort -u
                        /usr/bin/printf 'anacron\ne2scrub_all\nsysstat\n0hourly\n'
                    } | /usr/bin/sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
                        | /usr/bin/awk 'NF && !seen[$0]++' > "$CRON_D_ALLOWLIST_FILE"
                    /usr/bin/printf '30\n' > "$SUID_THRESHOLD_FILE"
                    # --init has now produced a fresh, accurate config — clear
                    # the defaults-notice sentinel so the next run starts with
                    # a clean slate (no notice unless something is missing
                    # again).
                    /usr/bin/rm -f /var/lib/box-audit/.defaults-notice-printed
                    echo "box-audit: seeded $PORTS_FILE, $TIMERS_FILE, $OUTBOUND_FILE, $CRON_D_ALLOWLIST_FILE, $SUID_THRESHOLD_FILE"
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
        # --- History query functions ------------------------------------------
        # These MUST be defined before the dispatch block below: bash reads
        # top-to-bottom, and the dispatch calls history_tail/history_diff
        # directly when the matching flag was parsed. (Before v0.5.0 these
        # lived below, so `--tail` printed "command not found" and exited 0.)
        # Read-only; /var/log/box-audit/history is optional state.
        # --tail [N] (default 7) / --diff [N] (default 1); the parser in the
        # CLI block above applies those defaults, matching the help text.
        HISTORY_DIR="/var/log/box-audit/history"

        # Tail mode: read-only summary of the last N daily snapshots. Sorted
        # most-recent-first.
        history_tail() {
            local n="${1:-7}"
            # 2>/dev/null: history is best-effort. When /var/log/box-audit
            # exists but history/ doesn't (fresh install pre-first-JSON-run),
            # mkdir can't create it as non-root — that's not an error worth
            # noise; the "history is empty" message below is the signal.
            /usr/bin/mkdir -p "$HISTORY_DIR" 2>/dev/null
            # Missing history is a successful empty answer for a read-only
            # query (stdout, exit 0) — same as the empty-dir case below. On
            # CI / fresh boxes /var/log/box-audit can't even be created by a
            # non-root user; that must not look like a failure.
            if [[ ! -d "$HISTORY_DIR" ]]; then
                echo "box-audit: no history directory at $HISTORY_DIR (run --json once to seed)"
                return 0
            fi
            local files
            files=$(find "$HISTORY_DIR" -maxdepth 1 -type f -name '*.json' ! -name '.*' -printf '%T@ %f\n' \
                | sort -rn | head -n "$n" | awk '{print $2}')
            [[ -z "$files" ]] && { echo "box-audit: history is empty (run --json once to seed)"; return; }
            local fname fdate
            while IFS= read -r fname; do
                [[ -z "$fname" ]] && continue
                fdate="${fname%.json}"
                /usr/bin/python3 -c "
import json
try:
    d = json.load(open('$HISTORY_DIR/$fname'))
    status = d.get('status', '?')
    n = len(d.get('findings', []))
    print(f'$fdate  {status:8}  {n} finding(s)')
except Exception:
    print(f'$fdate  (corrupt or unreadable)')
"
            done <<< "$files"
        }

        # Diff mode: what changed between today and N days ago. Read-only.
        # Optional $2 lets the replay path reuse the same comparison logic
        # against a different history directory and an explicit file pair
        # (replay's "today" is the last lex-sorted snapshot, not the wall
        # clock — date math doesn't apply). The default $2 path keeps the
        # live-history contract intact.
        # For the replay branch, the caller passes the resolved today/baseline
        # filenames as $3 and $4 — the footer line uses them verbatim instead
        # of `date -u` so the summary matches the files actually compared.
        history_diff() {
            local n="${1:-1}"
            local dir="${2:-$HISTORY_DIR}"
            local diff_file1 diff_file2 today_label baseline_label
            if [[ "$dir" == "$HISTORY_DIR" ]]; then
                diff_file1="$dir/$(date -u +%Y-%m-%d).json"
                diff_file2="$dir/$(date -u -d "$n days ago" +%Y-%m-%d).json"
                today_label="$(date -u +%Y-%m-%d).json"
                baseline_label="$(date -u -d "$n days ago" +%Y-%m-%d).json"
            else
                diff_file1="${3:-}"
                diff_file2="${4:-}"
                today_label="${3##*/}"
                baseline_label="${4##*/}"
            fi
            [[ -r "$diff_file2" ]] || { echo "box-audit: --diff cannot find $diff_file2 — need at least one prior snapshot" >&2; exit 1; }
            /usr/bin/python3 -c "
import json
def load(p):
    try: return {f.get('check_id'): f for f in json.load(open(p)).get('findings', [])}
    except Exception: return {}
base = load('$diff_file2')
today = load('$diff_file1')
added = today.keys() - base.keys()
removed = base.keys() - today.keys()
for k in sorted(added):
    print(f'+ ADDED  [{today[k].get(\"severity\", \"?\")[:4]:<4}] {today[k].get(\"message\", \"\")}')
for k in sorted(removed):
    print(f'- GONE   [{base[k].get(\"severity\", \"?\")[:4]:<4}] {base[k].get(\"message\", \"\")}')
print(f'  baseline=$baseline_label today=$today_label  (+{len(added)} -{len(removed)})')
"
        }

        # --replay <DIR>: treat DIR as a self-contained history root.
        # Read-only against the live /var/log/box-audit/: no history_write,
        # no history_persist_counts_from_json, no mkdir of live paths. The
        # dir-override plumbing reuses history_diff (see the $2 / $3 / $4
        # branch above) so the comparison logic is not forked.
        run_replay() {
            local dir="$1"
            # Empty / missing dir → success with a clear message on stdout.
            # Match the wording the issue specifies: "box-audit: replay
            # directory is empty", exit 0, stderr silent.
            if [[ ! -d "$dir" ]]; then
                echo "box-audit: replay directory is empty"
                return 0
            fi
            # Lex sort = chronological for YYYY-MM-DD.json filenames. We
            # explicitly do NOT use mtime here: a re-stamped fixture (e.g.
            # copy-into-place during testing) would otherwise reorder the
            # timeline silently.
            local replay_files=()
            local f
            while IFS= read -r f; do
                replay_files+=("$f")
            done < <(/usr/bin/find "$dir" -maxdepth 1 -type f -name '*.json' ! -name '.*' -printf '%f\n' | /usr/bin/sort)
            if [[ ${#replay_files[@]} -eq 0 ]]; then
                echo "box-audit: replay directory is empty"
                return 0
            fi
            local last_idx=$((${#replay_files[@]} - 1))
            local today_file="$dir/${replay_files[$last_idx]}"
            if [[ -n "${DIFF_MODE:-}" ]]; then
                # N positions earlier from the last file. Off-by-one protection:
                # requesting diff 5 against a 3-file corpus is an error, not a
                # silent truncation.
                local earlier_idx=$((last_idx - DIFF_MODE))
                if (( earlier_idx < 0 )); then
                    echo "box-audit: --diff $DIFF_MODE out of range (corpus has $((last_idx + 1)) snapshot(s))" >&2
                    return 1
                fi
                local baseline_file="$dir/${replay_files[$earlier_idx]}"
                history_diff "$DIFF_MODE" "$dir" "$today_file" "$baseline_file"
                return 0
            fi
            # No --diff: print a one-line summary of the latest snapshot —
            # date, status, finding count — the same shape history_tail
            # prints for the live history.
            local fdate
            fdate="${replay_files[$last_idx]%.json}"
            /usr/bin/python3 -c "
import json
try:
    d = json.load(open('$today_file'))
    print(f\"$fdate  {d.get('status','?'):8}  {len(d.get('findings', []))} finding(s)\")
except Exception:
    print(f'$fdate  (corrupt or unreadable)')
"
        }
        if [[ -n "${REPLAY_DIR:-}" ]]; then
            run_replay "$REPLAY_DIR"
            exit $?
        fi

        # --tail / --diff are read-only history queries; same dispatch path.
        if [[ -n "${TAIL_MODE:-}" ]]; then
            history_tail "$TAIL_MODE"
            exit 0
        fi
        if [[ -n "${DIFF_MODE:-}" ]]; then
            history_diff "$DIFF_MODE"
            exit 0
        fi
        if [[ -n "${PRINT_SCHEMA:-}" ]]; then
            /usr/bin/python3 -c '
import json
out = {
    "severities": {
        "alert": "🚨 active security signal (look now)",
        "warn": "🔒🛡️🔴⚠️💥🌐🔓⏰ above-threshold or delta (look today)",
        "info": "📅📦🆕🔄🔁 routine state (skim)",
        "degraded": "❓ a check could not run (fix before trusting no findings)",
    },
    "check_ids": {
        "security.fail2ban_banned":      "Currently banned IPs on fail2ban jail",
        "security.ssh_fails":            "SSH auth failures in last 24h",
        "security.sudo_fails":           "sudo auth failures in last 24h",
        "security.new_port":             "open port not in ports-allowlist",
        "security.outbound_remote_count":"non-LAN remote IPs established",
        "security.outbound_delta":       "today > 2x yesterday AND > 5 absolute",
        "security.suid_count":           "SUID binary count",
        "security.suid_delta":           "today suid - yesterday suid > 2",
        "system.failed_units":           "failed systemd unit names",
        "system.custom_timers":          "non-standard systemd timers",
        "system.user_cron":              "non-empty user crontab",
        "system.cron_d_dropins":         "unexpected /etc/cron.d/ entries",
        "system.docker_unhealthy":       "unhealthy docker containers",
        "system.crash_dumps":            "var crash files present",
        "system.kernel_errors":          "kernel errors in last 24h journal",
        "updates.upgradable":            "packages upgradable over threshold",
        "updates.security_pending":      "security updates pending",
        "updates.security_delta":        "security queue grew by over 1 vs yesterday",
        "updates.kernel_cve":            "kernel security CVEs pending",
        "maintenance.reboot_required":   "var run reboot-required present",
        "maintenance.apt_cache_stale":   "apt update stamp over 48h",
        "maintenance.timer_drift":       "apt-daily timer hasnt fired in 26h",
        "maintenance.unattended_upgrades": "unattended-upgrades log anomalies",
        "maintenance.kernel_restart":    "kernel mismatch installed vs running",
        "maintenance.services_restart":  "services running pre-upgrade libs",
        "maintenance.needrestart_warn":  "needrestart WARNING class",
        "integrity.change":              "crown-jewel file modified vs baseline",
        "resources.disk_high":           "root partition over 85 percent",
        "resources.swap_high":           "swap over 70 percent",
        "resources.load_high":           "1-min loadavg over 3.0",
        "degraded.check":                "a check could not run (see message)",
    },
}
print(json.dumps(out, indent=2, sort_keys=True))
'
            exit 0
        fi

        # --- Findings collector ----------------------------------------------------
# Checks push structured findings via json_push <severity> <check_id> <section>
# <message> [count]. Each call appends ONE json.dumps'd line to $FINDINGS_FILE
# (a mktemp file main() creates before any check runs — same lifetime pattern
# the old $DEGRADED_FILE had). File-backed on purpose: report_* functions run
# inside command substitutions, and an in-memory accumulator mutates a
# subshell-local copy that is thrown away when the substitution returns.
# BOTH the text report and the --json document are renderings of this one
# findings list; adding a check means one json_push call, nothing else.
FINDINGS_FILE=""

json_push() {
    # $1=severity (info|warn|alert|degraded), $2=check_id (e.g. "security.ssh_fails"),
    # $3=section (resources|security|system|updates|maintenance|integrity),
    # $4=message, optional $5=integer count (persisted for next-day delta mode).
    # Fields reach python via the environment so no shell->code quoting layer
    # can mangle message content; json.dumps does the escaping, so messages
    # containing quotes/backslashes are correct, not "usually correct".
    local severity="$1" check_id="$2" section="$3" msg="$4" count="${5:-}"
    [[ -n "$FINDINGS_FILE" ]] || return 0
    BA_SEV="$severity" BA_CID="$check_id" BA_SEC="$section" BA_MSG="$msg" BA_COUNT="$count" \
        FINDINGS_FILE="$FINDINGS_FILE" /usr/bin/python3 -c '
import json, os
finding = {
    "severity": os.environ["BA_SEV"],
    "check_id": os.environ["BA_CID"],
    "section": os.environ["BA_SEC"],
    "message": os.environ["BA_MSG"],
}
c = os.environ.get("BA_COUNT", "")
if c:
    finding["count"] = int(c)
with open(os.environ["FINDINGS_FILE"], "a") as fh:
    fh.write(json.dumps(finding) + "\n")
' 2>/dev/null
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
# doesn't get reported as "all clear". Degraded findings ride the same
# file-backed json_push collector as every other finding — they are raised
# from inside command-substitution subshells, which would discard a plain
# variable accumulator when the substitution returns.
flag_degraded() {
    json_push degraded degraded.check system "$1"
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
    local disk_pct df_output swap_pct load
    disk_pct=$(df / --output=pcent -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -1 | tr -d ' %')
    disk_pct=${disk_pct:-0}
    df_output=$(df -h / --output=source,size,used,avail,pcent -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -1)
    swap_pct=$(free | awk '/Swap:/ {if($2>0) printf "%.0f", $3/$2*100; else print "0"}')
    swap_pct=${swap_pct:-0}
    load=$(awk '{print $1}' /proc/loadavg)

    [[ $disk_pct -gt $DISK_THRESHOLD ]] && json_push warn resources.disk_high resources "${df_output} (${disk_pct}% used)"
    [[ $swap_pct -gt $SWAP_THRESHOLD ]] && json_push warn resources.swap_high resources "${swap_pct}% used"
    awk -v l="$load" -v thresh="$LOAD_THRESHOLD" 'BEGIN{exit !(l>thresh)}' && json_push warn resources.load_high resources "load ${load} (threshold ${LOAD_THRESHOLD})"
}

report_security() {

    # fail2ban banned IPs
    if /usr/bin/sudo -n /usr/bin/fail2ban-client status >/dev/null 2>&1; then
        local currently_banned
        currently_banned=$($T /usr/bin/sudo /usr/bin/fail2ban-client status sshd 2>/dev/null | awk '/Currently banned/ {print $4}' | tr -d ' ')
        local f2b_status=${PIPESTATUS[0]}
        if [[ $f2b_status -ne 0 ]]; then
            flag_degraded "fail2ban-client check failed or timed out (exit $f2b_status)"
        elif [[ -n "$currently_banned" ]] && [[ "$currently_banned" != "0" ]]; then
            json_push alert security.fail2ban_banned security "$currently_banned IP(s) banned on sshd"
        fi
    fi

    # SSH failures (last 24h)
    local ssh_fails
    ssh_fails=$($T /usr/bin/journalctl --since "24 hours ago" --facility=auth --no-pager 2>/dev/null | gc "Failed password|Invalid user")
    [[ $ssh_fails -gt $SSH_FAIL_THRESHOLD ]] && json_push warn security.ssh_fails security "$ssh_fails failed auth attempts (24h)"

    # sudo spam threshold (known gateway behavior, flag only if excessive)
    local sudo_fails
    sudo_fails=$($T /usr/bin/journalctl --since "24 hours ago" --facility=auth --priority=err --no-pager 2>/dev/null | gc "sudo.*true")
    [[ $sudo_fails -gt $SUDO_FAIL_THRESHOLD ]] && json_push warn security.sudo_fails security "$sudo_fails auth failures (24h)"

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
            json_push warn security.new_port security "$port is open (not in baseline)${proc:+ [$proc]}"
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
    [[ $outbound_remote_count -gt $(get_outbound_threshold) ]] && json_push warn security.outbound_remote_count security "$outbound_remote_count non-LAN remote IP(s) connected: $outbound_remote_sample" "$outbound_remote_count"
    # Delta finding — only fires if today's count is 2x AND 5+ above yesterday.
    # When yesterday's snapshot is missing the delta is mute and the absolute
    # threshold above is the only signal (graceful degradation: ~day 1 of use).
    if [[ -n "${YESTERDAY_OUTBOUND_COUNT:-}" ]]; then
        local delta_thresh=$(( YESTERDAY_OUTBOUND_COUNT * 2 ))
        [[ $outbound_remote_count -gt 5 && $outbound_remote_count -gt $delta_thresh ]] \
            && json_push warn security.outbound_delta security "$outbound_remote_count non-LAN remote IP(s), was $YESTERDAY_OUTBOUND_COUNT yesterday (>2x growth)" "$outbound_remote_count"
    fi

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
    # Baseline 18 measured 2026-09-14 on this box; flag if above the
    # per-box threshold (default 30, i.e. 50%+ growth).
    [[ $suid_count -gt $(get_suid_threshold) ]] && json_push warn security.suid_count security "$suid_count SUID binaries on disk (baseline ~18-25) — review for unauthorised additions" "$suid_count"
    # Delta: new SUID binaries are a classic rootkit persistence move. On
    # day 1 (no yesterday snapshot) the absolute check above is the only
    # signal; thereafter a +2 jump is more meaningful than +5 of 18.
    if [[ -n "${YESTERDAY_SUID_COUNT:-}" ]]; then
        local suid_delta=$(( suid_count - YESTERDAY_SUID_COUNT ))
        [[ $suid_delta -gt 2 ]] && json_push warn security.suid_delta security "+${suid_delta} new SUID binaries vs yesterday (${YESTERDAY_SUID_COUNT} → ${suid_count})" "$suid_count"
    fi
}

report_system() {

    # Failed systemd units
    local failed_list failed_units
    failed_list=$($T /usr/bin/systemctl list-units --type=service --state=failed --no-legend --plain --no-pager 2>/dev/null)
    failed_units=$(echo "$failed_list" | grep -c . | tr -d ' \n')
    failed_units=${failed_units:-0}
    [[ $failed_units -gt 0 ]] && {
        local units
        units=$(echo "$failed_list" | awk '{print $1}' | head -5 | tr '\n' ' ')
        json_push warn system.failed_units system "$failed_units failed service(s): $units"
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
            [[ "$timer_name" == "box-audit.timer" || "$timer_name" == "healthcheck.timer" ]] && continue
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
        json_push warn system.custom_timers system "$custom_count non-standard timer(s): $(echo "$custom_timers" | /usr/bin/tr ' ' '\n' | /usr/bin/grep -v '^$' | /usr/bin/head -3 | /usr/bin/tr '\n' ',' | /usr/bin/sed 's/,$//')"
    }

    # User crontab — flag if a non-empty user crontab exists. (You schedule
    # via Hermes cron, not system cron, so anything here is suspicious.)
    # `crontab -l` with no crontab prints "no crontab for <user>" to stdout,
    # which a naive grep counts as 1 line. Filter that out first. $USER is
    # empty under the root systemd unit, and `crontab -l` as root reads
    # root's crontab anyway — so the display name is "root" when EUID is 0.
    local cron_user="root"
    [[ $EUID -ne 0 ]] && cron_user="${USER:-$(id -un)}"
    local user_cron_raw user_cron_entries
    user_cron_raw=$($T /usr/bin/crontab -l 2>/dev/null | /usr/bin/grep -vE '^no crontab for ')
    user_cron_entries=$(echo "$user_cron_raw" | /usr/bin/grep -cvE '^[[:space:]]*(#|$)')
    user_cron_entries=${user_cron_entries:-0}
    [[ $user_cron_entries -gt 0 ]] && json_push warn system.user_cron system "$user_cron_entries entry/entries in $cron_user's crontab (unexpected user crontab — verify you created it)"

    # /etc/cron.d/ — flag unknown drop-ins beyond the per-box allowlist
    # (default: the standard Ubuntu entries).
    local cron_d_files
    cron_d_files=$($T /usr/bin/ls /etc/cron.d/ 2>/dev/null | /usr/bin/sort -u)
    local cron_d_allowlist
    cron_d_allowlist="$(get_cron_d_allowlist)"
    local unexpected_cron=""
    local f
    for f in $cron_d_files; do
        local known_cron=0
        for cf in $cron_d_allowlist; do
            [[ "$f" == "$cf" ]] && known_cron=1 && break
        done
        [[ $known_cron -eq 1 ]] || unexpected_cron="$unexpected_cron $f"
    done
    local ucron_count
    ucron_count=$(echo "$unexpected_cron" | /usr/bin/wc -w)
    ucron_count=${ucron_count:-0}
    [[ $ucron_count -gt 0 ]] && json_push warn system.cron_d_dropins system "unexpected drop-in(s): $(echo "$unexpected_cron" | /usr/bin/tr ' ' '\n' | /usr/bin/grep -v '^$' | /usr/bin/tr '\n' ',' | /usr/bin/sed 's/,$//')"

    # Docker containers - use Docker's own health filter (containers with no
    # HEALTHCHECK defined are correctly ignored, not false-flagged)
    if sudo_ok /usr/bin/docker; then
        local unhealthy unhealthy_names
        unhealthy_names=$($T /usr/bin/sudo /usr/bin/docker ps --filter health=unhealthy --format '{{.Names}}' 2>/dev/null)
        unhealthy=$(echo "$unhealthy_names" | grep -c . | tr -d ' \n')
        unhealthy=${unhealthy:-0}
        [[ $unhealthy -gt 0 ]] && json_push warn system.docker_unhealthy system "$unhealthy unhealthy container(s): $(echo "$unhealthy_names" | tr '\n' ' ')"
    fi

    # Apport crashes
    local crash_count
    crash_count=$(find /var/crash -maxdepth 1 -type f 2>/dev/null | wc -l)
    crash_count=${crash_count:-0}
    [[ $crash_count -gt 0 ]] && {
        local crash_files
        crash_files=$(find /var/crash -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | head -3 | tr '\n' ' ')
        json_push warn system.crash_dumps system "$crash_count crash dump(s): $crash_files"
    }

    # Kernel errors
    local kerr
    kerr=$($T /usr/bin/journalctl --since "24 hours ago" --priority=err --kernel --no-pager 2>/dev/null | grep -c "" | tr -d ' \n' || echo "0")
    kerr=${kerr:-0}
    [[ $kerr -gt 0 ]] && json_push warn system.kernel_errors system "$kerr error(s) in last 24h"
}

report_updates() {
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

    [[ $updatable -gt $UPDATE_THRESHOLD ]] && json_push info updates.upgradable updates "$updatable packages upgradable (distro: $distro · 3rd-party: $third_party)"
    [[ $security -gt 0 ]] && json_push warn updates.security_pending updates "$security security update(s) pending" "$security"
    # Delta: when yesterday's count is known, flag a security queue that
    # is GROWING — that's unattended-upgrades failing faster than it can
    # drain. The absolute check above is the signal for "any" pending.
    if [[ -n "${YESTERDAY_SECURITY_PEND:-}" ]]; then
        local sec_delta=$(( security - YESTERDAY_SECURITY_PEND ))
        [[ $sec_delta -gt 1 ]] && json_push warn updates.security_delta updates "security queue grew by $sec_delta vs yesterday (${YESTERDAY_SECURITY_PEND} → $security)" "$security"
    fi
    [[ $kernel_security -gt 0 ]] && json_push warn updates.kernel_cve updates "$kernel_security kernel security package(s) — reboot required to apply"
}

report_maintenance() {
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
        json_push warn maintenance.reboot_required maintenance "required since ${since}${reason:+ ($reason)}"
    fi

    # apt cache freshness — /var/lib/apt/periodic/update-success-stamp is
    # touched by apt-daily.timer whenever `apt update` succeeds. If it's
    # older than APT_CACHE_STALE_SECS, the script's `apt list --upgradable`
    # output could be missing recent security updates.
    if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
        local age=$(( $(/usr/bin/date +%s) - $(/usr/bin/stat -c %Y /var/lib/apt/periodic/update-success-stamp) ))
        if [[ $age -gt $APT_CACHE_STALE_SECS ]]; then
            json_push warn maintenance.apt_cache_stale maintenance "stale (${age}s / $((APT_CACHE_STALE_SECS / 3600))h since last apt update)"
        fi
    else
        json_push warn maintenance.apt_cache_stale maintenance "no update-success-stamp found — apt update has never succeeded?"
    fi

    # Timer health — apt-daily.timer and apt-daily-upgrade.timer should fire
    # at least daily. If either hasn't, unattended-upgrades isn't running.
    for t in apt-daily.timer apt-daily-upgrade.timer; do
        local last_trigger
        last_trigger=$($T /usr/bin/systemctl show "$t" --property=LastTriggerUSec --value 2>/dev/null)
        if [[ "$last_trigger" == "n/a" ]] || [[ -z "$last_trigger" ]]; then
            json_push warn maintenance.timer_drift maintenance "$t has never fired"
        else
            # LastTriggerUSec is a human-readable timestamp in modern systemd.
            # Convert to epoch seconds and compare against now.
            local last_epoch
            last_epoch=$($T /usr/bin/date -d "$last_trigger" +%s 2>/dev/null)
            if [[ -n "$last_epoch" ]] && [[ "$last_epoch" =~ ^[0-9]+$ ]]; then
                local drift=$(( $(/usr/bin/date +%s) - last_epoch ))
                if [[ $drift -gt $TIMER_DRIFT_SECS ]]; then
                    json_push warn maintenance.timer_drift maintenance "$t hasn't fired in ${drift}s ($((drift / 3600))h)"
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
            json_push warn maintenance.unattended_upgrades maintenance "no INFO line found in log"
        elif [[ $uu_age -gt $TIMER_DRIFT_SECS ]]; then
            json_push warn maintenance.unattended_upgrades maintenance "log not updated in ${uu_age}s — service may be broken"
        # NOTE: do NOT use 'echo "$uu_last" | grep -qE ...' here — the echo's
        # stdout leaks into the function's stdout, polluting the captured
        # report with the raw log line. Use a here-string so $uu_last goes
        # straight to grep's stdin without an echo.
        elif ! grep -qE "All upgrades installed|No packages found that can be upgraded unattended|kept packages can't be calculated in dry-run mode|Initial whitelist \(not strict\)" <<<"$uu_last"; then
            # Strip the timestamp prefix so the snippet fits Telegram's char
            # budget and answers "old artifact?" vs "current anomaly" at a glance.
            json_push warn maintenance.unattended_upgrades maintenance "last INFO line unexpected — $(echo "$uu_last" | /usr/bin/sed -E 's/^[^ ]+ +[0-9:,-]+ INFO //' | /usr/bin/cut -c1-100)"
        elif [[ $uu_age -gt $APT_CACHE_STALE_SECS ]] && grep -qE "Starting unattended upgrades script|Initial whitelist" <<<"$uu_last"; then
            # Log is fresh and the last line is a mid-run marker: a run is
            # in progress (or the last one died mid-flight). Freshness
            # already cleared it above, so this is informational only.
            :  # no finding — a run in progress is normal at audit time
        fi
    else
        json_push warn maintenance.unattended_upgrades maintenance "log file missing"
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
                json_push warn maintenance.kernel_restart maintenance "$kernel_line (newer kernel on disk, current kernel still running)"
            fi
            if [[ -n "$services_count" ]] && [[ "$services_count" -gt 0 ]]; then
                json_push warn maintenance.services_restart maintenance "$services_count service(s) running pre-upgrade libs (e.g. sshd, fail2ban) — restart or reboot"
            fi
        elif [[ $nr_rc -eq 1 ]]; then
            # WARNING state (e.g. microcode outdated, sessions active) — surface too.
            local warning_msg
            warning_msg=$(echo "$nr_out" | /usr/bin/head -1)
            [[ -n "$warning_msg" ]] && json_push warn maintenance.needrestart_warn maintenance "$warning_msg"
        elif [[ $nr_rc -gt 2 ]]; then
            flag_degraded "needrestart returned $nr_rc (expected 0, 1, or 2)"
        fi
    fi
}

# --- History dir + delta mode ---------------------------------------------
# Each daily run writes /var/log/box-audit/history/YYYY-MM-DD.json
# (bounded to 30 days by history_write's retention prune; see below). The
# next day's run reads yesterday's file and computes deltas (today > 2x
# yesterday AND > 5 absolute is the typical heuristic; thresholds are
# inlined in each report_* function). Day-1 has no yesterday file —
# those checks stay silent and the absolute-threshold finding above is
# the only signal (graceful degradation during the first ~24h of use).
# HISTORY_DIR itself is defined above the CLI dispatch block, next to the
# history_tail/history_diff functions it serves.

# Read yesterday's counts from the sidecar written by the prior run.
# Robust to missing / corrupt files (leaves the vars unset, which makes
# the delta checks silent).
history_load_counts() {
    local counts_file="$HISTORY_DIR/.latest-counts.json"
    [[ -r "$counts_file" ]] || return 0
    while IFS="=" read -r key val; do
        case "$key" in
            outbound_count)   YESTERDAY_OUTBOUND_COUNT="$val" ;;
            suid_count)       YESTERDAY_SUID_COUNT="$val" ;;
            security_pending) YESTERDAY_SECURITY_PEND="$val" ;;
        esac
    done < <(/usr/bin/python3 -c '
import json
try:
    d = json.load(open("'"$counts_file"'"))
    for k in ("outbound_count","suid_count","security_pending"):
        v = d.get(k, 0)
        if isinstance(v, int): print(f"{k}={v}")
except Exception:
    pass
')
}
history_load_counts

# Re-reads today's counts out of the JSON snapshot main() just printed,
# then writes a tiny sidecar the next day's delta mode reads. Both fail
# silently: history is best-effort and a missing dir must not break the
# audit. The numbers come from the JSON (single source of truth) so the
# sidecar agrees with what `--json` printed this run.
# (history_tail/history_diff live above the CLI dispatch block — they are
# dispatch targets and must be defined before the dispatch runs.)
history_persist_counts_from_json() {
    local json_text="$1"
    /usr/bin/mkdir -p "$HISTORY_DIR" 2>/dev/null || return 0
    [[ -d "$HISTORY_DIR" ]] || return 0
    /usr/bin/python3 -c '
import json, sys, datetime, socket
try:
    d = json.loads(sys.argv[1])
    out_c = sui_c = sec_c = 0
    for f in d.get("findings", []):
        cid = f.get("check_id", "")
        n = f.get("count")
        if not isinstance(n, int): continue
        if cid == "security.outbound_remote_count": out_c = n
        elif cid == "security.suid_count": sui_c = n
        elif cid == "updates.security_pending": sec_c = n
    payload = {
        "outbound_count": out_c,
        "suid_count": sui_c,
        "security_pending": sec_c,
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": socket.gethostname(),
    }
    with open("'"$HISTORY_DIR"'/.latest-counts.json","w") as fh:
        fh.write(json.dumps(payload))
except Exception:
    pass
' "$json_text" 2>/dev/null
    # Tighten perms to 0640 root:boxaudit: python's open() inherits
    # the parent umask (typically 0022 under the root systemd unit),
    # so the file would otherwise end up 0644 world-readable. Chmod
    # handles mode; chown handles group ownership for the non-systemd
    # path where the effective GID isn't boxaudit.
    /usr/bin/chmod 0640 "$HISTORY_DIR/.latest-counts.json" 2>/dev/null || true
    /usr/bin/chown :"$BOXAUDIT_GROUP" "$HISTORY_DIR/.latest-counts.json" 2>/dev/null || true
    return 0
}

# Write today's snapshot + enforce retention. The single mechanism for
# bounding /var/log/box-audit/: latest.json and .latest-counts.json are
# overwritten in place every run (no growth), so the only unbounded
# stream is history/YYYY-MM-DD.json — pruned here, right after the
# write, instead of logrotate. Logrotate would rename/compress the
# date-named files and break --diff, which looks them up by exact
# filename. Retention window: 30 days of history, which covers any
# --diff [N] a human will realistically ask for.
#
# Perm shape: 0640 root:boxaudit — readable by the boxaudit group so
# non-root users can run `box-audit --tail` / `--diff` without sudo.
# The systemd unit sets Group=boxaudit + UMask=0037 so its writes
# land at this perm naturally; the explicit chown below covers the
# non-systemd path (`sudo box-audit --json` from a shell, where
# root's effective GID is root, not boxaudit).
#
# Args: $1 = full JSON document (as printed by --json)
# Best-effort like every history operation: failures are silent.
HISTORY_RETENTION_DAYS=30
BOXAUDIT_GROUP="boxaudit"
history_write() {
    local json_text="$1"
    /usr/bin/mkdir -p "$HISTORY_DIR" 2>/dev/null || return 0
    [[ -d "$HISTORY_DIR" ]] || return 0
    # Write under a 037 umask: 0640 mode regardless of the caller's
    # umask. The integrity baseline is the documented exception —
    # 0600 because it contains /etc/shadow hashes. Subshell keeps the
    # rest of the run unaffected.
    ( umask 037; /usr/bin/printf '%s\n' "$json_text" \
        > "$HISTORY_DIR/$(/usr/bin/date -u +%Y-%m-%d).json" ) 2>/dev/null || return 0
    /usr/bin/chown :"$BOXAUDIT_GROUP" \
        "$HISTORY_DIR/$(/usr/bin/date -u +%Y-%m-%d).json" 2>/dev/null || true
    # Retention: delete snapshots older than the window. -mtime +30 =
    # strictly older than 30 days, so 31 calendar files remain.
    /usr/bin/find "$HISTORY_DIR" -maxdepth 1 -type f -name '????-??-??.json' \
        -mtime +$HISTORY_RETENTION_DAYS -delete 2>/dev/null || true
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
    # Non-root runs can't read /etc/shadow, /etc/gshadow, /etc/sudoers, or
    # /root/.ssh/authorized_keys. integrity_hash_path returns empty for
    # those, which drops them from the snapshot — the diff then reports
    # them as "removed" AND the poisoned snapshot overwrites the baseline,
    # so the next root run reports them all as "added". Skip the whole
    # check instead of corrupting it.
    if [[ $EUID -ne 0 ]]; then
        flag_degraded "not running as root — file-integrity check skipped (it would poison the baseline with false removals)"
        return
    fi

    if [[ ! -d "$INTEGRITY_BASELINE_DIR" ]]; then
        /usr/bin/mkdir -p "$INTEGRITY_BASELINE_DIR" 2>/dev/null || {
            flag_degraded "could not create $INTEGRITY_BASELINE_DIR — integrity check skipped"
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
                added)   json_push warn integrity.change integrity "added $path" ;;
                removed) json_push warn integrity.change integrity "removed $path" ;;
                changed) json_push warn integrity.change integrity "changed $path" ;;
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
            json_push info integrity.change integrity "$n crown-jewel change(s) total (baseline updated)"
        fi
    fi
}

main() {
    # File-backed findings collector — see the comment above json_push().
    # Left empty if mktemp fails; json_push then no-ops and the run
    # proceeds without findings (same graceful-degradation pattern as the
    # old DEGRADED_FILE). Every report_* call appends structured findings
    # here; the text report AND the --json document are both renderings
    # of this one list.
    FINDINGS_FILE=$(/usr/bin/mktemp 2>/dev/null) || FINDINGS_FILE=""

    check_deps

    # Call the report functions plainly: they no longer echo a text
    # report, they push findings into $FINDINGS_FILE (which survives
    # their internal command substitutions, unlike a variable would).
    report_resources
    report_security
    report_system
    report_updates
    report_maintenance
    report_integrity

    local findings_count=0
    [[ -n "$FINDINGS_FILE" && -s "$FINDINGS_FILE" ]] && findings_count=$(wc -l < "$FINDINGS_FILE" | tr -d ' ')
    local status="ok"
    [[ "$findings_count" -gt 0 ]] && status="findings"

    # --- Render text from findings (text mode AND raw_output use this) ---
    # One mapping: check_id -> emoji + label, in the fixed section order.
    # Today's per-check label text is preserved verbatim (including the
    # lowercase `fail2ban:`); findings carry label-free messages, so the
    # label is prefixed exactly once here.
    # The whole render is ONE python pass over the findings file. A
    # bash loop that spawns python3 per line costs ~200ms per finding
    # (~10s per run on a chatty box); one interpreter keeps the
    # audit's ~2s budget.
    render_text_report() {
        if [[ "$findings_count" -eq 0 ]]; then
            printf '\n=== SYSTEM HEALTH - %s ===\n' "$(date '+%Y-%m-%d %H:%M')"
            echo "✅ All clear — no issues detected"
            return 0
        fi
        printf '\n=== SYSTEM HEALTH REPORT - %s ===\n' "$(date '+%Y-%m-%d %H:%M')"
        FINDINGS_FILE="$FINDINGS_FILE" /usr/bin/python3 -c '
import json, os

EMOJI_LABEL = {
    "resources.disk_high":             ("⚠️", "DISK"),
    "resources.swap_high":             ("⚠️", "SWAP"),
    "resources.load_high":             ("⚠️", "LOAD"),
    "security.fail2ban_banned":        ("🚨", "fail2ban"),
    "security.ssh_fails":              ("⚠️", "SSH"),
    "security.sudo_fails":             ("⚠️", "sudo"),
    "security.new_port":               ("🆕", "PORT"),
    "security.outbound_remote_count":  ("🌐", "OUTBOUND"),
    "security.outbound_delta":         ("🌐", "OUTBOUND-DELTA"),
    "security.suid_count":             ("🔓", "SUID"),
    "security.suid_delta":             ("🔓", "SUID-DELTA"),
    "system.failed_units":             ("🔴", "SYSTEMD"),
    "system.custom_timers":            ("⏰", "CUSTOM-TIMERS"),
    "system.user_cron":                ("📅", "USER-CRON"),
    "system.cron_d_dropins":           ("📅", "/etc/cron.d/"),
    "system.docker_unhealthy":         ("🔴", "DOCKER"),
    "system.crash_dumps":              ("💥", "CORES"),
    "system.kernel_errors":            ("🔴", "KERNEL"),
    "updates.upgradable":              ("📦", "UPDATES"),
    "updates.security_pending":        ("🔒", "SECURITY"),
    "updates.security_delta":          ("🔒", "SECURITY-DELTA"),
    "updates.kernel_cve":              ("🛡️", "KERNEL-CVE"),
    "maintenance.reboot_required":     ("🔁", "REBOOT"),
    "maintenance.apt_cache_stale":     ("⏳", "APT-CACHE"),
    "maintenance.timer_drift":         ("⏰", "TIMER"),
    "maintenance.unattended_upgrades": ("⏰", "UNATTENDED-UPGRADES"),
    "maintenance.kernel_restart":      ("🛡️", "KERNEL-RESTART"),
    "maintenance.services_restart":    ("🔄", "SERVICES-RESTART"),
    "maintenance.needrestart_warn":    ("⚠️", "NEEDRESTART-WARN"),
    "integrity.change":                ("🔒", "INTEGRITY"),
    "degraded.check":                  ("❓", "DEGRADED"),
}
SECTION_ORDER = ["resources", "security", "system", "updates", "maintenance", "integrity"]
SECTION_RANK = {s: i for i, s in enumerate(SECTION_ORDER)}

findings = []
with open(os.environ["FINDINGS_FILE"]) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            continue

# Section order first, then insertion order within a section.
findings.sort(key=lambda f: SECTION_RANK.get(f.get("section", ""), len(SECTION_ORDER)))
for f in findings:
    emoji, label = EMOJI_LABEL.get(f.get("check_id", ""), (None, None))
    if emoji is None:
        continue
    msg = f.get("message", "")
    print(f"{emoji} {label}: {msg}")
' 2>/dev/null
    }

    if [[ "$OUTPUT_MODE" == "json" ]]; then
        # Both JSON fields come from the same findings file: findings is
        # the raw JSON lines joined with commas; raw_output is the
        # rendered text (identical to what text mode prints).
        local rendered_text findings_array_json raw_output_json full_json
        rendered_text=$(render_text_report)
        findings_array_json=""
        [[ -n "$FINDINGS_FILE" && -s "$FINDINGS_FILE" ]] && findings_array_json=$(paste -sd, "$FINDINGS_FILE")
        raw_output_json=$(/usr/bin/printf '%s' "$rendered_text" | /usr/bin/python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
        full_json=$(/usr/bin/printf '{"status":"%s","timestamp":"%s","host":"%s","findings":[%s],"raw_output":%s}\n' \
            "$status" \
            "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "$(/usr/bin/hostname)" \
            "$findings_array_json" \
            "$raw_output_json")
        /usr/bin/printf '%s' "$full_json"
        # History write: copy the day's snapshot to history/YYYY-MM-DD.json
        # so --tail/--diff and tomorrow's delta mode have something to read.
        history_write "$full_json" || true
        # Persist the per-day count sidecar for delta mode tomorrow.
        # Best-effort: a failing write is silent (history dir is optional).
        history_persist_counts_from_json "$full_json" || true
        # Always exit 0 in JSON mode — the JSON itself encodes "status:ok"
        # vs "status:findings", so callers can branch on that instead of
        # the exit code. This matters because pipefail in shells / systemd
        # units would otherwise treat exit-1 (findings) as a failure even
        # though the JSON was produced correctly.
        return 0
    fi

    render_text_report
    [[ "$findings_count" -gt 0 ]] && return 1
    return 0
}

main
