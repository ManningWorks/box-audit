#!/bin/bash
# notify-webhook.sh — optional push delivery for box-audit.
#
# Reads the latest audit snapshot and POSTs it as a JSON body to
# $BOX_AUDIT_WEBHOOK_URL. Works with any incoming-webhook endpoint that
# accepts a JSON POST: Discord webhook, Telegram bot via a relay, ntfy, etc.
#
# Configure the URL either via the environment or /etc/default/box-audit:
#
#   # /etc/default/box-audit
#   BOX_AUDIT_WEBHOOK_URL=https://your-webhook.example.com/audit
#
# Wire it into the daily run with a systemd drop-in (do NOT edit the unit —
# a package-style update to the unit file would clobber that):
#
#   sudo systemctl edit box-audit.service
#
# and add:
#
#   [Service]
#   ExecStartPost=/usr/local/bin/notify-webhook.sh
#
# ExecStartPost runs after the main process exits, so the snapshot it reads
# is the fresh one from this run. Do NOT pipe box-audit into this script in
# a replaced ExecStart: the pipe consumes the run's output, this script
# doesn't read stdin, and the unit's StandardOutput=truncate: capture would
# then clobber latest.json with this script's (empty) stdout.
#
# BOX_AUDIT_NOTIFY_MIN_SEVERITY (optional): suppress findings below this
# severity so a healthy box stops pushing routine state. Valid values:
#   info  nothing suppressed (same as unset — the default)
#   warn  warn + crit pushed, info suppressed
#   crit  crit pushed only
# "crit" is the top of the threshold scale; on the finding scale it maps
# onto `alert` (the top content severity). `degraded` findings are never
# suppressed — they report that a check could not run, and a quiet webhook
# that hides blindedness is worse than a noisy one. Whenever the filter
# actually runs, a `suppressed N findings` count is logged to stderr. An
# invalid value exits non-zero before anything is POSTed.

set -euo pipefail

LATEST="${1:-/var/log/box-audit/latest.json}"
POST_FILE="$LATEST"

# /etc/default/box-audit is the systemd EnvironmentFile convention; source it
# only for the variable we need, so a stray line there can't execute broadly.
if [[ -z "${BOX_AUDIT_WEBHOOK_URL:-}" && -f /etc/default/box-audit ]]; then
    BOX_AUDIT_WEBHOOK_URL="$(grep -E '^BOX_AUDIT_WEBHOOK_URL=' /etc/default/box-audit | head -1 | cut -d= -f2-)"
fi

[[ -n "${BOX_AUDIT_WEBHOOK_URL:-}" ]] || {
    echo "notify-webhook: BOX_AUDIT_WEBHOOK_URL not set (env or /etc/default/box-audit)" >&2
    exit 1
}
[[ -r "$LATEST" ]] || { echo "notify-webhook: cannot read $LATEST" >&2; exit 1; }
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$LATEST" \
    || { echo "notify-webhook: $LATEST is not valid JSON" >&2; exit 1; }

# Optional severity floor (F3). Validation runs first so a typo fails
# loudly before anything is rewritten or POSTed. Unset and "info" are the
# pass-through default; "warn"/"crit" filter findings[] through a temp
# file so the POSTed body carries only findings at or above the threshold
# — the on-disk snapshot is never touched.
MIN_SEV="${BOX_AUDIT_NOTIFY_MIN_SEVERITY:-}"
case "$MIN_SEV" in
    "" | info | warn | crit) ;;
    *)
        echo "notify-webhook: invalid BOX_AUDIT_NOTIFY_MIN_SEVERITY '$MIN_SEV' (expected info, warn or crit)" >&2
        exit 1
        ;;
esac

if [[ -n "$MIN_SEV" && "$MIN_SEV" != "info" ]]; then
    POST_FILE="$(mktemp "${TMPDIR:-/tmp}/box-audit-notify.XXXXXXXX")"
    # shellcheck disable=SC2064 # we want $POST_FILE expanded now, at trap-set time
    trap "rm -f '$POST_FILE'" EXIT
    if ! SUPPRESSED="$(BOX_AUDIT_NOTIFY_TMP="$POST_FILE" python3 - "$LATEST" "$MIN_SEV" <<'PY'
import json, os, sys

# Severity ordering is crit > warn > info. "crit" is the top of the
# threshold scale and maps onto the top finding severity: anything the
# rank table doesn't know (e.g. an unexpected new severity) ranks as
# top, so a filter change never silently suppresses a severity it
# doesn't understand.
rank = {"info": 0, "warn": 1, "crit": 2}
threshold = sys.argv[2]
payload = json.load(open(sys.argv[1]))
before = len(payload.get("findings", []))
kept = [
    f for f in payload.get("findings", [])
    if rank.get(f.get("severity"), 2) >= rank[threshold]
]
payload["findings"] = kept
with open(os.environ["BOX_AUDIT_NOTIFY_TMP"], "w") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
print(before - len(kept))
PY
)"; then
        echo "notify-webhook: failed to filter findings below $MIN_SEV threshold" >&2
        exit 1
    fi
    echo "notify-webhook: suppressed $SUPPRESSED findings below $MIN_SEV threshold" >&2
fi

curl -fsS -X POST \
    -H "Content-Type: application/json" \
    --data-binary "@$POST_FILE" \
    "$BOX_AUDIT_WEBHOOK_URL" > /dev/null
