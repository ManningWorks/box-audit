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
#   ExecStart=
#   ExecStart=/bin/sh -c '/usr/local/bin/box-audit --json | /usr/local/bin/notify-webhook.sh'
#
# (The empty ExecStart= clears the default before the replacement — systemd
# requires both lines.) Then: sudo systemctl daemon-reload.

set -euo pipefail

LATEST="${1:-/var/log/box-audit/latest.json}"

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

curl -fsS -X POST \
    -H "Content-Type: application/json" \
    --data-binary "@$LATEST" \
    "$BOX_AUDIT_WEBHOOK_URL" > /dev/null
