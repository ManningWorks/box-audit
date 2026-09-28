#!/usr/bin/env bash
# security.outbound_remote_count_v4 — the v4 side of the combined
# security.outbound_remote_count finding.
#
# The live check reads `ss -tnp state established` and resolves the
# remote (peer) column. The IPv4 path historically hardcoded field $5 —
# the pre-6.x layout. iproute2 6.x suppresses the constant State column
# and shifts the peer to field 4, so the hardcoded $5 read the wrong
# column and returned nothing: the v4 outbound check went blind on any
# box running iproute2 6.x (issue #53). The IPv6 path was already
# header-driven via ss_peer_column; this test pins the IPv4 path to the
# same header-driven resolution.
#
# Unlike security.outbound_remote_count_v6.sh (which asserts the finding's
# replay semantics against a JSON corpus), the v4 bug lives in the column
# extraction itself, so this test exercises the real extraction function
# against 5.x- and 6.x-shaped ss captures. It pulls the two pure helpers
# (ss_peer_column, ss_v4_remote_ips) straight out of scripts/box-audit.sh
# — the same sed-extract idiom the repo uses in its probes — so the test
# runs production logic, not a copy, without invoking the script's
# arg-parse / lock gate / main.
set -u
# assert.sh is sourced via a computed path, so shellcheck cannot follow it.
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assert.sh"

[[ -n "${BA_PROP_SCHEMA_FILE:-}" ]] || { fail "BA_PROP_SCHEMA_FILE not set — run via run.sh"; props_done "security.outbound_remote_count_v4"; exit 1; }

# Pull the real header-resolution + v4 extraction helpers from the current
# script. Both are defined at column 0 with a column-0 closing brace, so
# the range anchors are unambiguous.
# shellcheck disable=SC2046  # eval of a script we control, by design
eval "$(sed -n '/^ss_peer_column() {/,/^}/p' "$SCRIPT")"
# shellcheck disable=SC2046
eval "$(sed -n '/^ss_v4_remote_ips() {/,/^}/p' "$SCRIPT")"

# The header-driven v4 extraction is the feature under test. If it is
# missing from box-audit.sh the suite is RED — that is the bug.
if ! type -t ss_v4_remote_ips >/dev/null 2>&1; then
    fail "ss_v4_remote_ips not found in box-audit.sh (header-driven v4 peer extraction is missing — issue #53)"
    props_done "security.outbound_remote_count_v4"
    exit 1
fi

# 1. schema contract — the combined (v4-inclusive) finding is registered.
assert_grep "combined check_id in --print-schema" \
    '"security\.outbound_remote_count"' "$BA_PROP_SCHEMA_FILE"

# 2. 5.x capture — State column present, peer in field 5. This is the
#    pre-6.x layout the historical $5 was written for; the fix must keep
#    the 5.x result byte-identical (column 5).
SS_5X='State   Recv-Q Send-Q Local Address:Port Peer Address:Port
ESTAB  0      0      192.168.50.231:50490 198.51.100.100:443
ESTAB  0      0      192.168.50.231:50492 198.51.100.101:443'

# 3. 6.x capture — State suppressed, peer shifted left to field 4. This is
#    the layout iproute2 6.x emits; the hardcoded $5 read empty here and
#    the check went blind.
SS_6X='Recv-Q Send-Q Local Address:Port Peer Address:Port
0      0      192.168.50.231:50490 198.51.100.100:443
0      0      192.168.50.231:50492 198.51.100.101:443'

# The peer column must resolve per layout: 5 on 5.x, 4 on 6.x.
COL_5X=$(printf '%s\n' "$SS_5X" | ss_peer_column)
assert_eq "5.x header resolves the peer to column 5 (historical \$5)" "5" "$COL_5X"
COL_6X=$(printf '%s\n' "$SS_6X" | ss_peer_column)
assert_eq "6.x header resolves the peer to column 4 (State suppressed)" "4" "$COL_6X"

# 4. 5.x extraction — both doc-range v4 remotes, byte-identical to the
#    historical $5 result.
V4_5X=$(printf '%s\n' "$SS_5X" | ss_v4_remote_ips)
assert_eq "5.x capture: both v4 remotes extracted (byte-identical to historical \$5)" \
    "$(printf '198.51.100.100\n198.51.100.101')" "$V4_5X"

# 5. 6.x extraction — the fix. Same two remotes, now found in field 4.
#    On the old hardcoded $5 this returned nothing (blind).
V4_6X=$(printf '%s\n' "$SS_6X" | ss_v4_remote_ips)
assert_eq "6.x capture: both v4 remotes extracted (was blind on hardcoded \$5)" \
    "$(printf '198.51.100.100\n198.51.100.101')" "$V4_6X"

# 6. negative — a v6-only 6.x capture has no v4 remotes; the v4 extraction
#    must stay empty (a v6 box must not read as a v4 beacon).
SS_V6ONLY='Recv-Q Send-Q Local Address:Port Peer Address:Port
0      0      [fe80::5]:50492 [2001:db8::100]:443'
V6ONLY=$(printf '%s\n' "$SS_V6ONLY" | ss_v4_remote_ips)
assert_eq "v6-only capture: no v4 remotes (v4 check stays quiet)" "" "$V6ONLY"

# 7. negative — a 6.x capture mixing a v4 peer and a v6 peer in the same
#    stream: only the v4 address is returned, the bracketed v6 peer does
#    not leak into the v4 result.
SS_MIXED='Recv-Q Send-Q Local Address:Port Peer Address:Port
0      0      192.168.50.231:50490 198.51.100.100:443
0      0      [fe80::5]:50492    [2001:db8::100]:443'
MIXED=$(printf '%s\n' "$SS_MIXED" | ss_v4_remote_ips)
assert_eq "mixed v4+v6 capture: only the v4 remote is returned" \
    "198.51.100.100" "$MIXED"

props_done "security.outbound_remote_count_v4"
