# Replay fixture corpus — `*_delta` checks

Each subdirectory is a **self-contained replay corpus**: a pair of
`--json`-shaped daily snapshots (real historical dates, lex sort =
chronological) that `scripts/box-audit.sh --replay <dir> --diff 1`
compares with presence-based findings diffing. The property suite
(`test/properties/security.suid_delta.sh`,
`security.outbound_delta.sh`, `updates.security_delta.sh`) runs each
corpus through both branches of its delta:

- `<check_id>/` — **positive**: the finding exists only in the today
  snapshot, so `--diff 1` reports it as `+ ADDED` and the property
  test asserts the delta fired.
- `negative-*-stable/` — **negative**: identical snapshots. The delta
  finding is either on both days or on neither, so diffing reports no
  change and the property test asserts the delta did NOT fire. This is
  the fixture that proves the test's teeth.

## Check → directory map

| Directory | Check_id | Delta rule (from `--print-schema`) | Encoded scenario |
|---|---|---|---|
| `security-suid_delta/` | `security.suid_delta` | today suid − yesterday suid > 2 | 21 → 24 SUID binaries (+3) |
| `security-outbound_delta/` | `security.outbound_delta` | today > 2x yesterday AND > 5 absolute | 0 → 6 non-LAN remote IPs |
| `updates-security_delta/` | `updates.security_delta` | security queue grew by over 1 vs yesterday | 1 → 4 security updates pending |
| `negative-suid-stable/` | `security.suid_delta` | same | 21 → 21 (no delta) |
| `negative-outbound-stable/` | `security.outbound_delta` | same | 3 → 3 (steady, no delta) |
| `negative-security-stable/` | `updates.security_delta` | same | 1 → 1 (drained-and-refilled steady state) |

## Why the messages look like real findings

Snapshot findings are byte-shaped like what `json_push` emits for the
corresponding live check (severity, check_id, section, message,
count), and the `counts` block mirrors the live `--json` shape (issue
#38): `suid_count`, `outbound_remote_count`, `security_pending`
populated from the live measurement regardless of threshold. A future
format drift in either the diff renderer or the finding shape breaks
these tests loudly instead of silently passing an invented shape.
