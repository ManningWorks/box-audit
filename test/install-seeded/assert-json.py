#!/usr/bin/env python3
"""
Tier-2 seeded-container JSON assertion script (issue #17).

Reads `box-audit --json` output from stdin and asserts that the
expected check_ids appear with expected severities, and (where useful)
that the finding message contains a regex.

Eight check_ids are asserted — one per seeded-state condition the
driver (test/install-seeded.sh) sets up in the container:

    security.new_port          (warn)  -> port 9999 listening
    security.fail2ban_banned   (alert) -> one IP banned on sshd
    security.ssh_fails         (warn)  -> >15 auth-fail journal lines
    system.cron_d_dropins       (warn)  -> /etc/cron.d/0box-audit-test
    system.user_cron            (warn)  -> non-empty root crontab
    system.failed_units         (warn)  -> box-audit-fail.service
    maintenance.apt_cache_stale (warn)  -> stamp file >48h old
    integrity.change            (warn)  -> /etc/passwd mutated vs baseline

Top-level JSON contract (status, timestamp, host, findings) is also
verified — same shape the install-ci tier-1 job implicitly relies on.

Exit codes:
    0  all assertions passed
    1  one or more assertions failed (printed to stderr)
    2  JSON parsing or top-level contract failed (blocker; one
       bad-shape emission shouldn't be papered over by individual
       finding checks)

The CI job's negative variant (integration-seeded-regression) sed-mutates
seed.sh to skip the cron-d drop step; this script then sees no
system.cron_d_dropins finding, fails, and the workflow inverts the
failure into a pass — proving the gate has teeth.
"""
from __future__ import annotations

import json
import re
import sys

EXPECTED: list[tuple[str, str, str | None]] = [
    # (check_id, severity, message_regex_or_None)
    # NOTE on integrity.change: report_integrity emits one finding per
    # changed crown-jewel path AND an aggregate `info` summary when
    # >=2 paths changed. Asserting count==1 here would over-constrain
    # the audit. We check that at least one finding matches the
    # message we seeded and ignore the per-check_id strict count.
    ("security.new_port", "warn", r"9999"),
    ("security.fail2ban_banned", "alert", r"banned on sshd"),
    ("security.ssh_fails", "warn", r"failed auth attempts"),
    ("system.cron_d_dropins", "warn", r"0box-audit-test"),
    ("system.user_cron", "warn", r"root's crontab"),
    ("system.failed_units", "warn", r"box-audit-fail"),
    ("maintenance.apt_cache_stale", "warn", r"stale"),
    ("integrity.change", "warn", r"changed /etc/passwd"),
]
# check_ids where the audit legitimately emits more than one finding
# per run (one per changed path + an aggregate summary). Skip the
# strict-count check for these — see EXPECTED comment above.
MULTI_FINDING_IDS: set[str] = {"integrity.change"}


def main() -> int:
    raw = sys.stdin.read()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"FAIL: --json output is not valid JSON: {e}", file=sys.stderr)
        return 2

    # Top-level contract — same shape the smoke harness asserts.
    missing = [k for k in ("status", "timestamp", "host", "findings")
               if k not in doc]
    if missing:
        print(f"FAIL: --json missing top-level keys: {missing}", file=sys.stderr)
        return 2

    findings = doc.get("findings", [])
    if not isinstance(findings, list):
        print("FAIL: --json 'findings' is not a list", file=sys.stderr)
        return 2

    # Index findings by check_id for O(1) lookup; the script never
    # emits more than one finding per check_id today, but if that
    # ever changes the assertions will surface it (the dedup-by-id
    # step below).
    by_id: dict[str, list[dict]] = {}
    for f in findings:
        cid = f.get("check_id")
        if not cid:
            print(f"FAIL: a finding has no check_id: {f}", file=sys.stderr)
            return 2
        by_id.setdefault(cid, []).append(f)

    failures = 0
    for check_id, expected_sev, msg_re in EXPECTED:
        matches = by_id.get(check_id, [])
        if not matches:
            print(f"FAIL: missing check_id {check_id}", file=sys.stderr)
            failures += 1
            continue
        if check_id not in MULTI_FINDING_IDS and len(matches) > 1:
            print(f"FAIL: {check_id} appears {len(matches)} times "
                  f"(expected 1): {matches}", file=sys.stderr)
            failures += 1
            continue
        # For multi-finding IDs, assert severity on AT LEAST ONE match.
        # For single-finding IDs, matches[0] is the only one.
        sev_ok = False
        sev_match = None
        for m in matches:
            if m.get("severity") == expected_sev:
                sev_ok = True
                sev_match = m
                break
        if not sev_ok:
            print(f"FAIL: {check_id} no finding has severity={expected_sev!r} "
                  f"(got: {[m.get('severity') for m in matches]})",
                  file=sys.stderr)
            failures += 1
            continue
        f = sev_match if sev_match is not None else matches[0]
        if msg_re is not None:
            msg = f.get("message", "")
            if not re.search(msg_re, msg):
                print(f"FAIL: {check_id} message={msg!r} "
                      f"does not match /{msg_re}/", file=sys.stderr)
                failures += 1
                continue
        print(f"PASS: {check_id} severity={f.get('severity')} "
              f"message={f.get('message', '')!r}")

    if failures:
        print(f"\nseeded: {len(EXPECTED) - failures}/{len(EXPECTED)} "
              f"check_ids passed, {failures} failed", file=sys.stderr)
        return 1
    print(f"\nseeded: {len(EXPECTED)}/{len(EXPECTED)} check_ids passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())