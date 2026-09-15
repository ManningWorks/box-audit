#!/usr/bin/env python3
"""Snapshot a live box's external-tool outputs into test/fixtures/.

Record-once, freeze-forever: run this on the live box (the NucBox) when a
fixture needs (re)recording, commit the refreshed corpus as a dedicated
fixture-refresh PR, and never hand-edit fixtures afterwards. When the live
format drifts and a property test fails, the fix is a re-record plus diff
review — not a test workaround.

Usage (on the live box, as root — most inputs are root-only):

    sudo python3 test/fixtures/snapshot-fixtures.py --dry-run   # preview
    sudo python3 test/fixtures/snapshot-fixtures.py             # record

Not every fixture can be recorded mechanically:

  - apt-update-stamp-fresh / -stale are empty files whose mtime carries the
    signal; after recording, `touch` the fresh one and
    `touch -d '4 days ago'` the stale one.
  - crontab-empty / crontab-with-entries were hand-seeded from real
    crontab(5) format; re-record with `crontab -l` if a real crontab
    exists, else keep the seeded pair.
  - integrity-baseline.json / integrity-changed.json are deliberately
    synthetic (real hashes would freeze one box's crown-jewel state into
    a public repo). Their only contract is the shape integrity_snapshot()
    emits: a single JSON line of "path": "sha256" pairs.
  - journalctl-ssh-auth-fail-empty.txt is the empty-journal variant; the
    populated variant needs real auth failures in the window, so it is
    seeded from real journal line format unless the box actually has some.

All external IPs are documentation ranges (RFC 5737: 192.0.2.0/24,
203.0.113.0/24) so the corpus stays safe in a public repo. Scrub anything
the box emits that is not a documentation IP before committing.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent

# fixture name -> command whose stdout IS the fixture.
RECORDINGS = {
    "df-output.txt": [
        "df", "-h", "/", "--output=source,size,used,avail,pcent",
        "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs",
    ],
    "loadavg.txt": ["cat", "/proc/loadavg"],
    "ss-tln.txt": ["ss", "-tlnp"],
    "systemctl-failed-units.txt": [
        "systemctl", "list-units", "--type=service", "--state=failed",
        "--no-legend", "--plain", "--no-pager",
    ],
    "journalctl-ssh-auth-fail.txt": [
        "journalctl", "--since", "24 hours ago", "--facility=auth",
        "--no-pager",
    ],
    "fail2ban-status.txt": ["fail2ban-client", "status", "sshd"],
    "swap.txt": ["grep", "-E", "^(MemTotal|SwapCached|SwapTotal|SwapFree):",
                 "/proc/meminfo"],
}


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # A failing recording must stop the snapshot: half-refreshed
        # fixtures are worse than stale ones.
        sys.exit(f"snapshot-fixtures: '{' '.join(cmd)}' exited "
                 f"{result.returncode}: {result.stderr.strip()}")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true",
                        help="print the commands instead of recording")
    args = parser.parse_args()

    if args.dry_run:
        for name, cmd in RECORDINGS.items():
            print(f"{name:38} <- {' '.join(cmd)}")
        return

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("snapshot-fixtures: must run as root (journalctl, "
                 "fail2ban-client, ss -p need it)")

    for name, cmd in RECORDINGS.items():
        (FIXTURES / name).write_text(run(cmd))
        print(f"recorded {name}")


if __name__ == "__main__":
    main()
