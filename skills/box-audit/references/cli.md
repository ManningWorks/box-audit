# box-audit CLI reference

A flag, a sentence, an example. For narrative install + delivery see the
README; for triage methodology see `SKILL.md` § 2–3.

All flags exit 0 on success, 2 on bad input. Manage flags (`--init`,
`--accept-port`, `--accept-timer`, `--outbound-threshold`) require root
(`sudo`). The audit flags (`--json`, `--text`, `--version`) do not.

## Audit flags

| Flag | Default behavior | Output |
|---|---|---|
| (no flag) | Human-readable emoji-coded report to stdout | text |
| `--json` | Machine-readable JSON to stdout. Always exits 0; the JSON body's `status` field is the signal (`"ok"` or `"findings"`). | JSON |
| `--text` | Forces human-readable output (the default). | text |
| `--version` | Prints `box-audit X.Y.Z` and exits. The version comes from `/usr/local/share/box-audit/version`, written by `install.sh`. | text |
| `--check-groups` | Diagnoses stale group membership (issue #32): does this process's group list contain the boxaudit gid, and which of the invoking user's own long-running processes lack it? Read-only — never restarts, signals, or re-execs anything. Exits 0 either way: "stale" is a finding, not a failure. | text |
| `-h`, `--help` | Prints the usage block and exits. | text |

Exit codes for the audit (not the manage flags): `0` = all clear,
`1` = findings present, `2` = unknown flag. `--json` always exits 0.

## Stale-group self-diagnosis (`--check-groups`)

Supplementary groups are resolved at exec time, so a long-running process
started before `usermod -aG boxaudit` keeps hitting Permission denied on
the 0640 root:boxaudit outputs even after /etc/group is correct. Under
`systemd --user`, processes inherit groups from the user-manager (started
at login), so a bare consumer restart may not be enough — run
`systemctl --user daemon-reexec` first, or log out and back in.

`sudo box-audit --check-groups` reports, for the invoking user only:

1. Whether the invoking process's own group list (`/proc/self/status`,
   `Groups:` line, whole-token gid match) contains the boxaudit gid.
2. Which of the user's OWN processes older than `STALE_PROC_MIN_AGE`
   seconds (default 3600) still lack it — pid, name, age.

Observe-never-remediate: it diagnoses; it never kills, restarts, or
re-execs anything. A whole-box scan of other users' processes is the
installer's job at install time, not this flag's.

## Manage flags (per-box config under /var/lib/box-audit/)

Each runs as root, writes a single config file, exits 0. Argument
validation runs *before* the root check, so a bad value is reported
regardless of EUID.

| Flag | Argument | What it does |
|---|---|---|
| `--init` | none | Snapshots the box's current state into all five config files: currently-listening ports → `ports-allowlist.txt`; active `*.timer` units → `timers-baseline.txt`; current `/etc/cron.d/` entries (plus the four standard names) → `cron-d-allowlist.txt`; outbound threshold reset to 25 → `outbound-threshold.conf`; SUID threshold seeded at 30 → `suid-threshold.conf`. Idempotent — safe to re-run. |
| `--accept-port` | integer 1–65535 | Appends the port to `ports-allowlist.txt`. Refuses duplicates. Use after the audit flags a port you want to keep. |
| `--accept-timer` | name (e.g. `lynis`) | Appends `<name>.timer` to `timers-baseline.txt`. Accepts both `name` and `name.timer`. |
| `--outbound-threshold` | positive integer | Writes the new threshold to `outbound-threshold.conf`. The OUTBOUND finding fires only when today's count exceeds this; daily-delta awareness (PR 3) further narrows that to 2× yesterday, when yesterday exists. |

## File layout

```
/var/lib/box-audit/
├── ports-allowlist.txt       one port per line; # comments OK
├── timers-baseline.txt       one <name>.timer per line; # comments OK
├── outbound-threshold.conf   single non-negative integer
├── cron-d-allowlist.txt      one /etc/cron.d/ name per line; # comments OK
├── suid-threshold.conf       single positive integer (SUID finding threshold)
├── integrity-baseline.json   sha256s of /etc/passwd, sudoers, etc.
│                             (created by the audit's first run as root;
│                             not touched by install.sh)
```

When a file is missing, the audit uses a small built-in fallback (so the
script never breaks) and prints a one-time stderr notice pointing at
`--init`. Behavior is identical to a freshly-installed Ubuntu desktop,
modulo the per-box defaults.
