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
| `--json` | Machine-readable JSON to stdout. Exits 0 on a run that executes — the JSON body's `status` field is the signal (`"ok"` or `"findings"`); a refused run (lock dir unopenable) exits 75 with no JSON on stdout. A contended lock (flock held by another instance): the run is skipped and exits 0 with no JSON on stdout — the single-instance guard working as designed. | JSON |
| `--text` | Forces human-readable output (the default). | text |
| `--version` | Prints `box-audit X.Y.Z` and exits. The version comes from `/usr/local/share/box-audit/version`, written by `install.sh`. | text |
| `--check-groups` | Diagnoses stale group membership (issue #32): does this process's group list contain the boxaudit gid, and which of the invoking user's own long-running processes lack it? Read-only — never restarts, signals, or re-execs anything. Exits 0 either way: "stale" is a finding, not a failure. | text |
| `-h`, `--help` | Prints the usage block and exits. | text |

Exit codes for the audit (not the manage flags): `0` = all clear,
`1` = findings present, `2` = unknown flag, `75` = lock file unopenable
(read-only lock dir) — the run was refused before any check ran, so the
non-zero exit is the signal. `--json` always exits 0 on a run that
actually executes; a refused run exits 75 with no JSON on stdout.
A contended lock (flock held by another instance): the run is skipped and
exits 0 with no JSON on stdout (the warning on stderr is the signal) —
the single-instance guard working as designed.

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
| `--init` | none | Snapshots the box's current state into all five config files: currently-listening ports → `ports-allowlist.txt`; active `*.timer` units → `timers-baseline.txt`; current `/etc/cron.d/` entries (plus the four standard names) → `cron-d-allowlist.txt`; outbound threshold reset to 25 → `outbound-threshold.conf`; SUID threshold seeded at 30 → `suid-threshold.conf`. Idempotent — safe to re-run. Reports what happened: `box-audit: config unchanged at /var/lib/box-audit` when every file already held exactly what a fresh snapshot would write, or `box-audit: seeded <files>` when it rewrote one or more. |
| `--accept-port` | integer 1–65535 | Appends the port to `ports-allowlist.txt`. Refuses duplicates. Use after the audit flags a port you want to keep. |
| `--accept-timer` | name (e.g. `lynis`) | Appends `<name>.timer` to `timers-baseline.txt`. Accepts both `name` and `name.timer`. |
| `--accept-cron-d` | name (e.g. `0mycron`) | Appends the `/etc/cron.d/` entry name to `cron-d-allowlist.txt`. Refuses duplicates. Use after the audit flags an unexpected drop-in. |
| `--outbound-threshold` | positive integer | Writes the new threshold to `outbound-threshold.conf`. The OUTBOUND finding fires only when today's count exceeds this; daily-delta awareness (PR 3) further narrows that to 2× yesterday, when yesterday exists. The IPv6 finding (`security.outbound_remote_count_v6`) shares this knob — raising the threshold quiets both families at once. |
| `--suid-threshold` | positive integer | Writes the new threshold to `suid-threshold.conf`. The SUID finding (`security.suid_count`) fires only when the on-disk SUID count exceeds this. Use after the audit flags a box with a legitimately-high SUID set. |

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
