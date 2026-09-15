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
| `-h`, `--help` | Prints the usage block and exits. | text |

Exit codes for the audit (not the manage flags): `0` = all clear,
`1` = findings present, `2` = unknown flag. `--json` always exits 0.

## Manage flags (per-box config under /var/lib/box-audit/)

Each runs as root, writes a single config file, exits 0. Argument
validation runs *before* the root check, so a bad value is reported
regardless of EUID.

| Flag | Argument | What it does |
|---|---|---|
| `--init` | none | Snapshots the box's current state into all three config files: currently-listening ports → `ports-allowlist.txt`; active `*.timer` units → `timers-baseline.txt`; outbound threshold reset to 25. Idempotent — safe to re-run. |
| `--accept-port` | integer 1–65535 | Appends the port to `ports-allowlist.txt`. Refuses duplicates. Use after the audit flags a port you want to keep. |
| `--accept-timer` | name (e.g. `lynis`) | Appends `<name>.timer` to `timers-baseline.txt`. Accepts both `name` and `name.timer`. |
| `--outbound-threshold` | positive integer | Writes the new threshold to `outbound-threshold.conf`. The OUTBOUND finding fires only when today's count exceeds this; daily-delta awareness (PR 3) further narrows that to 2× yesterday, when yesterday exists. |

## File layout

```
/var/lib/box-audit/
├── ports-allowlist.txt       one port per line; # comments OK
├── timers-baseline.txt       one <name>.timer per line; # comments OK
├── outbound-threshold.conf   single non-negative integer
├── integrity-baseline.json   sha256s of /etc/passwd, sudoers, etc.
│                             (created by the audit's first run as root;
│                             not touched by install.sh)
└── README.md                 (planned for PR 4 — agent-facing notes)
```

When a file is missing, the audit uses a small built-in fallback (so the
script never breaks) and prints a one-time stderr notice pointing at
`--init`. Behavior is identical to a freshly-installed Ubuntu desktop,
modulo the per-box defaults.
