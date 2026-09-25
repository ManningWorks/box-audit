# Fixture corpus

One file per external tool that box-audit parses. These are the inputs the
property suite (and, from T03, the seeded-container CI job) feed the audit
script, so they must be **real tool output shapes** — never an invented
format. A fixture shaped like a real journal line makes a meaningful
property test; one shaped like a guess at a journal line tests nothing.

## Record-once, freeze-forever

Fixtures are snapshots of one box's tool outputs at a point in time
(recorded via [`snapshot-fixtures.py`](snapshot-fixtures.py), hand-seeded
where a live box can't produce a variant). When real tool output drifts
and a test fails, the fix is a **fixture-refresh PR**: re-record with the
script, review the diff, land it. Never edit a fixture to make a test
pass — that hides real format drift from the suite.

All IPs in this corpus are documentation ranges (RFC 5737: `192.0.2.0/24`,
`203.0.113.0/24`); hostnames are the NucBox's. Scrub anything else before
committing a refresh — the repo is public.

## The fixtures

| Fixture | Source | Notes |
|---|---|---|
| `df-output.txt` | `df -h / --output=source,size,used,avail,pcent -x tmpfs -x devtmpfs -x squashfs` | First data row is the real NucBox root (11%, below the 85% warn threshold); the second row is a same-shape row above threshold so both sides of `resources.disk_high` are documented in one file. |
| `loadavg.txt` | `cat /proc/loadavg` | Real content, 1-min load below the 3.0 `resources.load_high` threshold. |
| `loadavg-high.txt` | same | Same shape, 1-min load above 3.0. |
| `swap.txt` | `grep -E '^(MemTotal\|SwapCached\|SwapTotal\|SwapFree):' /proc/meminfo` | Real content; swap effectively unused (below the 70% `resources.swap_high` threshold). `free`'s swap line is derived from these fields. |
| `swap-high.txt` | same | Same shape with ~76% swap used (above threshold). |
| `journalctl-ssh-auth-fail.txt` | `journalctl --since "24 hours ago" --facility=auth --no-pager` | Three real-format `Failed password` lines (the exact patterns `security.ssh_fails` greps for), using documentation IPs. |
| `journalctl-ssh-auth-fail-empty.txt` | same | The empty-journal boundary variant: no lines, so the count is 0 and no finding may fire. |
| `fail2ban-status.txt` | `fail2ban-client status sshd` | Real fail2ban 1.0.2 layout with tab-indented fields and one banned documentation IP; `security.fail2ban_banned` reads the `Currently banned` value from this shape. |
| `ss-tln.txt` | `ss -tlnp` | Header plus two `LISTEN` rows: port 22 (in the default allowlist) and port 9999 (not), which is the `security.new_port` classification boundary. |
| `apt-update-stamp-fresh` | `touch` | `/var/lib/apt/periodic/update-success-stamp` analogue. The real stamp file is empty — its **mtime** is the signal `maintenance.apt_cache_stale` reads. Regenerate the "fresh" state with `touch apt-update-stamp-fresh`. |
| `apt-update-stamp-stale` | `touch -d '4 days ago'` | Same file, aged past the 48h staleness window. Regenerate with `touch -d '4 days ago' apt-update-stamp-stale`. |
| `systemctl-failed-units.txt` | `systemctl list-units --type=service --state=failed --no-legend --plain --no-pager` | One real line captured on the NucBox (`postfix@-.service`); `system.failed_units` counts these lines and reports the first five unit names. |
| `crontab-empty.txt` | hand-seeded, `crontab -l` format | Comments only — zero entries, the `system.user_cron` boundary case. |
| `crontab-with-entries.txt` | hand-seeded, `crontab -l` format | Same header with two real-format entries (note: user crontabs have **no** user column, unlike `/etc/crontab`). |
| `integrity-baseline.json` | synthetic by design | The shape `integrity_snapshot()` emits: a single JSON line of `"path": "sha256"` pairs, paths drawn from the script's `INTEGRITY_TARGETS`. Real hashes are deliberately not frozen (they'd pin one box's crown-jewel state into a public repo). |
| `integrity-changed.json` | synthetic by design | Same key set as the baseline with exactly one hash changed — the `integrity.change` added/changed/removed input boundary. |

### Gaps (planned for T03)

`maintenance.timer_drift` reads `systemctl show <timer> --property=LastTriggerUSec`
output, which has no fixture yet — add `systemctl-show-timer.txt` (fresh and
drifted variants) when the seeded container can drive the check.

## Regenerating

```bash
# On the live box, as root:
sudo python3 test/fixtures/snapshot-fixtures.py --dry-run   # preview commands
sudo python3 test/fixtures/snapshot-fixtures.py             # record in place

# Then hand-finish the non-mechanical bits (see script docstring):
touch test/fixtures/apt-update-stamp-fresh
touch -d '4 days ago' test/fixtures/apt-update-stamp-stale
```

`test/fixtures/replay/` is a separate corpus: real `--json`-shaped daily
snapshots used by the T01 replay smoke assertions, not external-tool
output. Do not mix the two. Its `deltas/` sub-corpus carries the
positive/negative `*_delta` regression fixtures — see
[replay/deltas/README.md](replay/deltas/README.md).
