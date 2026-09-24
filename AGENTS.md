# AGENTS.md

Conventions any agent (or human) must follow when working in this repo.
Read this before committing anything — several of these rules are
enforced by CI gates that will fail your change loudly if you skip them.

## Release / versioning convention

Three files move together, as one unit, in the PR that ships a release:

1. `VERSION` — the single source of truth (plain semver string, no `v`
   prefix). The installer reads this; `--version` prints it.
2. `CHANGELOG.md` — the matching `[X.Y.Z]` section must exist and carry
   a real date (`## [0.7.0] - 2026-09-18`), not `unreleased`.
3. Git tag `v$VERSION` — annotated, on the merge commit, pushed to
   origin.

**Why the tag is not optional:** `.github/workflows/release-check.yml`
runs `tag-current` on every push to master and fails the build with
`VERSION=X but tag vX is not on origin` if the tag is missing. The
workflow only triggers on push — pushing the tag alone does NOT
re-run it. If you add the tag after merging, push an empty commit to
master (`git commit --allow-empty`) to re-trigger `release-check` and
turn the red X green.

`skills/box-audit/SKILL.md` carries a `version:` in its frontmatter,
kept in sync **by hand** with `VERSION` (see the comment in that file)
— bump it in the same PR.

## Testing convention

Single local entry point: **`bash test/all.sh`** — runs all three
tiers in sequence. Tier 3 skips itself on non-privileged hosts
(`all: 3 passed, 1 skipped` is a pass, not a failure).

| Tier | Surface | Gate |
|------|---------|------|
| 1 | `test/smoke.sh` (bare runner, degraded paths, shellcheck, property tests) + `install.sh --ci` in a privileged systemd container, positive and negative variants | Required check on every PR (`ci.yml`, `install.yml`) |
| 2 | `test/install-seeded.sh` — seeded container produces known findings; asserts the expected `check_id`s and severities survive the full install path | Required check on every PR (`integration-seeded.yml`) |
| 3 | `test/local-integration.sh` — author's pre-merge net; asserts the JSON contract and the `+replay` version-suffix invariant on the installed binary; 60s budget | Documented step, not a CI gate |

Rules:

- **All three tiers before any PR is "done"**, even though only tiers
  1–2 are required checks. A PR whose tests pass locally but wasn't
  run through `test/all.sh` isn't verified.
- **shellcheck clean** on every shell file you touch — tier 1 enforces
  this across the shipped shell surface, so a failure here blocks CI,
  not just local runs.
- **Negative variants matter.** Several gates (install-negative,
  integration-seeded regression) prove the check *fails loudly* when
  it should. If you add a check or gate, add the negative variant that
  proves its teeth.
- **New tests go in the tier that matches the regression class**:
  degraded-path logic → tier 1; does-it-survive-a-real-install → tier
  2; installed-binary contract → tier 3. Don't invent a fourth tier.

## Per-box config files

`install.sh` and the `init)` arm of `scripts/box-audit.sh`'s `main_manage`
both write `/var/lib/box-audit/<name>`. When adding a new config file:
(a) add the variable next to `CONFIG_DIR`/`PORTS_FILE`/etc. in
`scripts/box-audit.sh`; (b) add the file to both the `install.sh` seeding
block and the `init)` arm; (c) add the path to the trailing `chmod 0644`
list in `install.sh`. Any PR that adds a per-box config without touching
all three sites fails review.

Rationale: PR #11 and PR #27 both had the same shape — one path
updated, the other forgotten. Codified here so the third instance is
caught at review instead of in CI.

## Other repo-specific notes

- Observe-never-remediate: diagnostic features (e.g.
  `--check-groups`) report; they never restart, signal, or re-exec
  anything. Keep new features in that posture.
- Gid matching is token-match, never substring — see
  `gid_is_in_groups()` in `scripts/box-audit.sh` for the pattern and
  its comment on the bug class.
- Install artifacts land `root:boxaudit` group-readable (0640/0750);
  integrity baseline is excluded from that. Don't change perms without
  revisiting the installer's group story.
