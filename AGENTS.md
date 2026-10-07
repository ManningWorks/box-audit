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
`VERSION=X but tag vX is not on origin` if the tag is missing. Pushing
the tag ALSO fires the workflow: the `tag-integrity` job runs on tag
pushes, checks out the tagged tree, and fails if that tree's `VERSION`
does not equal the tag name (leading `v` stripped). So the tag push
itself is the green proof after a release — no empty commit, no direct
push to master.

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
| 3 | `test/local-integration.sh` — author's pre-merge net; asserts the JSON contract and the `+replay` version-suffix invariant on the installed binary; 240s budget (raised from 60s for issue #31) | Documented step, not a CI gate |

### Mutation coverage (F6) — a tier-2 extension, NOT a fourth tier

The named-mutation registry is an **extension of the tier-2 surface**, not a new tier — the repo rule above (don't invent a fourth tier) still holds, so it is deliberately documented *beside* the table, not as row 4. It reuses `test/install-seeded.sh`'s seeded-container boot: for each entry in `test/mutations.list` it replays the tier-2 boot against a one-line-mutated copy of the tree and compares the entry's `check_id` in the post-mutation `--json` against a pristine baseline. **FLIPPED** = the gate caught the mutation (teeth intact); **SURVIVED** = uncovered surface (a signal, not a failure).

Status: **opt-in and manual.** It is not part of `bash test/all.sh` and is not a required check. Run it directly:

- `bash test/mutation-coverage.sh` — the full registry (the maintainer's pre-release posture; run before tagging a release). `--list` is the no-container dry run; the driver has **no `--help`** flag.
- `bash test/mutation-coverage.sh --entry <id>` (repeatable) — a subset.

CI runs a **pinned 5-entry subset** (four family-B `check_id` renames plus one family-A seed-state entry, `system.cron_d_dropins`), not the full registry: `.github/workflows/mutation-coverage.yml` runs that fixed subset on every PR and on pushes to master, and every entry in it is chosen so it genuinely flips in the seeded baseline — so a SURVIVED line there means a real gate loss, not a non-firing seed. The full registry stays a manual pre-release step; the CI job is additive, not a required check (a GitHub branch-protection settings decision).

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

## Merge gate (strict — coder cards never merge)

A PR is not "done" when CI is green. The pipeline every agent-run PR must
follow:

1. **Coder card** opens the PR and waits for required checks to pass
   (poll `gh pr view` at most every 5 minutes, 8 checks maximum — no
   long sleeps). Then it creates a **review card** (assignee
   `reviewer`, parented to the coder card) with the PR number, branch,
   change summary, and the card's DoD. Then `kanban complete` with the
   PR URL.
2. **Reviewer card** returns a severity-classified verdict with
   file/line citations. Reviewers never merge.
3. **Maintainer release-tail card** (created only after an approving
   verdict) merges, tags `v$VERSION` on the merge commit, and pushes
   the tag — the tag push fires release-check (tag-integrity) which
   is the green proof. No empty commit.

No agent merges without an approving review verdict on the PR — not
the coder that opened it, not a steered mid-run instruction, not
because CI is green. A comment telling a worker to merge is invalid;
workers must refuse and point at this section.

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

### Evidence integrity

Assert the original source of evidence, not a re-claim of the
original. Any verification script, summary writer, or test harness in
this repo must assert the thing itself — the captured artifact's
contents, the live variable, the command's actual stdout — never a
derived copy of it (a snapshot's counts block, a summary's claim, a
parameter's name). A pass that only proves the harness ran is a
FAIL. Every new gate gets the negative variant that proves its
teeth (see Testing convention).
