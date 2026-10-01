#!/usr/bin/env bash
# Driver for the F6 named-mutation registry (test/mutations.list).
#
#   bash test/mutation-coverage.sh                 # run every registry entry
#   bash test/mutation-coverage.sh --entry <id>    # repeatable; run a subset
#   bash test/mutation-coverage.sh --selftest      # stubbed-docker harness mode
#
# For each registry entry the driver runs the seeded tier-2 container path
# (test/install-seeded.sh's boot sequence) against a MUTATED copy of the
# tree and compares the entry's check_id in the post-mutation --json
# against a pristine baseline:
#
#   FLIPPED    the check_id is present in the baseline, absent after the
#              mutation — the gate caught the mutation (good).
#   SURVIVED   present in both, or absent in both — the mutation did not
#              flip a finding that the baseline produced (uncovered
#              surface; a signal, not a failure). When the baseline never
#              produced the finding (the seed for that check did not fire
#              in this container) an "(absent-in-baseline: ...)" note is
#              appended so it is not mistaken for a caught flip.
#
# How a mutation reaches the container (the load-bearing detail — both
# mutation families are handled by one code path):
#
#   The seeded image bakes ONLY seed.sh (test/install-docker/seeded/
#   Dockerfile: `FROM box-audit-base:test`, packages, `COPY seed.sh`).
#   box-audit.sh and install.sh are NOT baked into either image — they
#   arrive at boot when `install.sh --ci` copies /work/scripts/box-audit.sh
#   to /usr/local/bin/box-audit from the /work bind-mount. So:
#
#     * family B (rename the check_id inside scripts/box-audit.sh) reaches
#       the audit binary via the /work mount — the seeded image is
#       byte-identical and docker layer-caches it (no re-run);
#     * family A (mutate seed.sh) is baked into the seeded image at build
#       time, so the seeded state (e.g. the cron.d drop-in) is absent from
#       the start.
#
#   The mutation is applied to a STAGED scratch copy of the tree (the
#   install-lib.sh dual-build pattern: build the base, sed the staged
#   tree, build the seeded image on top) — NEVER the live working tree,
#   the same discipline as install-seeded.sh's own MUTATION path.
#
# A pristine seeded container (unmutated tree) is booted ONCE up front for
# the baseline audit; each entry costs one additional container run.
# Serial by design; this driver is opt-in and NOT part of test/all.sh.
#
# Exit codes:
#   0  every entry produced a verdict (FLIPPED or SURVIVED)
#   1  a hard error: baseline boot/audit failure, a malformed registry
#      line, an unknown --entry id, a sed that did not apply, a
#      container/audit failure, a --json that is not a findings list, or
#      a finding that APPEARS after the mutation (seed/mutation
#      misbehaviour — never a silent SURVIVED).
#   2  bad arguments.
#
# --selftest runs the same loop with a stubbed docker (env
# MUTATION_COVERAGE_DOCKER_STUB=1 set by the tier-1 harness in
# test/fixtures/mutation-coverage/selftest.sh) against a scratch repo, so
# the registry parse, sed application, verdict logic, and the error ->
# non-zero exit contract are provable without a container run. In stub
# mode the "audit" is the scratch tree's own scripts/box-audit.sh run in
# the current directory; the family-B rename is modelled by sedding that
# script's emitted check_id, so the verdict the loop records is the
# mechanism the real run exercises. The stub docker must implement `exec`
# (runs the command verbatim in $PWD). --repo <dir> points the driver at
# the scratch repo (selftest only).
#
# This card is the skeleton: it prints raw per-entry lines and restores
# only the live-tree files it actually mutated (selftest mode). The
# polished report table and the trap-based restoration machinery are
# later cards.

set -euo pipefail

# --- arguments ---------------------------------------------------------------
SELFTEST=0
SELFTEST_REPO=""
WANT_ENTRIES=()

prev=""
for arg in "$@"; do
    case "$prev" in
        --entry) WANT_ENTRIES+=("$arg") ;;
        --repo)  SELFTEST_REPO="$arg" ;;
    esac
    case "$arg" in
        --selftest) SELFTEST=1 ;;
        --entry|--repo) ;;
        --) ;;
        -*)
            echo "test/mutation-coverage.sh: unknown argument: $arg" >&2
            exit 2
            ;;
    esac
    prev="$arg"
done

REPO="$SELFTEST_REPO"
[[ -z "$REPO" ]] && REPO="$(cd "$(dirname "$0")/.." && pwd)"
REGISTRY="$REPO/test/mutations.list"

# shellcheck source=./install-lib.sh
source "$(dirname "$0")/install-lib.sh"

# box-audit-base:test is the exact FROM tag of the seeded Dockerfile, and
# it is what a prior tier-2 run (or this driver) leaves cached, so the
# base build is a docker cache no-op. The seeded image is rebuilt per run
# from the (possibly mutated) staged work — for family B the COPY seed.sh
# layer is unchanged and layer-cached; for family A it re-runs.
BASE_TAG="box-audit-base:test"
SEEDED_TAG="box-audit-mc:seeded"

# This driver runs MULTIPLE containers (one pristine baseline + one per
# entry), so it tracks every boot in MC_CONTAINERS and removes them all on
# exit — install-lib's trap only removes the LAST container it created
# (the global CID), which would strand the baseline + earlier entries.
# The trap also runs _lib_cleanup first so LIB_CLEANUP_PATHS (mktemp work
# dirs + capture files) are still rm -rf'd as the library intends.
MC_CONTAINERS=()
remove_mc_containers() {
    local c
    for c in ${MC_CONTAINERS[@]+"${MC_CONTAINERS[@]}"}; do
        docker rm -f "$c" >/dev/null 2>&1 || true
    done
    MC_CONTAINERS=()
}
# shellcheck disable=SC2064
trap '_lib_cleanup; remove_mc_containers' EXIT

# --- registry parse ------------------------------------------------------------
# Parallel arrays. The registry header documents three tab-separated
# fields: check_id <TAB> target <TAB> sed_expression. Applied verbatim
# (sed -i "<expr>" "<target>"), no shell expansion.
ENTRIES_ID=()
ENTRIES_TARGET=()
ENTRIES_SED=()

if [[ ! -f "$REGISTRY" ]]; then
    echo "test/mutation-coverage.sh: registry not found: $REGISTRY" >&2
    exit 1
fi
while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    IFS=$'\t' read -r id target sed_expr <<< "$line"
    if [[ -z "${id:-}" || -z "${target:-}" || -z "${sed_expr:-}" ]]; then
        echo "test/mutation-coverage.sh: malformed registry line (want check_id<TAB>target<TAB>sed): $line" >&2
        exit 1
    fi
    ENTRIES_ID+=("$id")
    ENTRIES_TARGET+=("$target")
    ENTRIES_SED+=("$sed_expr")
done < "$REGISTRY"
if (( ${#ENTRIES_ID[@]} == 0 )); then
    echo "test/mutation-coverage.sh: registry has no entries: $REGISTRY" >&2
    exit 1
fi

# Resolve the requested subset (or the full registry).
RUN_IDX=()
for i in "${!ENTRIES_ID[@]}"; do
    id="${ENTRIES_ID[$i]}"
    if (( ${#WANT_ENTRIES[@]} == 0 )); then
        RUN_IDX+=("$i")
        continue
    fi
    for want in "${WANT_ENTRIES[@]}"; do
        if [[ "$want" == "$id" ]]; then
            RUN_IDX+=("$i")
            break
        fi
    done
done
if (( ${#RUN_IDX[@]} == 0 )); then
    echo "test/mutation-coverage.sh: --entry matched no registry entries (want: ${WANT_ENTRIES[*]:-none})" >&2
    exit 1
fi

# --- seeded container path -----------------------------------------------------
# run_seed_sequence: the post-boot seed from test/install-seeded.sh, in the
# same order with the same readiness probes. `install.sh --ci` must exit 0
# — its verify gate is part of the contract this driver probes (and it is
# what copies /work/scripts/box-audit.sh to /usr/local/bin/box-audit, the
# channel family-B mutations ride).
run_seed_sequence() {
    privileged_exec /bin/bash -c 'cd /work && bash install.sh --ci' >/dev/null
    privileged_exec /bin/bash -c '
        echo "ALL ALL=(root) NOPASSWD: /usr/bin/fail2ban-client" \
            > /etc/sudoers.d/box-audit-fail2ban
        chmod 0440 /etc/sudoers.d/box-audit-fail2ban
    ' >/dev/null
    privileged_exec systemctl start box-audit-fail.service >/dev/null 2>&1 || true
    privileged_exec touch /var/log/fail2ban.log >/dev/null 2>&1 || true
    privileged_exec systemctl start fail2ban >/dev/null 2>&1 || true
    local ready=""
    for _ in $(seq 1 30); do
        if privileged_exec fail2ban-client ping 2>/dev/null | grep -q "pong"; then
            ready=yes
            break
        fi
        sleep 1
    done
    if [[ -z "$ready" ]]; then
        echo "test/mutation-coverage.sh: fail2ban-server did not become ready" >&2
        return 1
    fi
    privileged_exec fail2ban-client set sshd banip 192.0.2.1 >/dev/null 2>&1 || true
    privileged_exec fail2ban-client set recidive banip 203.0.113.7 >/dev/null 2>&1 || true
    privileged_exec /bin/bash -c '
        setsid python3 -m http.server 9999 --bind 127.0.0.1 --directory /tmp \
            >/tmp/box-audit-mc-http.log 2>&1 < /dev/null &
        echo $! > /tmp/box-audit-mc-http.pid
    ' >/dev/null
    local http_ready=""
    for _ in $(seq 1 30); do
        if privileged_exec ss -tlnH 2>/dev/null | grep -q ':9999 '; then
            http_ready=yes
            break
        fi
        sleep 1
    done
    if [[ -z "$http_ready" ]]; then
        echo "test/mutation-coverage.sh: python http.server did not bind to 9999" >&2
        privileged_exec /bin/bash -c 'cat /tmp/box-audit-mc-http.log' >&2 || true
        return 1
    fi
    # The $(date +%s) is evaluated by the container's shell on purpose
    # (fresh timestamp each run) — same as the tier-2 driver, so SC2016
    # is wrong here.
    # shellcheck disable=SC2016
    privileged_exec /bin/bash -c 'echo "# mc-mutation $(date +%s)" >> /etc/passwd' >/dev/null
    for _ in $(seq 1 16); do
        privileged_exec logger -p auth.err -t sshd \
            "Failed password for invalid user admin from 192.0.2.1 port 22 ssh2"
    done
    # Silence containerd (ships with the jrei image; binds a port that
    # would otherwise add a spurious security.new_port finding).
    privileged_exec /bin/bash -c 'pkill -f containerd || true; sleep 1' >/dev/null 2>&1 || true
}

# build_and_seed <work> [entry-idx]: stage the repo into <work> (building
# the base image), optionally apply the entry's sed to the STAGED tree,
# build the seeded image on top, boot it, and run the seed sequence.
# Mirrors test/install-seeded.sh's install-lib.sh dual-build pattern, so
# global $WORK is set for privileged_prep and the mutation survives into
# the image build (family A) and the /work mount (family B). Leaves the
# seeded container running as the global CID for the caller to audit.
build_and_seed() {
    local work="$1" i="${2:-}"
    privileged_build "$REPO/test/install-docker/Dockerfile" "$BASE_TAG" "$work"
    if [[ -n "$i" ]]; then
        if ! sed -i "${ENTRIES_SED[$i]}" "$work/${ENTRIES_TARGET[$i]}"; then
            echo "test/mutation-coverage.sh: sed did not apply on ${ENTRIES_TARGET[$i]}: ${ENTRIES_SED[$i]}" >&2
            return 1
        fi
    fi
    privileged_build "$REPO/test/install-docker/seeded/Dockerfile" "$SEEDED_TAG" "$work"
    privileged_prep "$SEEDED_TAG"
    run_seed_sequence
}

# audit_json <outfile>: run the installed audit and capture --json. Real
# mode runs the seeded container's /usr/local/bin/box-audit (the global
# CID just set by build_and_seed). Selftest mode runs the scratch tree's
# own scripts/box-audit.sh directly — the stub docker implements exec
# only, so the real in-container path is what the live run exercises.
audit_json() {
    local out="$1"
    if (( SELFTEST )); then
        if ! bash "$REPO/scripts/box-audit.sh" --json > "$out" 2>/dev/null; then
            echo "test/mutation-coverage.sh: box-audit --json exited non-zero" >&2
            return 1
        fi
    else
        if ! privileged_exec /usr/local/bin/box-audit --json > "$out" 2>/dev/null; then
            echo "test/mutation-coverage.sh: box-audit --json exited non-zero" >&2
            return 1
        fi
    fi
    if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert isinstance(d.get("findings"), list)' "$out" 2>/dev/null; then
        echo "test/mutation-coverage.sh: --json output is not valid JSON with a findings list" >&2
        return 1
    fi
}

# has_finding <json-file> <check-id> -> 0 if a finding carries that id.
has_finding() {
    local json_file="$1" check_id="$2"
    python3 - "$json_file" "$check_id" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if any(f.get("check_id") == sys.argv[2] for f in d["findings"]) else 1)
PY
}

FLIPPED=0
SURVIVED=0
START_S=$(date +%s)
# Live-tree files this run mutated. Real mode NEVER touches the live tree
# (the mutation lives in the staged scratch work), so this stays empty and
# the end-of-run restore is a no-op. Selftest mode seds the scratch repo's
# own tree directly, so we record each target here and restore EXACTLY
# those paths — never a blanket `git checkout -- .`, which would discard
# unrelated local edits the driver was invoked on top of.
LIVE_MUTATED=()

# --- pristine baseline -----------------------------------------------------------
# Boot the unmutated tree once for the baseline audit. In selftest mode
# there is no container — the baseline is the scratch tree's own audit.
BASELINE_JSON="$(mktemp)"
LIB_CLEANUP_PATHS+=("$BASELINE_JSON")

if (( SELFTEST )); then
    :
else
    baseline_work="$(mktemp -d)"
    LIB_CLEANUP_PATHS+=("$baseline_work")
    if ! build_and_seed "$baseline_work"; then
        echo "test/mutation-coverage.sh: pristine boot failed" >&2
        exit 1
    fi
    MC_CONTAINERS+=("$CID")
fi
if ! audit_json "$BASELINE_JSON"; then
    echo "test/mutation-coverage.sh: baseline audit failed" >&2
    exit 1
fi
if ! (( SELFTEST )); then
    docker rm -f "$CID" >/dev/null 2>&1 || true
fi

# --- entry loop --------------------------------------------------------------------
for i in "${RUN_IDX[@]}"; do
    id="${ENTRIES_ID[$i]}"
    target="${ENTRIES_TARGET[$i]}"
    MUT_JSON="$(mktemp)"
    LIB_CLEANUP_PATHS+=("$MUT_JSON")

    if (( SELFTEST )); then
        # Stub mode: apply the entry's sed to the scratch tree directly —
        # the "audit" is the tree's own stub script, so the family-B
        # rename lands exactly as the real /work mount delivers it.
        if ! sed -i "${ENTRIES_SED[$i]}" "$REPO/$target"; then
            echo "ENTRY $i $id ERROR (sed did not apply) target=$target" >&2
            git -C "$REPO" checkout -- "$target" 2>/dev/null || true
            exit 1
        fi
        LIVE_MUTATED+=("$target")
    else
        entry_work="$(mktemp -d)"
        LIB_CLEANUP_PATHS+=("$entry_work")
        if ! build_and_seed "$entry_work" "$i"; then
            echo "ENTRY $i $id ERROR (boot/build/seed) target=$target" >&2
            exit 1
        fi
        MC_CONTAINERS+=("$CID")
    fi

    audit_rc=0
    audit_json "$MUT_JSON" || audit_rc=$?
    if (( SELFTEST )); then
        # Restore the scratch tree before the next entry's sed. Scoped to
        # this entry's target (never a blanket `git checkout -- .`).
        git -C "$REPO" checkout -- "$target" 2>/dev/null || true
    fi
    if (( audit_rc != 0 )); then
        echo "ENTRY $i $id ERROR (audit) target=$target" >&2
        exit 1
    fi

    # Clean up this entry's container + rebuilt seeded image. The base
    # image stays for the next entry (docker cache); the container and
    # the per-entry seeded image go now (also in MC_CONTAINERS in case of
    # an early exit before this point).
    if ! (( SELFTEST )); then
        docker rm -f "$CID" >/dev/null 2>&1 || true
        docker rmi -f "$SEEDED_TAG" >/dev/null 2>&1 || true
    fi

    baseline_present=no
    has_finding "$BASELINE_JSON" "$id" && baseline_present=yes
    mutated_present=no
    has_finding "$MUT_JSON" "$id" && mutated_present=yes
    case "$baseline_present/$mutated_present" in
        yes/no)
            verdict="FLIPPED"
            FLIPPED=$((FLIPPED + 1))
            ;;
        yes/yes|no/no)
            verdict="SURVIVED"
            SURVIVED=$((SURVIVED + 1))
            ;;
        no/yes)
            # A finding appearing AFTER the mutation means the seed or
            # the mutation misbehaves — error, never a silent SURVIVED.
            echo "ENTRY $i $id ERROR (finding appeared after mutation) target=$target" >&2
            exit 1
            ;;
    esac
    note=""
    [[ "$baseline_present" == "no" ]] && note=" (absent-in-baseline: the seed for this check did not fire in this container)"
    echo "ENTRY $i $id $verdict target=$target baseline=$baseline_present mutated=$mutated_present$note"
done

# Safety net: restore EXACTLY the live-tree files this run mutated (selftest
# mode seds the scratch tree directly; real mode mutates only the staged
# work, so LIVE_MUTATED is empty and this is a no-op). Never a blanket
# `git checkout -- .` — that would discard unrelated local edits the driver
# was invoked on top of.
if [[ -d "$REPO/.git" && ${#LIVE_MUTATED[@]} -gt 0 ]]; then
    for t in "${LIVE_MUTATED[@]}"; do
        git -C "$REPO" checkout -- "$t" 2>/dev/null || true
    done
fi

ELAPSED_S=$(( $(date +%s) - START_S ))
echo "mutation-coverage: ${#RUN_IDX[@]} entries — $FLIPPED flipped, $SURVIVED survived — ${ELAPSED_S}s"
exit 0
