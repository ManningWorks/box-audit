#!/usr/bin/env bash
# install-lib.sh — shared setup for the privileged-systemd test drivers
# (test/install.sh, test/install-seeded.sh, test/local-integration.sh).
#
# Why this exists: those three drivers duplicated the same ~50-line boot
# sequence (throwaway WORK, privileged docker run with cgroup/tmpfs flags,
# wait-for-systemd loop, trap cleanup). The flag set is byte-identical;
# changes to the jrei/systemd-ubuntu base image's cgroup expectations had
# to land in three places. Issue #25 extracts that surface here.
#
#   bash test/install-lib.sh       # shellcheck-only entry; not runnable
#
# Sourced by the drivers — never invoked directly.
#
# Public API (consumed by drivers):
#   privileged_build <dockerfile> <image-tag> [work-dir]
#       If [work-dir] is given, builds from that directory and reuses
#       it across multiple builds (the dual-build case in
#       install-seeded.sh: base + seeded layered image both COPY
#       repo-relative paths from the same context).
#       If [work-dir] is omitted, stages $REPO into a fresh mktemp
#       WORK, builds <image-tag>, leaves WORK mounted at /work and
#       registers it for cleanup.
#
#   privileged_prep <image-tag>
#       Boots a detached privileged systemd container from <image-tag>
#       using WORK as /work, waits up to 30s for systemd-ready, sets
#       the global CID, registers cleanup. Eager-binds the EXIT trap;
#       see "Trap composability" in the issue body for why.
#
#   privileged_exec <cmd...>
#       Shortcut for `docker exec "$CID" "$@"`. Propagates exit code.
#
# Globals the library sets (drivers read after calling):
#   WORK, CID — set by privileged_prep
#   LIB_CLEANUP_PATHS — array; drivers append additional mktemps
#       (e.g. capture files) before calling privileged_build. The
#       library's EXIT trap `rm -rf`s every path on exit.
#
# Globals the driver MUST set before sourcing:
#   REPO — repo root. Drivers already compute this; the library uses it
#       only as the source of the WORK copy.
#
# Globals the driver MAY set before sourcing:
#   INSTALL_LIB_TIMEOUT — systemd-readiness wait in seconds (default 30).

set -euo pipefail

# --- driver extension mechanism --------------------------------------------
# Drivers that allocate additional mktemps (e.g. tier 3's capture files)
# append them here, and the library's EXIT trap rm -rf's every entry on
# exit — the trap reads the array at exit time, so appends made after
# sourcing are picked up. The trap is bound at source time so a failure
# before privileged_prep (e.g. a failed docker build) still cleans up
# any mktemps the driver has already registered.
LIB_CLEANUP_PATHS=()

# Default 30s — matches the value all three drivers used before issue #25.
# install-seeded.sh used 60s; we unify on 30s per the issue's Q3 call. If
# the seeded driver flakes on a slow runner, raise INSTALL_LIB_TIMEOUT
# before calling privileged_prep; don't re-introduce per-driver values.
: "${INSTALL_LIB_TIMEOUT:=30}"

# SC2015 — A && B || C is intentional: docker rm -f may legitimately
# return non-zero when the container is already gone, and we don't want
# cleanup under `set -e` to fail the run. Same disable as the drivers
# carried before the extraction.
# shellcheck disable=SC2015
_lib_cleanup() {
    [[ -n "${CID:-}" ]] && docker rm -f "$CID" >/dev/null 2>&1 || true
    if (( ${#LIB_CLEANUP_PATHS[@]} > 0 )); then
        rm -rf "${LIB_CLEANUP_PATHS[@]}"
    fi
}

# Bound at source time (not inside privileged_prep) so a failure before
# boot — e.g. a failed docker build — still cleans up any mktemps the
# driver has registered in LIB_CLEANUP_PATHS. The trap reads the array
# at exit time, so appends made after sourcing are picked up.
trap _lib_cleanup EXIT

# --- public: privileged_build ----------------------------------------------
# Stages $REPO into a fresh mktemp, builds <image-tag> from <dockerfile>,
# and registers the WORK directory for cleanup. The library does NOT
# bind an EXIT trap here — that happens in privileged_prep, so drivers
# that build-then-fail (e.g. on a Dockerfile error) get a normal shell
# exit code without the trap firing on a not-yet-existing CID.
#
# Drivers that mutate files in WORK between cp and build (e.g.
# install.sh's MUTATION path, install-seeded.sh's seed.sh mutation) do
# so by reading $WORK after the call returns and applying sed/awk to
# the file inside it. We don't expose a callback; that's a leakier
# abstraction than the explicit two-step.
privileged_build() {
    local dockerfile="$1" tag="$2" work_arg="${3:-}"

    if [[ -z "${REPO:-}" ]]; then
        echo "install-lib.sh: REPO must be set before privileged_build" >&2
        return 2
    fi

    if [[ -n "$work_arg" ]]; then
        # Reuse caller's WORK (dual-build case): stage the repo into it
        # only if it's empty (first call); the second build must see the
        # first call's staging — including any mutation the driver
        # applied in between — untouched.
        WORK="$work_arg"
        if [[ -z "$(ls -A "$WORK")" ]]; then
            cp -R "$REPO/." "$WORK/"
        fi
    else
        # Replace any prior WORK. Single-build case.
        if [[ -n "${WORK:-}" ]]; then
            rm -rf "$WORK"
            local old_work="$WORK"
            local new_paths=()
            local p
            for p in "${LIB_CLEANUP_PATHS[@]}"; do
                [[ "$p" != "$old_work" ]] && new_paths+=("$p")
            done
            LIB_CLEANUP_PATHS=("${new_paths[@]}")
        fi
        WORK="$(mktemp -d)"
        LIB_CLEANUP_PATHS+=("$WORK")
        cp -R "$REPO/." "$WORK/"
    fi

    # Returns 0 on successful build; `set -e` propagates build failure
    # to the caller as a non-zero exit.
    docker build -t "$tag" -f "$dockerfile" "$WORK" >/dev/null
}

# --- public: privileged_prep -----------------------------------------------
# Boots a detached privileged systemd container from <image-tag> against
# the WORK staged by the most recent privileged_build call. Waits up to
# INSTALL_LIB_TIMEOUT seconds for systemd to report ready (running or
# degraded), sets the global CID, and binds the EXIT trap for cleanup.
#
# On systemd-readiness timeout, prints
#   <driver-name>: systemd did not become ready (last state: '<state>')
# to stderr and exits 1, matching the failure shape all three drivers
# had before extraction. The driver name comes from $0 so the message
# identifies which tier failed in the aggregate `test/all.sh` log.
privileged_prep() {
    local image_tag="$1"

    if [[ -z "${WORK:-}" ]]; then
        echo "install-lib.sh: privileged_build must be called before privileged_prep" >&2
        return 2
    fi

    # Privileged + rw cgroup mount with --cgroupns=host so systemd gets
    # a working cgroup view (the jrei/systemd-ubuntu README's recipe);
    # tmpfs on /run and /var/log so each run starts clean (and the
    # --ci tee target exists in a fresh log dir). `container=docker`
    # so the audit's own probe paths recognise the env. The flag set
    # was byte-identical across all three drivers before extraction;
    # any future change to it lands here.
    CID="$(docker run -d --privileged \
        --cgroupns=host \
        --tmpfs /run \
        --tmpfs /var/log \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        -v "$WORK":/work \
        -e container=docker \
        "$image_tag")"

    # Wait for systemd to accept commands. "degraded" means booted with
    # some unit failed — fine for our purposes; the gate only judges
    # box-audit.
    local state=""
    local driver_name
    driver_name="$(basename "${BASH_SOURCE[1]:-$0}")"
    local deadline=$((INSTALL_LIB_TIMEOUT))
    for _ in $(seq 1 "$deadline"); do
        state="$(docker exec "$CID" systemctl is-system-running 2>/dev/null || true)"
        case "$state" in
            running|degraded) break ;;
        esac
        sleep 1
    done
    if [[ "$state" != "running" && "$state" != "degraded" ]]; then
        echo "$driver_name: systemd did not become ready (last state: '${state:-none}')" >&2
        # Trap will fire on EXIT and clean up CID + WORK + LIB_CLEANUP_PATHS.
        exit 1
    fi
}

# --- public: privileged_exec -----------------------------------------------
# Shortcut for `docker exec "$CID" "$@"`. Propagates the inner command's
# exit code so callers can assert under `set -e`. The drivers' previous
# pattern was the verbose `docker exec "$CID" /bin/bash -c '...'`
# inline; this preserves the semantics with less ceremony.
privileged_exec() {
    docker exec "$CID" "$@"
}