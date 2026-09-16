#!/usr/bin/env bash
# Driver: runs install.sh inside a privileged systemd container and asserts
# the verify gate passed. Used by install.yml's two jobs (positive + negative).
#
#   bash test/install.sh <image-tag> [sed-mutation]
#
# With a mutation, it is applied to install.sh inside a throwaway build
# context first, so the negative variant can prove the verify gate has
# teeth without touching the working tree.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="${1:-box-audit-install:positive}"
MUTATION="${2:-}"   # sed expression applied to install.sh in the build context

# 1. Throwaway copy of the repo (plus optional mutation) as the build
#    context. Same directory is mounted at /work in the container below.
WORK="$(mktemp -d)"
# SC2015 — A && B || C is intentional: docker rm -f may legitimately
# return non-zero when the container is already gone, and we don't
# want the cleanup to fail the run.
# shellcheck disable=SC2015
cleanup() {
    [[ -n "${CID:-}" ]] && docker rm -f "$CID" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
cp -R "$REPO/." "$WORK/"

if [[ -n "$MUTATION" ]]; then
    sed -i "$MUTATION" "$WORK/install.sh"
fi

# 2. Build the image (python3 for the verify gate's JSON parse lives here).
docker build -t "$IMAGE_TAG" -f "$REPO/test/install-docker/Dockerfile" "$WORK" >/dev/null

# 3. Boot the container with its default CMD (/sbin/init) detached, then
#    exec install.sh into the running system. Running `docker run image
#    bash -c ...` would replace systemd as PID 1 and systemctl would have
#    no daemon to talk to; docker exec propagates install.sh's exit code.
#    Privileged + rw cgroup mount with --cgroupns=host so systemd gets a
#    working cgroup view (the jrei/systemd-ubuntu README's recipe); tmpfs
#    on /run and /var/log so each run starts clean (and the --ci tee
#    target exists in a fresh log dir).
CID="$(docker run -d --privileged \
    --cgroupns=host \
    --tmpfs /run \
    --tmpfs /var/log \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$WORK":/work \
    -e container=docker \
    "$IMAGE_TAG")"

# Wait for systemd to accept commands. "degraded" means booted with some
# unit failed — fine for our purposes; the gate only judges box-audit.
STATE=""
for _ in $(seq 1 30); do
    STATE="$(docker exec "$CID" systemctl is-system-running 2>/dev/null || true)"
    case "$STATE" in
        running|degraded) break ;;
    esac
    sleep 1
done
if [[ "$STATE" != "running" && "$STATE" != "degraded" ]]; then
    echo "test/install.sh: systemd did not become ready (last state: '${STATE:-none}')" >&2
    exit 1
fi

docker exec "$CID" /bin/bash -c 'cd /work && bash install.sh --ci'
