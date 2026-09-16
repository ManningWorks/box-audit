#!/usr/bin/env bash
# Driver: runs install.sh inside a privileged systemd container and asserts
# the verify gate passed. Used by install.yml's two jobs (positive + negative).
#
#   bash test/install.sh <image-tag> [sed-mutation]
#
# With a mutation, it is applied to install.sh inside the throwaway build
# context first, so the negative variant can prove the verify gate has
# teeth without touching the working tree.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_TAG="${1:-box-audit-install:positive}"
MUTATION="${2:-}"   # sed expression applied to install.sh in the build context

# shellcheck source=./install-lib.sh
# shellcheck disable=SC1091
source "$(dirname "$0")/install-lib.sh"

privileged_build "$REPO/test/install-docker/Dockerfile" "$IMAGE_TAG"

if [[ -n "$MUTATION" ]]; then
    sed -i "$MUTATION" "$WORK/install.sh"
fi

privileged_prep "$IMAGE_TAG"

# Run `docker run image bash -c ...` would replace systemd as PID 1 and
# systemctl would have no daemon to talk to; docker exec propagates
# install.sh's exit code into this shell under `set -e`.
privileged_exec /bin/bash -c 'cd /work && bash install.sh --ci'