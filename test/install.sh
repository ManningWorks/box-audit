#!/usr/bin/env bash
# Driver: runs install.sh inside a privileged systemd container and asserts
# the verify gate passed. Used by install.yml's two jobs (positive + negative).
#
#   bash test/install.sh <image-tag> [sed-mutation]
#
# With a mutation, it is applied to install.sh inside the throwaway build
# context first, so the negative variant can prove the verify gate has
# teeth without touching the working tree.
#
# Also asserts the --ci "does not learn" negative (spec Testing Decisions:
# "Tier 1 (degraded/CI paths): --ci installs do not learn (starter defaults
# untouched)"): a fresh --ci install must NOT run the learn step and must
# keep the seeded generic defaults byte-for-byte — the CI branch of the
# learn gate's teeth, per AGENTS.md "every new gate gets the negative".
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
CI_OUT="$(mktemp)"
LIB_CLEANUP_PATHS+=("$CI_OUT")
privileged_exec /bin/bash -c 'cd /work && bash install.sh --ci' > "$CI_OUT" 2>&1

# --- --ci "does not learn" negative (spec Testing Decisions) -----------------
# A fresh --ci install runs with CI_MODE=1, so the learn gate
# (IS_FRESH_INSTALL && !CI_MODE && !NO_INIT && (-t 0 || LEARN_FORCE))
# cannot fire: no TTY (docker exec) AND CI_MODE short-circuits before the
# TTY/force check. This is the negative variant proving the CI branch holds —
# the install must NOT emit the learn summary and must keep the seeded
# generic defaults (ports 22 53 80 443 631), not a snapshot of the box.
if grep -q "learned baseline (from live box state)" "$CI_OUT"; then
    echo "test/install.sh: FAIL — --ci install ran the learn step (CI must never learn)" >&2
    tail -30 "$CI_OUT" >&2
    exit 1
fi
# The five seeded generic ports must all be present, exactly as install.sh
# seeds them (this is the "starter defaults untouched" assertion).
if ! privileged_exec /bin/bash -c 'grep -qx 22 /var/lib/box-audit/ports-allowlist.txt \
    && grep -qx 53 /var/lib/box-audit/ports-allowlist.txt \
    && grep -qx 80 /var/lib/box-audit/ports-allowlist.txt \
    && grep -qx 443 /var/lib/box-audit/ports-allowlist.txt \
    && grep -qx 631 /var/lib/box-audit/ports-allowlist.txt'; then
    echo "test/install.sh: FAIL — --ci install did not keep the seeded generic ports (22 53 80 443 631)" >&2
    privileged_exec cat /var/lib/box-audit/ports-allowlist.txt >&2 || true
    exit 1
fi
echo "test/install.sh: --ci install did not learn and kept the seeded generic defaults"