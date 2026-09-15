#!/usr/bin/env bash
# Property-suite orchestrator. Runs every check-family test under
# test/properties/*.sh in sequence, aggregates file-level results, and
# exits non-zero on any failure. Assertion style comes from assert.sh;
# the shape (counters, summary line, aggregate exit) mirrors test/smoke.sh.
#
# The opt-in live-agreement suite lives in test/properties/live/ and is
# deliberately NOT picked up by this glob: it performs a full `--json`
# audit, which costs ~7s on a box with broad NOPASSWD sudo (apt-get
# update + needrestart + SUID find) and would blow the 5-second budget
# the smoke harness enforces there. Run it manually:
#   bash test/properties/live/audit-agreement.sh
set -u

PROPS_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$PROPS_DIR/../../scripts/box-audit.sh"

START_NS=$(date +%s%N)

# One --print-schema call shared by every test: each asserts its own
# check_id is in the schema, and ten separate calls would burn ~1.5s of
# the 5s budget on byte-identical output.
SCHEMA_FILE="$(mktemp)"
trap 'rm -f "$SCHEMA_FILE"' EXIT
if ! bash "$SCRIPT" --print-schema > "$SCHEMA_FILE" 2>/dev/null; then
    echo "props: FAIL — --print-schema exited non-zero; schema contract broken"
    exit 1
fi
export BA_PROP_SCHEMA_FILE="$SCHEMA_FILE"

TOTAL=0
FAILED=0
for t in "$PROPS_DIR"/*.sh; do
    # Skip the helper module and this orchestrator — both match *.sh, and
    # running run.sh from run.sh is infinite recursion (learned the loud way).
    case "$(basename "$t")" in
        assert.sh|run.sh) continue ;;
    esac
    TOTAL=$((TOTAL + 1))
    if ! bash "$t"; then
        FAILED=$((FAILED + 1))
        echo "FAIL - test file: $(basename "$t")"
    fi
done

ELAPSED_MS=$(( ($(date +%s%N) - START_NS) / 1000000 ))
echo
echo "properties: $((TOTAL - FAILED))/$TOTAL test file(s) passed in ${ELAPSED_MS}ms"
[[ $FAILED -eq 0 ]]
