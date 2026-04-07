#!/bin/bash
# ============================================================================
# MOOR Security Audit Pipeline
# ============================================================================
#
# Automated CWE audit with static analysis and iterative manual fix-and-verify cycle.
# Produces reproducible, labeled reports in audit/ directory.
#
# Usage:
#   ./security-audit.sh              # full audit (static + CWE pattern scan)
#   ./security-audit.sh --quick      # static analysis only (fast mode)
#   ./security-audit.sh --report     # view latest summary report
#
# Output:
# audit/
# ├── round-N/
# │   ├── snapshot.sha          # git state at audit start
# │   ├── code-before.patch     # exact code state audited (reproducible)
# │   ├── cppcheck.log
# │   ├── flawfinder.log
# │   ├── scanbuild.log
# │   ├── scanbuild-html/       # clang static analyzer HTML report
# │   ├── findings.txt          # all findings, categorized
# │   └── (future: fixes.patch / code-after.patch / verify.log)
# ├── summary.txt               # cross-round summary
# └── CLEAN                     # created when 0 critical findings remain
#
# ============================================================================
set -euo pipefail

cd "$(dirname "$0")"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

AUDIT_DIR="audit"
QUICK=0
REPORT_ONLY=0

case "${1:-}" in
    --quick)  QUICK=1 ;;
    --report) REPORT_ONLY=1 ;;
    --help|-h)
        echo -e "${BOLD}MOOR Security Audit${NC}"
        echo "Usage: $0 [--quick | --report | --help]"
        exit 0
        ;;
esac

if [[ $REPORT_ONLY -eq 1 ]]; then
    if [[ -f "$AUDIT_DIR/summary.txt" ]]; then
        cat "$AUDIT_DIR/summary.txt"
    else
        echo "No audit report found. Run ./security-audit.sh first."
    fi
    exit 0
fi

mkdir -p "$AUDIT_DIR"

# Determine current round number
ROUND=1
while [[ -d "$AUDIT_DIR/round-$ROUND" ]]; do
    ROUND=$((ROUND + 1))
done
RDIR="$AUDIT_DIR/round-$ROUND"
mkdir -p "$RDIR"

echo -e "${BOLD}${CYAN}============================================${NC}"
echo -e "${BOLD}${CYAN} MOOR Security Audit — Round $ROUND${NC}"
echo -e "${BOLD}${CYAN}============================================${NC}"
echo ""

# ---- Step 1: Snapshot ----
echo -e "${YELLOW}[1/5] Snapshot${NC}"
git rev-parse HEAD > "$RDIR/snapshot.sha" 2>/dev/null || echo "uncommitted" > "$RDIR/snapshot.sha"
git diff HEAD -- src/ include/ > "$RDIR/code-before.patch" 2>/dev/null || true

SNAP=$(cat "$RDIR/snapshot.sha")
NCHANGED=$(git diff --name-only HEAD -- 'src/*.c' 'include/*.h' 2>/dev/null | wc -l)
ADDITIONS=$(git diff HEAD -- 'src/*.c' 'include/*.h' 2>/dev/null | grep '^+[^+]' | wc -l)

echo " Base commit: ${SNAP:0:8}"
echo " Changed files: $NCHANGED"
echo " New lines: +$ADDITIONS"
echo ""

# ---- Step 2: Static Analysis ----
echo -e "${YELLOW}[2/5] Static Analysis${NC}"

echo -n " cppcheck... "
cppcheck --enable=warning,style,performance --std=c11 \
    --suppress=missingIncludeSystem --suppress=unusedFunction \
    --suppress=constParameterPointer --suppress=constVariablePointer \
    --suppress=shadowVariable --suppress=funcArgNamesDifferent \
    --suppress=staticFunction --suppress=unusedStructMember \
    -Iinclude -Isrc/kyber -Isrc/dilithium --force \
    src/*.c 2> "$RDIR/cppcheck.log"

CPP_ERRORS=$(grep -c '(error)' "$RDIR/cppcheck.log" 2>/dev/null || echo 0)
CPP_WARNINGS=$(grep -c '(warning)' "$RDIR/cppcheck.log" 2>/dev/null || echo 0)
echo "${CPP_ERRORS} errors, ${CPP_WARNINGS} warnings"

echo -n " flawfinder... "
flawfinder --minlevel=2 --columns src/*.c > "$RDIR/flawfinder.log" 2>/dev/null || true
FF_HIGH=$(grep -cE '^\s+\[[4-5]\]' "$RDIR/flawfinder.log" 2>/dev/null || echo 0)
FF_MED=$(grep -cE '^\s+\[3\]' "$RDIR/flawfinder.log" 2>/dev/null || echo 0)
echo "${FF_HIGH} high, ${FF_MED} medium"

echo -n " scan-build... "
# Portable scan-build detection (works on Linux/macOS with any clang version)
if command -v scan-build-19 >/dev/null 2>&1 && command -v clang-19 >/dev/null 2>&1; then
    SCANBUILD=scan-build-19
    CLANG=clang-19
elif command -v scan-build >/dev/null 2>&1 && command -v clang >/dev/null 2>&1; then
    SCANBUILD=scan-build
    CLANG=clang
    echo -n "(system default) "
else
    echo -e "${YELLOW}(skipped: scan-build not found)${NC}"
    SB_BUGS=0
    SCANBUILD=""
fi

if [[ -n "$SCANBUILD" ]]; then
    make clean >/dev/null 2>&1 || true
    # Portable CPU count (Linux + macOS)
    JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)
    $SCANBUILD -o "$RDIR/scanbuild-html" make -j"$JOBS" CC="$CLANG" \
        > "$RDIR/scanbuild.log" 2>&1 || true
    SB_BUGS=$(grep -c 'warning:' "$RDIR/scanbuild.log" 2>/dev/null || echo 0)
    echo "${SB_BUGS} findings"
else
    SB_BUGS=0
fi

# Rebuild with gcc for normal use
make clean >/dev/null 2>&1 || true
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 4)" >/dev/null 2>&1
echo ""

# ---- Step 3: CWE Pattern Scan (skipped in --quick) ----
if [[ $QUICK -eq 0 ]]; then
    echo -e "${YELLOW}[3/5] CWE Pattern Scan (changed lines only)${NC}"
    DIFF_ADDS=$(git diff HEAD -- 'src/*.c' 2>/dev/null | grep '^+[^+]' || true)
    FINDINGS=""
    FINDING_COUNT=0

    check_cwe() {
        local pattern="$1" cwe="$2" sev="$3" desc="$4"
        local matches=$(echo "$DIFF_ADDS" | grep -c "$pattern" 2>/dev/null || echo 0)
        if [[ $matches -gt 0 ]]; then
            FINDING_COUNT=$((FINDING_COUNT + 1))
            local lines=$(echo "$DIFF_ADDS" | grep "$pattern" | head -3 | sed 's/^+//' | sed 's/^/ /')
            FINDINGS="${FINDINGS} #${FINDING_COUNT} [${cwe}] ${sev}: ${desc} (${matches} hits)\n${lines}\n\n"
            echo -e " ${RED}[${cwe}]${NC} ${sev}: ${desc} (${matches})"
        fi
    }

    # Critical patterns (should NEVER appear in new code)
    check_cwe 'system(\|popen(' 'CWE-78' 'CRITICAL' 'Command injection'
    check_cwe 'gets(' 'CWE-120' 'CRITICAL' 'gets() buffer overflow'
    check_cwe 'sprintf(' 'CWE-120' 'HIGH' 'sprintf without bounds'
    check_cwe 'strcpy(' 'CWE-120' 'HIGH' 'strcpy without bounds'
    check_cwe 'rand()\b' 'CWE-330' 'HIGH' 'Weak PRNG (use randombytes)'
    check_cwe 'LOG.*_sk\[' 'CWE-532' 'HIGH' 'Secret key in log'

    # Medium patterns (review needed)
    check_cwe 'atoi(' 'CWE-190' 'MEDIUM' 'Unchecked integer parse'
    check_cwe 'fopen(' 'CWE-59' 'MEDIUM' 'fopen may follow symlinks'

    # Info patterns
    check_cwe 'TODO\|FIXME\|HACK\|XXX' 'REVIEW' 'INFO' 'Flagged for review'
    echo ""
else
    FINDING_COUNT=0
    FINDINGS="(skipped in --quick mode)"
    echo -e "${YELLOW}[3/5] CWE Pattern Scan${NC} ${GREEN}(skipped in quick mode)${NC}"
fi

# ---- Step 4: Compile findings ----
echo -e "${YELLOW}[4/5] Compile Report${NC}"
{
    echo "============================================"
    echo " MOOR Security Audit — Round $ROUND"
    echo " $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "============================================"
    echo ""
    echo "Base: $(cat "$RDIR/snapshot.sha")"
    echo "Files changed: $NCHANGED"
    echo "Lines added: +$ADDITIONS"
    echo ""
    echo "=== Static Analysis ==="
    echo "cppcheck: ${CPP_ERRORS} errors, ${CPP_WARNINGS} warnings"
    echo "flawfinder: ${FF_HIGH} high, ${FF_MED} medium"
    echo "scan-build: ${SB_BUGS} findings"
    echo ""
    echo "=== CWE Pattern Scan ==="
    if [[ $FINDING_COUNT -eq 0 ]]; then
        echo "No critical/high CWE patterns in changed code."
    else
        echo -e "$FINDINGS"
    fi
    echo ""
    echo "=== Static Analysis Details ==="
    echo ""
    echo "--- cppcheck errors/warnings ---"
    grep -E '\(error\)|\(warning\)' "$RDIR/cppcheck.log" 2>/dev/null || echo "(none)"
    echo ""
    echo "--- flawfinder level 3+ ---"
    grep -E '^\s+\[[3-5]\]' "$RDIR/flawfinder.log" 2>/dev/null || echo "(none)"
    echo ""
    echo "--- scan-build ---"
    grep 'warning:' "$RDIR/scanbuild.log" 2>/dev/null || echo "(none)"
} > "$RDIR/findings.txt"

# Strip whitespace
CPP_ERRORS=$(echo "$CPP_ERRORS" | tr -d '[:space:]')
CPP_WARNINGS=$(echo "$CPP_WARNINGS" | tr -d '[:space:]')
FF_HIGH=$(echo "$FF_HIGH" | tr -d '[:space:]')
FF_MED=$(echo "$FF_MED" | tr -d '[:space:]')
SB_BUGS=$(echo "$SB_BUGS" | tr -d '[:space:]')
: "${CPP_ERRORS:=0}" "${CPP_WARNINGS:=0}" "${FF_HIGH:=0}" "${FF_MED:=0}" "${SB_BUGS:=0}"

TOTAL=$((CPP_ERRORS + FF_HIGH + SB_BUGS + FINDING_COUNT))

echo " Total findings: $TOTAL"
echo " Report: $RDIR/findings.txt"
echo ""

# ---- Step 5: Summary ----
echo -e "${YELLOW}[5/5] Summary${NC}"
{
    echo "MOOR Security Audit Summary"
    echo "==========================="
    echo ""
    echo "Round $ROUND — $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo " cppcheck: ${CPP_ERRORS} errors, ${CPP_WARNINGS} warnings"
    echo " flawfinder: ${FF_HIGH} high, ${FF_MED} medium"
    echo " scan-build: ${SB_BUGS} findings"
    echo " CWE patterns: ${FINDING_COUNT} in changed code"
    echo " TOTAL: ${TOTAL}"
    echo ""
    if [[ $TOTAL -eq 0 ]]; then
        echo "STATUS: [:)] CLEAN"
        touch "$AUDIT_DIR/CLEAN"
    else
        echo "STATUS: [!] ${TOTAL} findings need review"
        rm -f "$AUDIT_DIR/CLEAN"
    fi
} > "$AUDIT_DIR/summary.txt"

cat "$AUDIT_DIR/summary.txt"

if [[ $TOTAL -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}${BOLD}AUDIT CLEAN — no critical findings.${NC}"
    echo -e "${GREEN}Run './security-audit.sh --report' to view full report.${NC}"
else
    echo ""
    echo -e "${RED}${BOLD}${TOTAL} findings need review.${NC}"
    echo -e "${YELLOW}Review: cat $RDIR/findings.txt${NC}"
    echo -e "${YELLOW}After fixing: ./security-audit.sh (runs round $((ROUND+1)))${NC}"
fi
