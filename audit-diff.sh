#!/bin/bash
# audit-diff.sh — Audit only NEW or CHANGED code since last snapshot
#
# Usage:
#   ./audit-diff.sh              # audit changes since last commit
#   ./audit-diff.sh <commit>     # audit changes since specific commit
#   ./audit-diff.sh --snapshot   # save current state as baseline
#
# Runs cppcheck + flawfinder on ONLY the changed lines.
# Highlights potential CWE patterns in new code.

set -euo pipefail
cd "$(dirname "$0")"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

SNAPSHOT_REF="${1:-HEAD}"

if [[ "${1:-}" == "--snapshot" ]]; then
    git stash 2>/dev/null || true
    HASH=$(git rev-parse HEAD)
    git stash pop 2>/dev/null || true
    echo "$HASH" > .audit-snapshot
    echo -e "${GREEN}Snapshot saved: $HASH${NC}"
    exit 0
fi

# Use snapshot ref if it exists
if [[ -f .audit-snapshot ]]; then
    SNAPSHOT_REF=$(cat .audit-snapshot)
    echo -e "${CYAN}Auditing changes since snapshot: ${SNAPSHOT_REF:0:8}${NC}"
else
    echo -e "${CYAN}Auditing changes since: $SNAPSHOT_REF${NC}"
fi

# Get list of changed C files
CHANGED=$(git diff --name-only "$SNAPSHOT_REF" -- 'src/*.c' 'include/*.h' 2>/dev/null || \
          git diff --name-only HEAD -- 'src/*.c' 'include/*.h' 2>/dev/null)

if [[ -z "$CHANGED" ]]; then
    echo -e "${GREEN}No C source changes to audit.${NC}"
    exit 0
fi

NFILES=$(echo "$CHANGED" | wc -l)
echo -e "${YELLOW}Changed files: $NFILES${NC}"
echo "$CHANGED" | sed 's/^/  /'
echo ""

# Count new/changed lines
ADDITIONS=$(git diff "$SNAPSHOT_REF" -- 'src/*.c' 'include/*.h' 2>/dev/null | grep '^+[^+]' | wc -l || echo 0)
DELETIONS=$(git diff "$SNAPSHOT_REF" -- 'src/*.c' 'include/*.h' 2>/dev/null | grep '^-[^-]' | wc -l || echo 0)
echo -e "${YELLOW}Lines: +${ADDITIONS} / -${DELETIONS}${NC}"
echo ""

# === CWE Pattern Scan on NEW lines only ===
echo -e "${CYAN}=== CWE Pattern Scan (new lines only) ===${NC}"

DIFF_ADDS=$(git diff "$SNAPSHOT_REF" -- 'src/*.c' 2>/dev/null | grep '^+[^+]' || true)

check_pattern() {
    local pattern="$1"
    local cwe="$2"
    local desc="$3"
    local matches=$(echo "$DIFF_ADDS" | grep -c "$pattern" 2>/dev/null || true)
    if [[ $matches -gt 0 ]]; then
        echo -e "  ${RED}[$cwe]${NC} $desc ($matches occurrences)"
        echo "$DIFF_ADDS" | grep --color=always "$pattern" | head -5 | sed 's/^/    /'
        echo ""
    fi
}

check_pattern 'memcpy\|memmove\|memset' 'CWE-120' 'Buffer copy — check bounds'
check_pattern 'sprintf(' 'CWE-120' 'sprintf without bounds — use snprintf'
check_pattern 'strcpy(' 'CWE-120' 'strcpy without bounds — use strncpy'
check_pattern 'strcat(' 'CWE-120' 'strcat without bounds — use strncat'
check_pattern 'gets(' 'CWE-120' 'gets() — NEVER use this'
check_pattern 'malloc\|calloc\|realloc' 'CWE-401' 'Heap alloc — check for matching free'
check_pattern 'free(' 'CWE-416' 'free() — check for use-after-free'
check_pattern 'fopen\b' 'CWE-59' 'fopen — check for symlink following'
check_pattern 'system(\|popen(' 'CWE-78' 'Command injection — NEVER in security code'
check_pattern 'rand()\|srand(' 'CWE-330' 'Weak PRNG — use randombytes_buf'
check_pattern 'memcmp(' 'CWE-208' 'Non-constant-time comparison — use sodium_memcmp for secrets'
check_pattern 'atoi\|atol\|atof' 'CWE-190' 'No-error integer parse — use strtol with checks'
check_pattern 'LOG_.*identity_sk\|LOG_.*secret\|LOG_.*_sk\[' 'CWE-532' 'Secret key in log output'
check_pattern 'TODO\|FIXME\|HACK\|XXX\|BROKEN' 'REVIEW' 'Flagged for review'

# === cppcheck on changed files ===
echo -e "${CYAN}=== cppcheck (changed files only) ===${NC}"
if command -v cppcheck &>/dev/null; then
    cppcheck --enable=warning,style,performance --std=c11 \
        --suppress=missingIncludeSystem --suppress=unusedFunction \
        -Iinclude -Isrc/kyber -Isrc/dilithium --force \
        $CHANGED 2>&1 | grep -v 'Checking\|files checked\|^$' | head -30
    echo ""
else
    echo "  cppcheck not installed, skipping"
fi

# === flawfinder on changed files ===
echo -e "${CYAN}=== flawfinder (changed files only) ===${NC}"
if command -v flawfinder &>/dev/null; then
    flawfinder --minlevel=2 --columns $CHANGED 2>/dev/null | \
        grep -v 'Flawfinder\|Number\|Examining\|^$\|ANALYSIS\|Hits\|Lines\|Physical\|inhibit\|There may' | head -30
    echo ""
else
    echo "  flawfinder not installed, skipping"
fi

# === Summary ===
echo -e "${CYAN}=== Summary ===${NC}"
echo -e "  Files changed: $NFILES"
echo -e "  Lines added:   $ADDITIONS"
echo -e "  Lines removed: $DELETIONS"
echo ""
echo -e "${GREEN}Run './audit-diff.sh --snapshot' after fixing issues to reset baseline.${NC}"
