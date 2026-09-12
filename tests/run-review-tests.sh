#!/usr/bin/env bash
# Build and run the review regression tests.
#
# These need libsodium + zlib headers. If they are not installed system-wide,
# this script fetches the distro packages and unpacks them into a local prefix
# -- no root, nothing installed on the system.
#
#   ./tests/run-review-tests.sh
#
# Covers: F-01/F-03/F-04 (path diversity), F-05 (PQ mandatory),
#         F-06 (seccomp arch gate), F-10/F-11/F-19 (log redaction).
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
WORK=${MOOR_TEST_WORK:-/tmp/moor-review-tests}
mkdir -p "$WORK"

# ---- dependency prefix ------------------------------------------------
if pkg-config --exists libsodium 2>/dev/null && [ -f /usr/include/zlib.h ]; then
    SOD_INC=""; SOD_LIB="-lsodium"; Z_LIB="-lz"
    echo "using system libsodium + zlib"
else
    PREFIX=$WORK/local
    if [ ! -f "$PREFIX/usr/include/sodium.h" ]; then
        echo "fetching libsodium + zlib into $PREFIX (no root, nothing installed)"
        mkdir -p "$WORK/debs" "$PREFIX"
        ( cd "$WORK/debs" && apt-get download libsodium-dev libsodium23 zlib1g-dev >/dev/null 2>&1 )
        for d in "$WORK"/debs/*.deb; do dpkg -x "$d" "$PREFIX/"; done
    fi
    SOD_INC="-I$PREFIX/usr/include"
    SOD_LIB="$PREFIX/usr/lib/x86_64-linux-gnu/libsodium.a"
    Z_LIB="$PREFIX/usr/lib/x86_64-linux-gnu/libz.a"
    echo "using local prefix $PREFIX"
fi

INC="-Iinclude -Isrc/pqclean -Isrc/pqclean/common $SOD_INC"
WARN="-Wall -Wextra -O2"

# Scalar PQClean only: keccak2x is ARM NEON, keccak4x needs -mavx2.
CORE="src/node.c src/crypto.c src/geoip.c src/falcon.c src/kem.c src/log.c
      src/pqclean/falcon_512/*.c
      src/pqclean/common/fips202.c src/pqclean/common/sha2.c
      src/pqclean/common/aes.c src/pqclean/common/randombytes.c
      src/pqclean/ml_kem_768/*.c"
LIBS="$SOD_LIB $Z_LIB -lm -lpthread"

fail=0
run() {  # run <name> <sources...> [extra flags]
    local name=$1; shift
    printf '\n=== %s ===\n' "$name"
    # shellcheck disable=SC2086
    if ! gcc $WARN $INC -o "$WORK/$name" "$@" 2>"$WORK/$name.build"; then
        echo "BUILD FAILED -- see $WORK/$name.build"; sed -n '1,10p' "$WORK/$name.build"; fail=1; return
    fi
    "$WORK/$name" || fail=1
}

# log redaction + the out_len==0 underflow, under ASan
printf '\n=== test_log_redact (ASan) ===\n'
if gcc -Wall -Wextra -O1 -g -fsanitize=address -Iinclude \
       -o "$WORK/test_log_redact" src/log.c tests/test_log_redact.c 2>"$WORK/log.build"; then
    "$WORK/test_log_redact" || fail=1
else
    echo "BUILD FAILED"; sed -n '1,10p' "$WORK/log.build"; fail=1
fi

# seccomp architecture gate (installs a real filter in a forked child)
run test_sandbox_arch src/sandbox.c src/log.c tests/test_sandbox_arch.c

# shellcheck disable=SC2086
run test_path_diversity tests/test_path_diversity.c $CORE $LIBS
# shellcheck disable=SC2086
run test_pq_mandatory   tests/test_pq_mandatory.c   $CORE $LIBS

printf '\n%s\n' "$( [ $fail -eq 0 ] && echo 'ALL REVIEW TESTS PASSED' || echo 'FAILURES -- see above' )"
exit $fail
