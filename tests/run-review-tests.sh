#!/usr/bin/env bash
# Build and run the review regression tests.
#
# These need libsodium + zlib headers. If they are not installed system-wide,
# this script fetches the distro packages and unpacks them into a local prefix
# under ~/.cache/moor-review-tests -- no root, nothing installed on the system.
#
#   ./tests/run-review-tests.sh
#
# Covers: F-01/F-03/F-04 (path diversity), F-05/F-26 (PQ + upgrade floor),
#         F-15 (ML-KEM-768 and ML-DSA-65 against NIST vectors),
#         F-06 (seccomp arch gate), F-10/F-11/F-19 (log redaction),
#         F-09/F-18 (key store), F-20/F-21/F-27 (descriptor + consensus bounds),
#         F-15 (the SOCKS5 request parser on its own).
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
# The prefix below holds fetched .debs and unpacked headers/archives -- it is
# expensive to rebuild (needs network + apt-get download) and must survive a
# reboot, so it lives in the XDG cache, not /tmp. Override with MOOR_TEST_WORK.
WORK=${MOOR_TEST_WORK:-${XDG_CACHE_HOME:-$HOME/.cache}/moor-review-tests}
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
        ( cd "$WORK/debs" && apt-get download \
            libsodium-dev libsodium23 zlib1g-dev \
            libevent-dev libevent-2.1-7t64 libevent-core-2.1-7t64 \
            libevent-extra-2.1-7t64 libevent-pthreads-2.1-7t64 >/dev/null 2>&1 )
        for d in "$WORK"/debs/*.deb; do dpkg -x "$d" "$PREFIX/"; done
    fi
    SOD_INC="-I$PREFIX/usr/include"
    SOD_LIB="$PREFIX/usr/lib/x86_64-linux-gnu/libsodium.a"
    Z_LIB="$PREFIX/usr/lib/x86_64-linux-gnu/libz.a"
    echo "using local prefix $PREFIX"
fi

INC="-Iinclude -Isrc/pqclean -Isrc/pqclean/common -Itests $SOD_INC"
WARN="-Wall -Wextra -O2"

# Scalar PQClean only: keccak2x is ARM NEON, keccak4x needs -mavx2.
CORE="src/node.c src/crypto.c src/geoip.c src/falcon.c src/kem.c src/log.c
      src/pqclean/falcon_512/*.c
      src/pqclean/common/fips202.c src/pqclean/common/sha2.c
      src/pqclean/common/aes.c src/randombytes_moor.c
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

# F-15: the PQ primitives against NIST's own vectors. These are the tests that
# say the post-quantum claim is true, so they run even though they are slower.
KEM_SRC="src/kem.c src/log.c src/pqclean/common/fips202.c
         src/randombytes_moor.c src/pqclean/ml_kem_768/*.c"
DSA_SRC="src/sig.c src/log.c src/pqclean/common/fips202.c
         src/randombytes_moor.c src/pqclean/ml_dsa_65/*.c"
# shellcheck disable=SC2086
run test_kyber_kat tests/test_kyber_kat.c $KEM_SRC $SOD_LIB -lm
# shellcheck disable=SC2086
run test_mldsa_kat tests/test_mldsa_kat.c $DSA_SRC $SOD_LIB -lm

# Full crypto-layer source set, used by the seal and key-store tests.
KS_SRC="src/crypto.c src/log.c src/kem.c src/sig.c src/falcon.c
        src/randombytes_moor.c src/pqclean/common/fips202.c
        src/pqclean/common/sha2.c src/pqclean/common/aes.c
        src/pqclean/ml_kem_768/*.c src/pqclean/ml_dsa_65/*.c
        src/pqclean/falcon_512/*.c"

# F-13: pq_seal binds its KEM ciphertext (wire change, protocol v5).
# shellcheck disable=SC2086
run test_pq_seal tests/test_pq_seal.c $KS_SRC $SOD_LIB -lm

# F-09/F-18: key-store hardening, against real files in a scratch dir.
# shellcheck disable=SC2086
run test_keystore tests/test_keystore.c $KS_SRC $SOD_LIB -lm

# F-20/F-21/F-27: needs the whole library, so it links the built objects rather
# than a source subset. Requires `make` to have run; skipped with a note if not.
if [ -d obj ] && [ -n "$(find obj -name '*.o' -print -quit 2>/dev/null)" ]; then
    OBJS=$(find obj -name '*.o' ! -name 'main.o' | tr '\n' ' ')
    EV_LIB=""
    [ -n "$SOD_INC" ] && EV_LIB="$PREFIX/usr/lib/x86_64-linux-gnu/libevent.a $PREFIX/usr/lib/x86_64-linux-gnu/libevent_pthreads.a" || EV_LIB="-levent -levent_pthreads"
    # shellcheck disable=SC2086
    run test_descriptor_bounds tests/test_descriptor_bounds.c $OBJS $SOD_LIB $EV_LIB $Z_LIB -lm -lpthread
    # SOCKS5 request parser, split out of the handler 2026-09-12 (F-15).
    # shellcheck disable=SC2086
    run test_socks5_parse tests/test_socks5_parse.c $OBJS $SOD_LIB $EV_LIB $Z_LIB -lm -lpthread
else
    printf '\n=== test_descriptor_bounds ===\n  skipped: run make first (needs obj/*.o)\n'
fi

printf '\n%s\n' "$( [ $fail -eq 0 ] && echo 'ALL REVIEW TESTS PASSED' || echo 'FAILURES -- see above' )"
exit $fail
