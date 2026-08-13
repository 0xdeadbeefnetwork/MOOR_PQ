#!/bin/sh
# MOOR_PQ — Windows build fix.
#
# Run from the repo root in the MSYS2 MINGW64 shell:
#     sh fix-windows.sh
#
# Uses `grep -v -F` rather than sed: fixed-string matching has no regex or
# quoting hazards and is immune to CRLF line endings, which is what corrupted
# src/directory.c and src/socks5.c into the literal text "d;".
#
# Idempotent — safe to run twice.
set -e

if [ ! -f Makefile ] || [ ! -d src ]; then
    echo "error: run this from the MOOR_PQ repo root" >&2
    exit 1
fi

# --- 1. Undo any prior mangling ---------------------------------------------
echo "==> restoring src/ and include/ from git"
git checkout -- src/ include/

# --- 2. Remove the defines that shadow the compat layer ---------------------
# These come AFTER -include compat_win.h, so they override it. A blanket
# `#define close closesocket` also catches real file descriptors (PID file,
# config, keys), which is the bug the compat layer exists to fix.
echo "==> removing shadowing defines"
for f in src/bridgedb.c src/bw_auth.c src/connection.c src/crypto.c src/dht.c \
         src/directory.c src/hidden_service.c src/main.c src/monitor.c \
         src/onionbalance.c src/relay.c src/socks5.c src/transport_nether.c \
         src/transport_scramble.c; do
    [ -f "$f" ] || continue
    grep -v -F '#define close closesocket' "$f" \
      | grep -v -F '#define poll WSAPoll' \
      | grep -v -F '#define mkdir(p, m) _mkdir(p)' > "$f.tmp"
    mv "$f.tmp" "$f"
done

# --- 3. POSIX header shims ---------------------------------------------------
# dns_server.c, exit_notice.c and socks5.c include these unconditionally.
# Shimming them means those three files need no edits at all.
echo "==> creating compat/win shims"
mkdir -p compat/win/sys compat/win/netinet compat/win/arpa
for h in sys/socket.h sys/time.h sys/uio.h netinet/in.h netinet/tcp.h \
         arpa/inet.h poll.h netdb.h; do
    printf '/* Windows shim -> MOOR compat layer */\n#include "moor/compat_win.h"\n' \
        > "compat/win/$h"
done

# --- 4. Put compat_win.h where the shims can find it ------------------------
# The shims use #include "moor/compat_win.h", which resolves via -Iinclude.
# A copy at the repo root does NOT satisfy that.
if [ -f compat_win.h ] && [ ! -f include/moor/compat_win.h ]; then
    echo "==> moving compat_win.h to include/moor/"
    cp compat_win.h include/moor/compat_win.h
fi

# --- 5. Report --------------------------------------------------------------
echo
echo "==> verification"
bad=$(grep -rl '^d;' src/*.c 2>/dev/null | wc -l)
stale=$(grep -rn '#define close closesocket' src/*.c 2>/dev/null | wc -l)
shims=$(find compat/win -name '*.h' | wc -l)
echo "    corrupted 'd;' lines : $bad   (must be 0)"
echo "    stale defines        : $stale   (must be 0)"
echo "    header shims         : $shims   (must be 8)"
[ -f include/moor/compat_win.h ] && echo "    include/moor/compat_win.h : present" \
                                 || echo "    include/moor/compat_win.h : MISSING <-- copy it there"
[ -f src/compat_win.c ] && echo "    src/compat_win.c          : present" \
                        || echo "    src/compat_win.c          : MISSING <-- copy it there"
echo
echo "Two manual edits remain (see the message that came with this script):"
echo "  1. include/moor/log.h  -- gnu_printf archetype (kills ~40 %zu warnings)"
echo "  2. Makefile            -- add \$(SRCDIR)/compat_win.c to SOURCES (needed to link)"
