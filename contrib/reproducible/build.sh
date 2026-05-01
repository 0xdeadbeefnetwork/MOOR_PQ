#!/bin/bash
# Build moor deterministically inside the pinned container image.
#
# Two invocations of this script (in clean trees from the same git
# revision) must produce byte-identical `moor` binaries. Drift here
# is a packaging bug, not an acceptable variation.
#
# Usage (from repo root):
#   contrib/reproducible/build.sh                # uses HEAD
#   contrib/reproducible/build.sh <git-ref>      # checks out a ref first

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

REF="${1:-HEAD}"
[ "$REF" != "HEAD" ] && git checkout --quiet "$REF"

# Pin SOURCE_DATE_EPOCH to the commit's authored timestamp so debug
# info, archive headers, and any embedded timestamps match across
# rebuilds of the same source.
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$REF")"
export SOURCE_DATE_EPOCH

# Strip per-build paths from debug info and any __FILE__ macros.
# Preserve hardening flags from the upstream Makefile.
EXTRA="-ffile-prefix-map=$REPO_ROOT=. -fdebug-prefix-map=$REPO_ROOT=."

# Force C locale for any tooling that emits localized text into objects.
export LC_ALL=C
export LANG=C
export TZ=UTC

# Honour an explicit build_id if the caller provided one (e.g. CI
# stamps the short git hash). Otherwise the Makefile derives it.
if [ -n "${MOOR_BUILD_ID:-}" ]; then
    BUILD_ID_FLAG="MOOR_BUILD_ID=$MOOR_BUILD_ID"
else
    BUILD_ID_FLAG=""
fi

make -j"$(nproc)" \
     EXTRA_CFLAGS="$EXTRA" \
     $BUILD_ID_FLAG

# Print a summary the caller can grep / compare.
echo "----"
echo "moor build summary"
echo "  ref:                $(git rev-parse "$REF")"
echo "  SOURCE_DATE_EPOCH:  $SOURCE_DATE_EPOCH"
echo "  binary sha256:      $(sha256sum moor | cut -d' ' -f1)"
echo "  binary size:        $(stat -c%s moor) bytes"
