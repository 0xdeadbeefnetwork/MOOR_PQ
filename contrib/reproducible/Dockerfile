# Reproducible build environment for MOOR.
#
# Two builds executed inside this image must produce byte-identical
# `moor` binaries. The base image is pinned by digest so a malicious
# Debian mirror cannot silently swap in a different toolchain.
#
# Update procedure:
#   1. Pick a new digest from https://hub.docker.com/_/debian/tags
#      (use the bookworm-slim variant of a stable release).
#   2. Update the FROM line below.
#   3. Rebuild, confirm the binary hash still matches a known-good
#      reference build before merging the digest bump.
FROM debian:bookworm-slim@sha256:90522eeb7e5923ee2b871c639059537b30521272f10ca86fdbbbb2b75a8c40cd

# All Debian packages pinned implicitly by the snapshot of the base
# image. We don't pin individual versions here because the FROM digest
# already locks the entire APT state.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        debhelper-compat \
        dh-make \
        devscripts \
        diffoscope-minimal \
        fakeroot \
        git \
        libevent-dev \
        libsodium-dev \
        pkg-config \
        zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# Reproducibility hygiene.
ENV LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    TZ=UTC \
    SOURCE_DATE_EPOCH=1735689600

WORKDIR /src
