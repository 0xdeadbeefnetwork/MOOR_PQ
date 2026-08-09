/*
 * build_id.c — exposes the git commit hash this binary was built from.
 *
 * This file is recompiled on every `make` so moor_build_id reflects HEAD.
 * The string is passed via -DMOOR_BUILD_ID=... from the Makefile recipe
 * (shell command substitution at build time).
 *
 * F-06: this is an operational identifier, NOT a security control. It is a
 * self-asserted string the relay writes into its own descriptor and signs;
 * a signature over a self-asserted value proves only self-assertion. The DA
 * prints it in the startup banner and (advisory) rejects descriptors whose
 * build_id differs from its own to keep a fleet on a single commit, but
 * that gate cannot stop a malicious or downgraded binary from declaring
 * whatever string is required. Wire/version integrity is enforced through
 * MOOR_MIN_PROTOCOL_VERSION and the NODE_FEATURES_REQUIRED bitmask; genuine
 * binary attestation would require release-signing keys or reproducible builds.
 */
#include "moor/moor.h"
#include <string.h>

#ifndef MOOR_BUILD_ID
#define MOOR_BUILD_ID "unknown"
#endif

/* 16-byte buffer, NUL-padded.  Wire-visible via descriptor.build_id.
 * Store as plain char array (not string) so strncmp is well-defined even if
 * the hash is exactly 16 bytes with no terminator. */
const char moor_build_id[16] = MOOR_BUILD_ID;
