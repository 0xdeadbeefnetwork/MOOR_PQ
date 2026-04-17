/*
 * build_id.c — exposes the git commit hash this binary was built from.
 *
 * This file is recompiled on every `make` so moor_build_id always matches HEAD.
 * The string is passed via -DMOOR_BUILD_ID=... from the Makefile recipe
 * (shell command substitution at build time).
 *
 * Purpose: fleet-wide strict version gating.  DAs reject descriptors whose
 * build_id doesn't match the DA's own, so mixed-commit fleets cannot form.
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
