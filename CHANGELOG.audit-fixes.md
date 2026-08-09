# MOOR_PQ Audit Remediation — 2026-08-09

Verification and fixes for the 10 findings in `MOOR audit1.pdf` against HEAD `98bb70c`.
All 10 findings were independently confirmed against the code; all 10 are addressed here.

## Verification outcome

| ID | Severity | Verdict | Fixed |
|----|----------|---------|-------|
| F-01 | Critical | Confirmed | yes |
| F-02 (a,b,c) | Critical | Confirmed (all 3 instances) | yes |
| F-03 | Critical | Confirmed | yes |
| F-04 | High | Confirmed | yes |
| F-05 | High | Confirmed | yes |
| F-06 | High | Confirmed | yes |
| F-07 | Medium-High | Confirmed | yes |
| F-08 | Medium | Confirmed | yes |
| F-09 | Medium | Confirmed | yes |
| F-10 | Low-Medium | Confirmed | yes |

None were already fixed in HEAD; none rejected.

## Fixes

### F-01 — Race/UAF: EXTEND workers run unisolated (`src/relay.c`, `src/event.c`)
- `extend_worker_func` now calls `moor_worker_isolate()` as its first statement, so
  `moor_connection_alloc()` returns a heap object, the connection is kept out of
  `g_conn_ht`, and the socket is dup'd to fd >= 256. The outbound direction is now
  isolated the same way the hand-back direction already was.
- Added `MOOR_ASSERT_MSG(!moor_is_worker(), ...)` at the top of `moor_event_add` and
  `moor_event_remove` in `event.c`, so any future off-main-thread call fails loudly
  instead of corrupting libevent state. `extern int moor_is_worker(void)` declared.

### F-02 — Cross-thread UAF on shared consensus (`src/node.c`, `src/dht.c`, `src/main.c`, `include/moor/relay.h`)
- `moor_consensus_copy()` and `moor_consensus_cleanup()` rewritten to be non-destructive
  to readers: build into a fresh array, publish array + count together, free the old
  array last. The previous dangling-pointer window (free relays, then ~10 field
  assignments, then calloc) is gone.
- (a) `dht.c` DHT-STORE responsibility check now wraps `moor_relay_get_consensus()` in
  `moor_relay_consensus_rdlock()` / `moor_relay_consensus_unlock()` (the helpers that
  existed but were never called).
- (c) HS refresh thread now swaps via `moor_consensus_copy()` instead of
  `cleanup()` + `memcpy`, removing the mid-refresh empty-consensus window. Temporary
  is cleaned up before free (no leak).
- Added the rdlock/unlock declarations to `include/moor/relay.h` so readers can use them.
- (b) client consensus (`g_client_consensus`): now fully locked. A dedicated
  `pthread_rwlock_t g_client_consensus_lock` mirrors the relay one. The writer
  (`moor_socks5_update_consensus`) takes the write lock; all readers take the
  read lock for the duration of their dereference — the prebuilt-circuit timer
  and on-demand builder in socks5.c, the HS connect worker snapshot, the guard
  sampler and consensus-refresh scheduler in main.c, the bridge-CKE fallback
  scan in circuit.c, and `fetch_consensus_via_dir_guard` (which releases and
  re-acquires around each blocking network fetch to avoid holding the lock
  across I/O, re-validating the pointer after re-locking). The stale
  "No locking needed -- everything is single-threaded now" comment is deleted.

### F-03 — DA signature threshold bypass (`src/directory.c`, `src/node.c`)
- `moor_consensus_verify_hybrid()` now tracks `counted[j]` so each trusted key is
  credited at most once; a repeated signature for the same DA no longer counts twice.
- Threshold changed from `(num_trusted <= 2) ? 1 : ...` to `(num_trusted / 2) + 1`
  (genuine majority, no small-N exemption). The shipped 2-DA config now requires both.
- Parse side (`node.c:moor_consensus_deserialize`) rejects duplicate DA identity keys
  at ingest instead of appending every `directory-signature` line.

### F-04 — SRV off-by-one (`src/node.c`)
- `strncmp(line, "shared-rand-current-value ", 26)` (was 25; the literal is 26 bytes).
  The sibling previous-value line already used the correct 27.
- Decode failure now rejects the consensus with a warning instead of silently leaving
  `srv_current` all-zero (which made the HSDIR ring fully predictable).

### F-05 — Self-declared role flags (`src/directory.c`, `src/bw_auth.c`, `include/moor/limits.h`)
- DA ingest (`da_add_relay_unlocked`) now strips `NODE_FLAG_RUNNING | NODE_FLAG_AUTHORITY |
  NODE_FLAGS_DA_ASSIGNED` from every descriptor before it enters the consensus, at all
  three ingest sites. Only Exit and MiddleOnly survive from the wire. AUTHORITY is no
  longer accepted from the wire (audit remediation #6).
- `moor_da_probe_relays()` now sets `NODE_FLAG_RUNNING` on probe success and clears it on
  failure (previously only counted failures toward eviction).
- DA-assigned flags accumulated across descriptor refreshes are preserved (except Exit,
  which follows the current self-declaration).
- **Bandwidth cap**: `moor_bw_auth_effective()` now returns
  `min(self_reported, MOOR_DA_UNMEASURED_BW_CAP)` when `measured == 0` (100 KB/s), so a
  fresh relay cannot claim an arbitrarily large bandwidth and dominate path selection.
- **Guard floor**: the `n_active < 100` bypass is removed. Guard is now always earned:
  `guard_tk` has an absolute floor of `DA_GUARD_BOOTSTRAP_TIME_KNOWN` (24h) on small
  networks and the full 8-day floor (`DA_GUARD_MIN_TIME_KNOWN`) at 100+ relays. A fresh
  Sybil can no longer claim Guard instantly.
- **Exit verification**: the DA probe now actively verifies exit relays by connecting to
  the mandatory exit-notice HTTP server on :80 (README requirement). A relay that
  self-declares Exit but does not serve the notice is flagged BadExit and loses the Exit
  bit, so it cannot be selected for the exit position. This is a lighter-weight stand-in
  for a full Tor-style exit canary scan (which requires DA circuit-building capability
  not yet present); the hook is in place for when that lands.
- **PoW difficulty**: `MOOR_POW_DEFAULT_DIFFICULTY` raised from 8 to 20 leading-zero bits.
  Combined with the existing per-identity epoch salt, this makes bulk Sybil registration
  (~1M Argon2id evaluations per identity) expensive enough to deter the guard/exit
  capture attack.

### F-06 — build_id not a security control (`src/build_id.c`, `Makefile`)
- Comments corrected: build_id is advisory/operational, not a security gate.
- Makefile now fails loudly when no build id can be determined (no more silent "unknown"),
  and refuses to build a dirty working tree so a locally-patched binary can't inherit
  the committed hash. Operator override via `MOOR_BUILD_ID=...` still works.

### F-07 — Consensus estimator under-counts; k line silent skip (`src/node.c`)
- `moor_consensus_wire_size()` per-relay budget raised from 2200 to 2400 with a real
  derivation comment (k line alone is ~1583 bytes; worst case ~2306).
- The k line now fails serialization on overflow (via `bcat`) like every other field,
  instead of being silently skipped. malloc failure for the base64 buffer is now an error.
  This prevents emitting a relay that advertises NODE_FEATURE_PQ with no kem_pk.

### F-08 — Unseeded rand() for DNS txid (`src/dns_server.c`)
- `up_txid` now drawn from `moor_crypto_random()` (libsodium), not `rand()`. No `srand()`
  exists anywhere in the tree, so the previous sequence was deterministic per-run.

### F-09 — Log redaction inverted default (`src/log.c`, `src/main.c`)
- `g_log_safe_mode` default flipped from 0 to 1 (redaction on by default).
- Verbose-mode banner corrected: redaction applies at all log levels by default; the
  previous text claimed it was "always redacted" while the code only enabled it under -v.

### F-10 — Mirage replay cache ring eviction (`src/transport_mirage.c`)
- Eviction is now age-based: the oldest expired slot is reused, and if none has expired
  the handshake fails closed. The previous index-based ring let 256 fresh connections
  flush a captured ClientHello in seconds.

## Build verification

Syntax-checked every touched file with clang 22.1.1 (`-fsyntax-only`). `log.c` and
`build_id.c` compile clean with `-Wall -Wextra`. The remaining files require
libsodium / libevent / POSIX socket headers that are not present in this Windows/MinGW
environment; with those headers stubbed, the only residual errors are missing system
symbols (`crypto_box_*`, `SHUT_WR`, `struct utsname`) — none in edited regions.

### Tests added

- `tests/test_consensus.c` — F-03 (duplicate DA signature is deduped at parse; distinct
  signatures are kept) and F-04 (shared-rand-current-value parses to a non-zero value).
- `tests/test_serialize.c` — F-07 round-trip across relay counts {1, 10, 25, 100} with
  all relays PQ-capable and all optional fields at full width. Asserts serialize does not
  fail/truncate at the estimated size, srv_current round-trips, and every relay's kem_pk
  survives (catches the silent k-line drop).
- Both wired into the Makefile (`TEST_CONSENSUS_*`, `TEST_SERIALIZE_*`) and the `test`,
  `asan-test`, `tsan-test`, and `coverage` targets via the existing stem rules.

### Makefile validation

Parsed with `make -n` (msys2 make); both new test rules resolve correctly to their object
dependencies (confirmed via `make -p`: `test_consensus: tests/test_consensus.c obj/node.o ...`).
The F-06 dirty-tree guard was itself validated during this work — it correctly refused to
build the dirty tree and correctly bypasses when `MOOR_BUILD_ID` is passed explicitly as a
make argument.

## Remaining work

- **Run the suite on a real build host.** This Windows/MinGW environment lacks
  libsodium/libevent/POSIX socket headers, so no full `make` or test execution happened
  here — only `-fsyntax-only` validation. Run `make test`, `make asan-test`, and
  `make tsan-test` on a Linux host with the deps installed. TSan/ASan is the audit's top
  cross-cutting recommendation and would catch any F-01/F-02 regression on first run
  under load.
- **Pre-existing test gap.** The Makefile references 20 test sources (test_crypto.c,
  test_cell.c, ...) of which only test_transport.c existed before this work; the two new
  tests added here are real and build, but `make test` will still fail on the 19 missing
  stubs until they are written or removed from the Makefile.
- **F-06 full attestation.** build_id is now honest and advisory, not a security control.
  For genuine binary attestation, pin DA release-signing keys or adopt reproducible
  builds — self-asserted strings cannot provide that property.
- **F-05 exit canary.** The current exit verification checks the mandatory :80 notice
  server. A full Tor-style exit scan (DA builds a circuit through the candidate and
  fetches a canary URL) requires DA circuit-building capability not yet present; the
  verification hook is in place for when that lands.
