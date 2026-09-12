# MOOR_PQ — source review fixes, `review-fixes` branch

A source review of this tree, carried out 2026-09-11 and fixed 2026-09-12, against
upstream `6fd7743` (`0xdeadbeefnetwork/MOOR_PQ`). Everything below is on the
`review-fixes` branch of this fork; `main` here is left equal to upstream.

**Finding numbers in this file are not the same series as
`CHANGELOG.audit-fixes.md`.** That file covers a separate audit of 2026-08-09 with
its own F-01…F-10 against HEAD `98bb70c`. The two numberings collide and are
unrelated — this round's F-07 is not that round's F-07.

**27 findings: 23 closed, 1 partly closed, 1 dismissed by design, 2 open.** A
finding is only counted closed when a regression test covers it; the suite is
`./tests/run-review-tests.sh`, nine binaries, one of them under AddressSanitizer.

---

## ⚠️ This branch bumps the wire protocol to 5 — it is a flag day

`moor_crypto_pq_seal()` now binds the KEM ciphertext into the sealed blob, so a
v4 peer cannot open a v5 seal. `MOOR_PROTOCOL_VERSION` and
`MOOR_MIN_PROTOCOL_VERSION` both move to 5, and the floor is enforced at client
relay selection as well as at the directory authority.

**A client running this branch refuses to build circuits through any relay below
v5.** On a network that still has v4 relays, those become unreachable rather than
degrading quietly. That is deliberate — a silent fallback is the downgrade path the
README says does not exist — but it means this branch is not a drop-in upgrade for
one relay at a time.

## What changed, by area

### Path selection
Relay family diversity was implemented and then skipped at runtime: the check sat
behind a GeoIP database the project does not ship, so with no GeoIP file present
no diversity constraint applied at all. The family check now runs on its own —
family is a declaration relays make about themselves and needs no geography. The
guard is diversity-checked against the rest of the path, and the diverse-selection
helper fails closed (returns nothing) rather than returning a relay that does not
satisfy the constraint, which previously made a captured path indistinguishable
from a diverse one. Constraints are enforced where candidates are filtered rather
than at each call site.

### Post-quantum handshake
Hybrid PQ is mandatory with no configuration path to disable it; a config key that
did so was added during the fixes and removed again for that reason. The vendored
PQClean tree is byte-identical to upstream, and its `randombytes()` return value —
discarded upstream, so an RNG failure was invisible — is handled by supplying
MOOR's own `randombytes()` at the seam PQClean documents for integrators, not by
patching the vendored code. ML-KEM-768 and ML-DSA-65 now have Known Answer Tests
against the NIST vectors; the project previously shipped neither.

### Sandbox
The seccomp filter had no architecture check, so on a mismatched personality the
syscall numbers in the allowlist denote different calls than intended. An
architecture gate is now the filter's first instruction. Separately, the directory
authority's worker pool was created before the filter was installed — and
`prctl(PR_SET_SECCOMP)` covers only the calling thread plus threads created after
it, so exactly the threads handling untrusted client sockets ran unsandboxed. Pool
creation now happens after the filter.

### Parsers and bounds
Descriptor and consensus parsing gained bounds that were missing: a consensus
declaring more authority signatures than there are slots for is clamped rather
than indexed past, a maximally-populated descriptor round-trips through the
signing serialiser, and the recursive consensus-verify path no longer grows its
stack with input. Four libFuzzer harnesses cover the untrusted parsers
(`docs/building.md` has the build and its pitfalls); seventeen further harnesses
the Makefile declares still do not exist.

### Keys, logging, control port
Key files carry an integrity MAC and a file without one is refused by default,
with an explicit one-time migration for installs that predate it. Key directories
are tightened to 0700 when found wider. Log redaction covers IPv6 literals, which
previously survived it. Control-port authentication throttling is no longer
per-connection, so the attempt limit is not reset by reconnecting.

### Install path and build
The documented install was a script piped from a URL into a root shell, which then
cloned whatever the default branch happened to be. `setup.sh` now builds the
checkout it is run from — what an operator reads is what gets installed — and dies
with instructions if piped. A `--fetch` mode takes a full 40-character commit id,
refuses a branch or tag, and refuses a tree that does not resolve to exactly that
commit. The GeoIP step fetched a file from another project's default branch that
was removed from it in March 2024, so it had been failing silently on every fresh
install; the database now comes from the distribution's package, verified by the
package manager, extracted without installing the daemon it depends on.

`./configure` now probes libevent, which the Makefile links unconditionally and
configure never checked, and records it — so a missing libevent fails at configure
time instead of midway through a build, and `make` needs no environment. An rpath
is no longer emitted for a multiarch distribution libdir (the previous check
compared against `/usr/lib` exactly, so `/usr/lib/x86_64-linux-gnu` fell through
and every packaged binary carried one). Builds no longer embed the build
directory, `make release` splits debug info out of the installed binary, and
`make` refuses a dirty tree so the compiled build id cannot name a commit that was
not compiled.

## Not addressed here

Two findings remain open and are not code changes this branch can make. One is a
deployment property of the directory-authority trust root rather than a defect in
the source. The other is a resource concern in the handshake receive path, where a
peer that sends slowly occupies a thread for the duration of the timeout. Both were
recorded with the analysis kept out of this public file; the fuzz harnesses that do
not exist, and the absence of any ThreadSanitizer pass over sixteen
`pthread_create` sites, are the other known gaps.
