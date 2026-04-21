# Security

## Threat model

MOOR protects against:

- **Network observers** who can see traffic between any two points but cannot observe all links simultaneously
- **Malicious relays** who control fewer than all three hops in a circuit
- **Future quantum adversaries** performing harvest-now-decrypt-later attacks on recorded traffic
- **DPI censors** using protocol fingerprinting, entropy analysis, or active probing (mitigated via pluggable transports and the relay ingress honeypot)

MOOR does **not** protect against:

- **Global passive adversaries** who can observe every network link and correlate timing end-to-end
- **Compromised endpoints** — your machine or the destination
- **All three hops controlled by the same adversary**

## Post-quantum cryptography

Every key exchange and every signature in MOOR is a **hybrid** of a classical primitive and a NIST-standardized post-quantum primitive. An attacker must break **both** to recover a secret or forge an identity. Verification is **sequential-AND**: there is no "fall back to classical" path.

| Layer | Classical | Post-quantum | Combination |
|-------|-----------|--------------|-------------|
| Link handshake (Noise_IK + post-handshake KEM) | X25519 | ML-KEM-768 | HKDF-BLAKE2b(Noise_chain ‖ kem_ss) |
| Circuit key exchange per hop | X25519 ECDH | ML-KEM-768 | HKDF-BLAKE2b(dh_result ‖ kem_ss) |
| Onion cell encryption | ChaCha20 | keys are PQ-derived | — |
| HS end-to-end INTRODUCE1 | X25519 + ChaCha20-Poly1305 | ML-KEM-768 sealing | kem_ct (1088 B) ‖ aead_ct ‖ tag |
| HS descriptor signing | Ed25519 | Falcon-512 | sequential-AND verify |
| `.moor` address commitment | — | BLAKE2b-16(ML-KEM_pk ‖ Falcon_pk) hashed into address | address itself binds both PQ keys |
| Consensus signatures | Ed25519 | ML-DSA-65 | sequential-AND verify |

**Parameters:**

- ML-KEM-768 — NIST FIPS 203 (Kyber), 1184-byte public key, 1088-byte ciphertext, 32-byte shared secret. NIST security level 3 (~192-bit quantum security).
- ML-DSA-65 — NIST FIPS 204 (Dilithium3), 1952-byte public key, 3309-byte signature. NIST level 3.
- Falcon-512 — NIST FN-DSA, 897-byte public key, ~666-byte average signature (variable). NIST level 1, chosen for HS descriptors because of its compact signature size.

## What's strong

- **Classical primitives** via **libsodium** — audited, constant-time, widely reviewed. X25519, Ed25519, ChaCha20-Poly1305, XChaCha20-Poly1305, BLAKE2b, Argon2id.
- **Post-quantum primitives** vendored from **PQClean** — the NIST reference implementations, not a separate rewrite. No liboqs dependency. Pinned in-tree so behavior never changes under us.
- **Noise_IK** for the link handshake — formally analyzed pattern.
- **Sequential-AND verification** everywhere — no downgrade paths, no fallback to classical-only, no "PQ optional" flag.
- **Dual-signed hidden service descriptors** — Ed25519 + Falcon-512. A descriptor with only Ed25519 will not be accepted once Falcon is bound into the address.
- **Address commitment to both PQ keys** — swapping either key invalidates the onion address.
- **Build-ID fleet gate** — directory authorities reject relay descriptors whose git hash differs from the DA's own. Mixed-commit fleets cannot form; cryptographic changes ship with a coordinated upgrade or not at all.
- **Path diversity** — GeoIP + AS + family exclusion on every path selection.
- **Prop 271 guards** — sampled / primary / confirmed guard sets activate at ≥20 relays. Path-bias detection (WARN at 50 % success, EXTREME at 30 %, min 20 circuits).
- **Vanguards** — hidden service circuits pin L2 and L3 vanguards to resist guard discovery via time-correlation of fresh circuits.
- **DoS resistance** — per-IP rate limits, per-connection CREATE rate limits, per-IP circuit-count cap, circuit pool OOM watchdog, extend-pending timeout, connection reaper, idle-circuit eviction, Argon2id PoW gating relay admission (configurable difficulty).
- **Descriptor privacy** — HS descriptors are encrypted with blinded keys per time period; revision is signed; replay is blocked by monotonic counter that is also wall-clock-floored so a warm restart cannot wedge.
- **PIR HS lookup** — the DHT relay storing descriptors cannot learn which onion a client is looking up: clients use 2-server XOR-PIR or DPF-PIR pair queries.
- **Self-loop filter** — a relay's own circuit builder refuses to route through itself even on shared NAT / dev environments.
- **Scanner honeypot** — non-bridge relays intercept DPI probes matching well-known fingerprints and return rotating fake industrial-control banners, poisoning scanning datasets.
- **mlockall(MCL_CURRENT)** — sensitive pages pinned in memory.
- **seccomp-bpf sandbox** — syscall allow-list, no_new_privs, rlimits.

## Known limitations

- **No third-party audit.** An internal audit pass in April 2026 swept cryptographic code, memory safety, concurrency, and DoS resistance, but external review has not happened yet.
- **The code is C.** Stack protector and FORTIFY_SOURCE are on, but memory safety is not proof-grade.
- **Vendored PQ code has not been independently reviewed for this integration.** PQClean is a high-quality reference, but our wiring around it (key serialization, AEAD framing, KDF inputs) is our own and inherits our risk.
- **Global traffic analysis is not defeated.** WTF-PAD, FRONT, volume padding, EWMA scheduling, and conflux raise the cost of correlation but a global passive adversary with full timing visibility can still correlate. This is a fundamental limitation shared with Tor.
- **Small DA set.** The default network uses two directory authorities. A compromised majority (both) could forge consensus. Production-grade deployment needs 5–9 DAs, and enclave operators should deploy accordingly.
- **Per-DA flag voting.** Each DA independently computes relay flags from statistical medians. There is no cross-DA majority vote on flags.
- **Side-channel surface.** libsodium primitives are constant-time and the PQClean primitives aim to be, but surrounding C code has not been formally audited for timing leaks.
- **Onion key lifetime.** Circuit static DH uses Curve25519 onion keys that rotate every 28 days. Compromise of a rotated-out key cannot decrypt past sessions. Identity keys are permanent but only appear in HKDF salt (authentication binding), never in DH.
- **No in-circuit key rotation.** Circuit keys are not rekeyed during a circuit's lifetime; circuits themselves rotate every ~10 minutes. Link-layer rekey runs on an implicit counter trigger.

## Cryptographic dependencies

- **libsodium** — X25519, Ed25519, ChaCha20-Poly1305, XChaCha20-Poly1305, BLAKE2b, Argon2id, constant-time memcmp, secure RNG.
- **Vendored PQClean** (in `src/pqclean/`) — ML-KEM-768, ML-DSA-65, Falcon-512, FIPS 202 (SHA-3 / SHAKE), FIPS 180 (SHA-2), AES.

No OpenSSL. No GnuTLS. No liboqs.

## Responsible disclosure

Report vulnerabilities privately to the project maintainer. Do not open public issues for security bugs.
