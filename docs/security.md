# Security

## Threat model

MOOR protects against:
- **Network observers** who can see traffic between any two points but cannot observe all links simultaneously
- **Malicious relays** who control fewer than all 3 hops in a circuit
- **Future quantum computers** performing harvest-now-decrypt-later attacks on recorded traffic

MOOR does NOT protect against:
- **Global passive adversaries** who can observe all network links simultaneously and correlate timing
- **Compromised endpoints** (your machine or the destination)
- **All 3 hops controlled by the same adversary**

## Post-quantum security

Every cryptographic key exchange in MOOR is a hybrid of classical X25519 and post-quantum Kyber768. An attacker must break BOTH to recover any secret:

| Layer | Classical | Post-quantum | Hybrid |
|-------|-----------|-------------|--------|
| Link (Noise_IK) | X25519 | Kyber768 | HKDF(DH_key, KEM_shared) |
| Circuit hop 0 | X25519 DH | Kyber768 KEM | BLAKE2b(key_seed \|\| kem_ss) |
| Circuit hop 1 | X25519 DH | Kyber768 KEM | BLAKE2b(key_seed \|\| kem_ss) |
| Circuit hop 2 | X25519 DH | Kyber768 KEM | BLAKE2b(key_seed \|\| kem_ss) |
| Consensus signing | Ed25519 | ML-DSA-65 | Both must verify |

A quantum computer that breaks X25519 cannot decrypt any MOOR traffic without also breaking Kyber768 (NIST Level 3, 192-bit quantum security).

## What's strong

- **Primitives**: All classical crypto via libsodium (audited, constant-time). Ed25519, X25519, ChaCha20-Poly1305, BLAKE2b.
- **Protocol**: Noise_IK handshake is formally analyzed. Circuit key exchange follows proven patterns.
- **PQ**: NIST-standardized ML-KEM-768 and ML-DSA-65. Reference implementations from NIST submission.
- **Consensus**: Dual-signed (Ed25519 + ML-DSA-65) by 2 independent DAs. Both signatures must verify.
- **Path diversity**: GeoIP-aware relay selection avoids same country/AS/family in a circuit.
- **Vanguards**: Hidden service circuits use vanguard relays to resist guard discovery.
- **DoS protection**: Argon2id proof-of-work for relay registration. Per-IP and per-circuit rate limiting.

## Known limitations

- **Audit**: No third-party security audit. Single-developer C codebase.
- **Memory safety**: C with stack protector and FORTIFY_SOURCE, but still C.
- **Vendored PQ code**: Kyber and Dilithium reference implementations have not been independently audited for this integration.
- **Traffic analysis**: Padding machines exist but a global adversary can still correlate timing. This is a fundamental limitation shared with Tor.
- **2-DA network**: Only 2 directory authorities. A compromised majority (both) could forge consensus. Production needs 5-9 DAs.
- **Flag voting**: Each DA independently computes relay flags from statistical medians rather than majority voting across DAs.
- **Side channels**: libsodium primitives are constant-time, but surrounding C code has not been audited for timing leaks.
- **Forward secrecy**: Circuit keys are not rotated during a circuit's lifetime. Circuits rotate every 10 minutes.

## Responsible disclosure

Report vulnerabilities to the project maintainer. Do not open public issues for security bugs.
