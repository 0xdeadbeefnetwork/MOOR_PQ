# MOOR Implementation Status

Last updated: 2026-04-14

## Overview

~47K lines of C across 64 source files. All features implemented. Fleet operational:
2 DAs, 3 core relays, 20 AWS relays (11 countries), 1 Pi hidden service.

## Completed Features

### Cryptography & Handshakes
- **Noise_IK link handshake** — mutual auth, full forward secrecy
- **PQ Kyber768 hybrid** — post-quantum KEM mixed into Noise_IK session keys
- **DA-to-DA Noise_IK** — replaced hand-rolled DH (2026-04-14)
- **ML-DSA-65 consensus signatures** — hybrid Ed25519 + post-quantum DA sigs
- **Async handshake state machine** — non-blocking Noise_IK + PQ for circuit builds

### Cell Scheduling (SKIPS)
- **EWMA circuitmux** — min-heap priority, tick-based decay, quietest-circuit-first (`channel.c:340-567`)
- **SKIPS scheduler** — TCP_INFO-aware write budgets, RTT-adaptive interval, burst mode (`scheduler.c`)
- **Per-circuit queues** — relay-forward cells deferred to SKIPS, client/HS cells flush directly
- **Backpressure** — checks `outq + circuitmux_total_queued()`, pauses client reads at threshold
- **XOFF/XON flow control** — Prop 344, exit-to-client and client-to-exit

### Traffic Analysis Defenses
- **WTFPad** — adaptive padding state machine on every circuit (`wfpad.c`, 466 lines)
- **Pluggable transports** — 6 implementations:
  - Scramble (635 loc), Shade (653), Speakeasy (707), Nether/Minecraft (612), Mirage (1165), Shitstorm (3116)
- **Poisson mixing** — configurable per-relay mix delay
- **Elligator2** — indistinguishable-from-random key encodings

### Hidden Services
- **v3 HS protocol** — blinded keys, time periods, encrypted descriptors
- **Vanguards** — restricted middle hops (L2/L3) to prevent guard discovery
- **HS PoW DoS protection** — configurable proof-of-work for INTRODUCE2
- **Intro re-establishment** — deferred rebuild with stale ctx purge (fixed 2026-04-14)
- **PQ e2e** — Kyber768 KEM for end-to-end HS circuit key exchange
- **DHT descriptor storage** — PIR and DPF-PIR for private descriptor fetch

### Directory Authority
- **2-DA consensus** — epoch-aligned timestamps with 3s grace window
- **PQ vote exchange** — Ed25519 + ML-DSA-65 dual-signed votes
- **Descriptor propagation** — PROPAGATE with signature verification
- **DA-to-DA sync** — Noise_IK encrypted SYNC_RELAYS (5-min cycle)
- **Relay liveness probing** — PROBE/ALIVE + bandwidth measurement (15-min cycle)
- **Stale relay eviction** — 3-hour threshold, 3-strike probe failure
- **SRV commit-reveal** — shared random values for DHT epoch computation

### Network
- **Conflux multi-path** — circuit leg linking, switching, acknowledgment
- **SENDME flow control** — window-based, per-circuit
- **Connection reaper** — idle connection culling
- **Circuit-level DoS** — CREATE rate limiting, cell token bucket (Prop 305)
- **EXTEND_PQ** — post-quantum circuit extension with concurrency cap
- **GeoIP** — IPv4/IPv6 country + AS lookup, relay flag computation

## Known Issues (Non-Blocking)

- **PQ KEM spin-loops removed** — replaced with poll-based blocking (2026-04-14)
- **Vote divergence at epoch boundary** — 3s grace window added, may still fire once/hour at the boundary; self-heals on next cycle
- **SKIPS only schedules relay-forward path** — client/HS cells flush directly; this is intentional (latency-sensitive paths need immediate send)

## What an Auditor Should Focus On

1. **Noise_IK implementation** — `connection.c:490-900` (handshake), `connection.c:904-1091` (PQ KEM exchange)
2. **Cell encryption** — `connection.c:1274-1460` (send_cell/recv_cell AEAD)
3. **HS descriptor crypto** — `hidden_service.c` (blinded keys, sealed box, descriptor encryption)
4. **DA consensus signing** — `directory.c:619-990` (body hash, Ed25519 + ML-DSA-65 signing, vote verification)
5. **PIR/DPF-PIR** — `dht.c:645-1100` (query/response, privacy guarantees)
6. **Transport obfuscation** — each `transport_*.c` (DPI resistance claims)
7. **EWMA fairness** — `channel.c:340-567` (does the min-heap actually prevent starvation?)
8. **Key management** — identity key generation, storage, rotation; optional hardware-token integration

## Removed Dead Code (2026-04-14)

- `padding_adv.c` / `padding_adv.h` — legacy padding module, replaced by WTFPad
- `moor_transport_shade_register()` — unused wrapper, Shade registered directly
- `MOOR_PADDING_CONSTANT/ADAPTIVE/JITTER` defines — config parsed but never read
- `padding_mode` field from config.h, relay.h, circuit.h
