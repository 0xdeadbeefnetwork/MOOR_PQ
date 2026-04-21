# MOOR

Post-quantum anonymous overlay network.

## What is this

MOOR is an onion router. Your traffic takes a three-hop encrypted path through the network. Each relay peels one layer, learns only the next hop, and forwards. No single relay knows both who you are and what you're accessing.

Every cryptographic step is **hybrid post-quantum**: a classical primitive (X25519, Ed25519) combined with a NIST-standardized post-quantum primitive (ML-KEM-768, ML-DSA-65, Falcon-512). An adversary must break **both** to recover anything. Traffic captured today cannot be decrypted by a quantum computer tomorrow.

~55,000 lines of C across the core, plus ~16,000 lines of vendored NIST PQ reference implementations (PQClean). Dependencies: libsodium, zlib, libevent, pthreads. No OpenSSL.

```
You  --->  Guard  --->  Middle  --->  Exit  --->  Destination
           sees:        sees:         sees:
           your IP      nothing       destination
           NOT where    useful.       NOT your IP.
           you're       just passes   makes the
           going.       encrypted     connection
                        data along.   on your behalf.
```

## Quick start

```bash
# Install build deps
sudo apt install build-essential libsodium-dev zlib1g-dev libevent-dev

# Build
git clone https://github.com/0xdeadbeefnetwork/MOOR_PQ
cd MOOR_PQ && make

# Run as client (SOCKS5 proxy on :9050)
./moor

# Browse
curl -x socks5h://127.0.0.1:9050 http://example.com
```

One-command relay setup:

```bash
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
```

## Hidden services

Host any TCP service behind a `.moor` address. SSH, HTTP, IRC, databases — anything.

```bash
./moor --mode hs --hs-dir ./hs_keys --hs-port 8080 -v
```

torrc-style port mapping:

```
# /etc/moor/moorrc
HiddenServiceDir   /var/lib/moor/hidden_service
HiddenServicePort  80 8080      # virtual 80 -> localhost:8080
HiddenServicePort  22            # virtual 22 -> localhost:22
```

- **PQ-committed `.moor` addresses** — both the ML-KEM and Falcon public keys are hashed into the address itself, so the onion address cannot be forged even if Ed25519 falls
- **Dual-signed descriptors** — Ed25519 + Falcon-512 signatures on every descriptor
- **PQ-sealed INTRODUCE1** — rendezvous setup encapsulated under ML-KEM-768
- **DHT descriptor storage with PIR** — clients fetch via 2-server XOR-PIR or DPF-PIR; the storing relay cannot learn which onion was requested
- **Client authorization** — up to 16 authorized ML-KEM client keys per service
- **Argon2id PoW** — memory-hard proof-of-work to blunt intro flooding
- **Vanguards** — L2/L3 guard rotation prevents service deanonymization via guard discovery
- **OnionBalance** — load balance one onion across multiple backends

## Cryptography

Every layer is hybrid classical + post-quantum. Both must break.

| Layer | Classical | Post-Quantum | What it protects |
|-------|-----------|--------------|-----------------|
| Link handshake | Noise_IK (X25519 + XChaCha20-Poly1305 + BLAKE2b) | ML-KEM-768 post-handshake encapsulation | Wire traffic between relays |
| Circuit key exchange | X25519 ECDH (CREATE_PQ / CREATED_PQ) | ML-KEM-768 (CELL_KEM_CT) | Per-hop session keys |
| HS end-to-end | X25519 + ChaCha20-Poly1305 | ML-KEM-768 sealing on INTRODUCE1 | Client ↔ hidden service |
| Hidden service identity | Ed25519 | Falcon-512 (descriptor dual-sig, INTRODUCE1 co-sig) | Cannot impersonate onion |
| `.moor` address commitment | — | BLAKE2b-16(ML-KEM_pk ‖ Falcon_pk) baked into address | PQ keys cannot be swapped |
| Consensus signatures | Ed25519 | ML-DSA-65 | Relay directory integrity |
| Onion cell encryption | ChaCha20 | keys derived from hybrid KDF | Cell confidentiality |
| Hashing / KDF | BLAKE2b-256, HKDF-BLAKE2b | — | — |

PQ hybrid is **mandatory**. There is no downgrade path. Verification is sequential-AND: both signatures must verify, both KEM secrets must be mixed in.

Classical primitives come from libsodium. Post-quantum primitives are vendored from [PQClean](https://github.com/PQClean/PQClean) — no liboqs, no moving targets.

## Pluggable transports

Six cover-traffic transports for censored networks. Pick one when running a bridge.

| Transport | Cover | What it looks like on the wire |
|-----------|-------|--------------------------------|
| **ShitStorm** | Chrome 146 JA4 fingerprint, Elligator2, ECH GREASE, HTTP/2 | Chrome browsing a CDN |
| **Nether** | Minecraft 1.21.4 real handshake + login | Minecraft game traffic |
| **Mirage** | TLS 1.3 ClientHello with real X25519 DH, configurable SNI | HTTPS to any domain |
| **Shade** | Elligator2 obfuscation + inter-arrival-time modes | Random bytes |
| **Scramble** | ASCII HTTP/1.1 GET prefix + ChaCha20 stream | HTTP traffic |
| **Speakeasy** | SSH-2.0 banner exchange + encrypted channel framing | SSH session |

```bash
# Connect through a ShitStorm bridge
./moor --UseBridges 1 --Bridge "shitstorm 1.2.3.4:9001 <fingerprint>" -v
```

Non-bridge relays run a **scanner honeypot** on their ORPort that intercepts probes matching "GET ", "SSH-2.0", etc. and returns fake industrial-control banners (SCADA / turbine controller / satellite modem). Bridges skip the honeypot so legitimate cover-traffic prefixes pass through.

## Traffic analysis resistance

- **Fixed 514-byte cells** — every cell is identical size on the wire
- **WTF-PAD** — per-circuit randomized adaptive padding (web, stream, generic machines)
- **FRONT padding** — Rayleigh-sampled burst cover over the first 5 seconds
- **Volume padding** — cells-per-circuit padded to the next power of two
- **Constant-rate floor** — configurable minimum cover-traffic rate
- **EWMA scheduling** — exponentially-weighted per-circuit multiplexing prevents starvation
- **Conflux** — 4-leg multi-path aggregation with sequence-based reordering (Feistel PRP per set)
- **SKIPS** — RTT-adaptive scheduling interval with persistent timer

## Network infrastructure

- **Vegas congestion control** — Prop 324 per-circuit CC + Prop 289 authenticated SENDME (20-byte digest FIFO)
- **Multi-DA consensus** — directory authorities sign every consensus with Ed25519 **and** ML-DSA-65; sequential-AND verification on the client
- **Prop 271 guard selection** — sampled / primary / confirmed guard sets (activates at ≥20 relays)
- **GeoIP path diversity** — country + AS exclusion, ~370K IPv4 entries vendored
- **Bandwidth-weighted selection** — Tor-aligned flag assignment (Guard, Fast, Stable, Exit)
- **Path-bias detection** — per-guard circuit-success statistics with WARN/EXTREME thresholds
- **Argon2id relay PoW** — mandatory for relay admission, configurable difficulty
- **seccomp-bpf sandbox** — syscall allow-list, no_new_privs, rlimits
- **TransPort + DNSPort** — transparent proxy and encrypted DNS resolution over exit relays
- **Build-ID fleet gate** — DAs reject descriptors whose git hash differs from theirs; mixed-commit fleets cannot form, forcing coordinated upgrades
- **mlockall(MCL_CURRENT)** — sensitive pages pinned in memory
- **Self-loop filter** — a relay's own circuit-builder cannot route through itself even on shared NAT / dev setups
- **Mandatory exit notice** — every exit relay serves an HTTP notice on :80 explaining it's a MOOR exit, not a website (safe-harbor / mere-conduit posture)

## Enclaves

Anyone can spin up a fully independent MOOR network. No recompile. Just a config file.

```bash
# Generate DA keys on each host
host1$ moor --keygen-enclave --advertise 1.2.3.4 --data-dir /var/lib/moor
host2$ moor --keygen-enclave --advertise 5.6.7.8 --data-dir /var/lib/moor

# Combine the hex pks into an enclave file
cat > mynet.enclave <<EOF
1.2.3.4:9030  <hex_pk_from_host1>
5.6.7.8:9030  <hex_pk_from_host2>
EOF

# All nodes use the same file
moor --mode da    --enclave mynet.enclave --advertise 1.2.3.4
moor --mode relay --enclave mynet.enclave
moor             --enclave mynet.enclave  # client
```

## Default network

| Node | Role | Location |
|------|------|----------|
| DA1 | Directory Authority | US |
| DA2 | Directory Authority | US |
| TURBINE | Relay | US |
| DROPOUT | Guard relay | NL |
| VALIDATOR | Exit relay | NL |

## Documentation

- [Architecture](docs/architecture.md) — system design, source layout, cell format
- [Protocol](docs/protocol.md) — wire formats, cell commands, handshake + consensus format
- [Security](docs/security.md) — threat model, cryptographic analysis, limitations
- [Configuration](docs/configuration.md) — all config options, CLI flags, torrc compatibility
- [Building](docs/building.md) — dependencies, build options, cross-compilation, sanitizers
- [OPSEC](docs/opsec.md) — using MOOR without defeating the point
- [Philosophy](docs/philosophy.md) — why MOOR exists
- [PQ crypto flow diagram](docs/pq-crypto-flow.svg) — one-page overview of the hybrid PQ data paths

## Source

~55,000 lines of C (core) across `src/` and `include/moor/`, plus ~16,000 lines of vendored NIST PQ reference code in `src/pqclean/` (ML-KEM-768, ML-DSA-65, Falcon-512, FIPS 202 / SHA-2 / AES primitives).

Website: <https://moor.afflicted.sh>

## License

See `LICENSE`.
