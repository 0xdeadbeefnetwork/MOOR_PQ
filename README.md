# MOOR

Post-quantum anonymous overlay network.

## What is this

MOOR is an onion router. Your traffic goes through three relays. Each relay peels one encryption layer, learns only the next hop, and forwards. No single relay knows both who you are and what you're accessing.

Every key exchange uses hybrid post-quantum cryptography: X25519 + Kyber768. Traffic recorded today cannot be decrypted by a quantum computer tomorrow.

~53,000 lines of C. Three dependencies (libsodium, zlib, pthreads). No OpenSSL.

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
# Install
sudo apt install build-essential libsodium-dev zlib1g-dev
git clone https://github.com/0xdeadbeefnetwork/MOOR_PQ
cd MOOR_PQ && make

# Run as client (SOCKS5 proxy on :9050)
./moor

# Browse
curl -x socks5h://127.0.0.1:9050 http://example.com
```

Or one-command relay setup:

```bash
curl -sL https://raw.githubusercontent.com/0xdeadbeefnetwork/MOOR_PQ/main/setup.sh | sudo bash
```

## Hidden services

Host any TCP service as a `.moor` hidden service. SSH, HTTP, IRC, databases — anything.

```bash
./moor --mode hs --hs-dir ./hs_keys --hs-port 8080 -v
```

Tor-style port mapping:

```
# /etc/moor/moorrc
HiddenServiceDir /var/lib/moor/hidden_service
HiddenServicePort 80 8080      # virtual 80 -> localhost:8080
HiddenServicePort 22           # virtual 22 -> localhost:22
```

- **PQ-committed .moor addresses** — Kyber768 public key hash baked into the address
- **6-hop tunnel** — 3 client + 3 service with vanguard protection
- **Any TCP service** — SSH, HTTP, IRC, SMTP, databases all work
- **DPF-PIR lookups** — storage relay cannot learn which descriptor you requested
- **Descriptor anti-replay** — signed monotonic revision counters
- **Vanguards** — L2 (24h) + L3 (1h) rotation prevents guard discovery
- **Argon2id PoW** — memory-hard proof-of-work prevents intro flooding
- **OnionBalance** — load balance across multiple backend instances
- **Client authorization** — restrict descriptor access per-client
- **Built-in DNS-over-TCP** — host an onion-wrapped recursive resolver (`--dns-server-port`)

## Cryptography

| Layer | Algorithm | What it protects |
|-------|-----------|-----------------|
| Link handshake | Noise_IK + Kyber768 | Connection to first relay |
| Circuit key exchange | X25519 + Kyber768 hybrid CKE | Each hop of the 3-hop path |
| HS end-to-end | X25519 + Kyber768 (post-handshake KEM) | Client to hidden service |
| Onion encryption | ChaCha20 (PQ hybrid derived keys) | Data through the circuit |
| Link AEAD | XChaCha20-Poly1305 | Wire frames (532 bytes) |
| Consensus signatures | Ed25519 + ML-DSA-65 (Dilithium3) | Relay directory integrity |
| Identity keys | Ed25519 | Relay and service identity |
| Exit DNS | DNSCrypt v2 (X25519 + XSalsa20-Poly1305) | Encrypted DNS at exit relay |

Every layer uses hybrid PQ crypto. An attacker must break both X25519 and Kyber768 to decrypt anything. PQ hybrid is mandatory — no downgrade possible.

## Pluggable transports

Six pluggable transports for censorship circumvention:

| Transport | Technique | Looks like |
|-----------|-----------|------------|
| **ShitStorm** | Chrome 146 JA4, Elligator2, ECH GREASE, HTTP/2 | Chrome browsing a CDN |
| **Nether** | Minecraft 1.21.4 protocol, real handshake + login | Minecraft gameplay |
| **Mirage** | TLS 1.3 framing, configurable SNI | HTTPS to any domain |
| **Shade** | Elligator2 obfuscation, IAT modes | Random bytes |
| **Scramble** | ASCII HTTP prefix + ChaCha20 stream | HTTP traffic |
| **Speakeasy** | SSH banner exchange + encrypted channel | SSH session |

```bash
# Connect through a ShitStorm bridge
./moor --UseBridges 1 --Bridge "shitstorm 1.2.3.4:9001 <fingerprint>" -v
```

## Traffic analysis resistance

- **Fixed 514-byte cells** — all cells identical size on the wire
- **WTF-PAD** — per-circuit randomized adaptive padding (web, stream, generic machines)
- **FRONT padding** — Rayleigh-sampled burst-cover over first 5 seconds
- **Constant-rate floor** — 50 cells/sec minimum cover traffic
- **EWMA scheduling** — exponentially weighted circuit multiplexing
- **Conflux** — multi-path circuit aggregation

## Network infrastructure

- **Vegas CC** — Prop 324/329 per-circuit congestion control with SENDME auth (Prop 289)
- **Multi-DA consensus** — directory authorities with Ed25519 + ML-DSA-65 dual signatures
- **Prop 271 guard selection** — sampled/primary/confirmed guard sets (kicks in at 20+ relays)
- **GeoIP path diversity** — country + AS exclusion, 370K+ IPv4 entries
- **Bandwidth-weighted selection** — Tor-aligned flag assignment (Guard, Fast, Stable, Exit)
- **Path bias detection** — statistical guard compromise detection
- **Argon2id PoW** — mandatory for relay admission, configurable difficulty
- **seccomp-bpf sandbox** — syscall filtering, no_new_privs, rlimits
- **TransPort + DNSPort** — transparent proxy and encrypted DNS resolution
- **Build-ID fleet gate** — DAs reject descriptors whose git hash differs from theirs; mixed-commit fleets cannot form (coordinated upgrades required)
- **Mandatory exit notice** — every exit relay serves an HTTP notice on :80 explaining it's a MOOR exit, not a website (safe-harbor / mere-conduit posture)

## Enclaves

Anyone can spin up a fully independent MOOR network. No recompile. Just a config file.

```bash
# Generate DA keys on each host
host1$ moor --keygen-enclave --advertise 1.2.3.4 --data-dir /var/lib/moor
host2$ moor --keygen-enclave --advertise 5.6.7.8 --data-dir /var/lib/moor

# Combine into an enclave file
cat > mynet.enclave <<EOF
1.2.3.4:9030 <hex_pk_from_host1>
5.6.7.8:9030 <hex_pk_from_host2>
EOF

# All nodes use the same file
moor --mode da --enclave mynet.enclave --advertise 1.2.3.4
moor --mode relay --enclave mynet.enclave
moor --enclave mynet.enclave  # client
```

## Current network

| Node | Role | Location |
|------|------|----------|
| DA1 | Directory Authority | US |
| DA2 | Directory Authority | US |
| TURBINE | Relay | US |
| DROPOUT | Guard relay | NL |
| VALIDATOR | Exit relay | NL |

## Documentation

- [Architecture](docs/architecture.md) — system design, source layout
- [Building](docs/building.md) — dependencies, build options, cross-compilation
- [Configuration](docs/configuration.md) — all config options, CLI flags, relay types
- [Protocol](docs/protocol.md) — wire formats, cell types, consensus format
- [Security](docs/security.md) — threat model, crypto analysis, limitations
- [OPSEC](docs/opsec.md) — how to use MOOR without defeating the point
- [Philosophy](docs/philosophy.md) — why MOOR exists

## Source

~53,000 lines of C across 48 source files and 48 headers. ~3,000 lines of vendored NIST PQ reference implementations (Kyber768, ML-DSA-65).

Website: [https://moor.afflicted.sh](https://moor.afflicted.sh)

## License

See LICENSE file.
