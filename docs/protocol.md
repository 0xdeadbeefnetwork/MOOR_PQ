# Protocol

## Cells

All data on the wire travels in fixed-size 514-byte cells:

```
circuit_id  (4 bytes, big-endian)
command     (1 byte)
payload     (509 bytes)
```

Encrypted on the link, each cell is transmitted as 532 bytes:
`2-byte length prefix + 514-byte cell plaintext + 16-byte AEAD tag`.

### Cell commands

| Command | Value | Direction | Description |
|---------|-------|-----------|-------------|
| PADDING | 0 | Both | Ignored, used for traffic shaping |
| CREATE | 1 | Client → Relay | Classical circuit handshake (first hop) |
| CREATED | 2 | Relay → Client | Classical handshake response |
| RELAY | 3 | Both | Encrypted relay payload |
| DESTROY | 4 | Both | Tear down circuit |
| NETINFO | 5 | Both | Link-level peer info exchange |
| CREATE_PQ | 6 | Client → Relay | PQ hybrid circuit handshake (X25519 + ML-KEM-768) |
| CREATED_PQ | 7 | Relay → Client | PQ hybrid handshake response |
| KEM_CT | 8 | Both | ML-KEM-768 ciphertext fragment (1088 B across ~3 cells) |
| RELAY_EARLY | 9 | Both | Like RELAY but allowed to carry EXTEND (max 8 / circuit) |

### Relay commands (inside RELAY cells)

```
relay_command  (1 byte)
recognized     (2 bytes, zero when decrypted at the correct hop)
stream_id      (2 bytes)
digest         (4 bytes, running BLAKE2b-truncated)
data_length    (2 bytes)
data           (up to 498 bytes)
```

| Relay command | Value | Description |
|---------------|-------|-------------|
| RELAY_BEGIN | 1 | Open stream to target host:port |
| RELAY_DATA | 2 | Stream data |
| RELAY_END | 3 | Close stream |
| RELAY_CONNECTED | 4 | Stream opened successfully |
| RELAY_SENDME | 5 | Authenticated flow-control ack (Prop 289 — 20-byte digest FIFO) |
| RELAY_EXTEND | 6 | Extend circuit to next hop (classical) |
| RELAY_EXTENDED | 7 | Extension successful |
| RELAY_EXTEND2 | 8 | Extend via typed link specifiers (Tor-aligned) |
| RELAY_EXTENDED2 | 9 | EXTEND2 response |
| RELAY_DROP | 10 | Drop (padding / cover) |
| RELAY_RESOLVE | 11 | Remote DNS resolve request |
| RELAY_RESOLVED | 12 | DNS resolve response |
| RELAY_BEGIN_UDP | 28 | UDP stream begin |
| RELAY_ESTABLISH_INTRO | 32 | HS: establish introduction point |
| RELAY_INTRO_ESTABLISHED | 33 | HS: intro-point ack |
| RELAY_INTRODUCE1 | 34 | HS: client → intro point (ML-KEM-768 sealed payload) |
| RELAY_INTRODUCE2 | 35 | HS: intro point → service |
| RELAY_RENDEZVOUS1 | 36 | HS: service → rendezvous point |
| RELAY_RENDEZVOUS2 | 37 | HS: rendezvous point → client |
| RELAY_ESTABLISH_RENDEZVOUS | 38 | HS: client establishes RP |
| RELAY_RENDEZVOUS_ESTABLISHED | 39 | HS: RP ack |
| RELAY_FRAGMENT | 40 | Multi-cell payload: more follows |
| RELAY_FRAGMENT_END | 41 | Multi-cell payload: last fragment |
| RELAY_EXTEND_PQ | 42 | PQ hybrid extend |
| RELAY_EXTENDED_PQ | 43 | PQ hybrid extend response |
| RELAY_KEM_OFFER | 44 | ML-KEM-768 public key (chunked) |
| RELAY_KEM_ACCEPT | 45 | ML-KEM-768 ciphertext (chunked) |
| RELAY_E2E_KEM_CT | 46 | PQ end-to-end: client → HS KEM ciphertext |
| RELAY_E2E_KEM_ACK | 47 | PQ end-to-end: HS rekey complete |
| RELAY_CONFLUX_LINK | 50 | Link circuit to conflux set |
| RELAY_CONFLUX_LINKED | 51 | Conflux link ack |
| RELAY_CONFLUX_SWITCH | 52 | Switch active conflux leg |
| RELAY_XON | 53 | Stream flow: resume sending (Prop 344) |
| RELAY_XOFF | 54 | Stream flow: pause sending (Prop 344) |
| RELAY_DHT_STORE | 60 | Store HS descriptor in DHT |
| RELAY_DHT_STORED | 61 | DHT store ack |
| RELAY_DHT_FETCH | 62 | Fetch HS descriptor from DHT |
| RELAY_DHT_FOUND | 63 | DHT fetch: descriptor found |
| RELAY_DHT_NOT_FOUND | 64 | DHT fetch: descriptor not found |
| RELAY_DHT_PIR_QUERY | 66 | 2-server XOR-PIR: 256-bit bitmask query |
| RELAY_DHT_PIR_RESPONSE | 67 | 2-server XOR-PIR: XOR-aggregated response |
| RELAY_DHT_DPF_QUERY | 68 | DPF-PIR: distributed-point-function query |
| RELAY_DHT_DPF_RESPONSE | 69 | DPF-PIR: DPF-evaluated response |

## Link handshake

Noise_IK pattern over TCP, followed by ML-KEM-768 post-handshake
encapsulation:

```
Client -> Server:
  e_pk (32)                         Ephemeral X25519 public key
  AEAD(s_pk, 32)                    Static identity encrypted + MAC (48)
  Total: 80 bytes

Server -> Client:
  e_pk (32)                         Server ephemeral
  AEAD(empty, 0)                    Empty payload + MAC (16)
  Total: 48 bytes

--- Noise_IK complete, link encrypted ---

Client -> Server:
  ml_kem_pk (1184)                  Ephemeral ML-KEM-768 public key

Server -> Client:
  ml_kem_ct (1088)                  KEM ciphertext

Both: mix KEM shared secret into link keys via HKDF-BLAKE2b.
```

Link rekey is implicit (counter-triggered), not negotiated. There is no
downgrade to classical-only.

## Circuit handshake (PQ hybrid)

### First hop (CREATE_PQ)

```
Client -> Guard (CREATE_PQ cell):
  relay_identity_pk (32)
  client_eph_pk     (32)

Guard -> Client (CREATED_PQ cell):
  guard_eph_pk (32)
  auth_tag     (32)

Client -> Guard (KEM_CT cells, fragmented):
  kem_ct (1088)                     ML-KEM-768 ciphertext (client encapsulated
                                    to guard's consensus ml_kem_pk)

Both sides:
  dh1      = X25519(client_eph, guard_eph)            Forward secrecy
  dh2      = X25519(client_eph, guard_onion_pk)       Onion key binding (28d rotation)
  key_seed = CKE_HKDF(dh1, dh2, identity_pk)         Identity in HKDF salt
  kem_ss   = ML_KEM_Decap(kem_ct, guard_kem_sk)      PQ shared secret

  hybrid   = BLAKE2b(key_seed || kem_ss)
  fwd_key  = KDF(hybrid, 1, "moorFWD!")
  bwd_key  = KDF(hybrid, 2, "moorBWD!")
```

If either the classical chain **or** the KEM secret is unknown to the
attacker, the hybrid output stays secret.

### Subsequent hops (EXTEND_PQ)

```
Client -> Guard (RELAY_EXTEND_PQ, encrypted through circuit):
  next_addr (64) + port (2) + identity_pk (32) + eph_pk (32) = 130 bytes

Client -> Guard (RELAY_KEM_OFFER, chunked):
  kem_ct (1088 bytes, split across 3 relay cells)

Guard connects to middle, runs Noise_IK + ML-KEM-768 link handshake,
then sends CREATE_PQ + CELL_KEM_CT cells, receives CREATED_PQ.

Guard -> Client (RELAY_EXTENDED_PQ):
  middle_eph_pk (32) + auth_tag (32) = 64 bytes

Client derives hybrid keys for this hop (same formula as first hop).
```

## Consensus document

Text format, one line per field:

```
moor-consensus 1
valid-after YYYY-MM-DD HH:MM:SS
fresh-until YYYY-MM-DD HH:MM:SS
valid-until YYYY-MM-DD HH:MM:SS
known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly Running Stable Valid
shared-rand-current-value <base64(32)>
shared-rand-previous-value <base64(32)>
```

Per relay:

```
n <nickname> <b64(identity_pk)> <published> <IP> <ORport> <DirPort>
o <b64(onion_pk)>
a <IPv6 address>                     (optional)
k <b64(ml_kem_pk)>                   (if PQ-capable; always set on modern relays)
s Flag1 Flag2 ...                    (alphabetical)
w Bandwidth=N [Measured=M]
g CC ASN                             (if GeoIP available)
f <b64(family_id)>                   (if in a family)
p <b64(relay_signature)>
```

Footer:

```
directory-footer
directory-signature <b64(da_identity_pk)> <b64(ed25519_sig)>
pq-directory-signature <b64(da_identity_pk)>
<b64(mldsa_pk)>
<b64(mldsa_sig)>
```

Clients verify **both** signatures (Ed25519 and ML-DSA-65) —
sequential-AND. There is no downgrade path.

## DA vote exchange

DAs exchange Ed25519 + ML-DSA-65 signatures over the consensus body hash
over an encrypted channel (ephemeral X25519 DH + AEAD framing):

```
Sender -> Peer DA:
  "VOTE_PQ\n" (8 bytes)
  identity_pk (32)
  ed25519_signature (64)
  mldsa_pk (1952)
  mldsa_signature (3309)
```

Peer DAs must be configured with each other's identity fingerprints for
trust verification.

## Hidden service protocol

```
1. HS generates Ed25519 + Curve25519 + ML-KEM-768 + Falcon-512 keypairs.
2. HS publishes a descriptor, encrypted under a key derived from
   identity_pk + time_period, signed by both Ed25519 and Falcon-512
   (sequential-AND verify).
3. Descriptor is stored in the DHT at 3 responsible relays per time period.
4. Client fetches the descriptor via 2-server XOR-PIR or DPF-PIR so the
   storing relay cannot learn which onion was requested.
5. Client verifies both signatures and confirms that
   BLAKE2b_16(ml_kem_pk || falcon_pk) equals the 16-byte PQ commit baked
   into the onion address.
6. Client builds a rendezvous circuit (3 hops) and an intro circuit (3 hops).
7. Client sends RELAY_INTRODUCE1 to the intro point. INTRODUCE1 is
   ML-KEM-768 sealed to the service's KEM pk:
     kem_ct (1088) || aead_ct || aead_tag (16)
8. Intro point forwards RELAY_INTRODUCE2 to the HS.
9. HS decapsulates with its ML-KEM sk, builds a circuit to the rendezvous
   point, and sends RELAY_RENDEZVOUS1 with the cookie.
10. Client receives RELAY_RENDEZVOUS2, derives end-to-end keys.
11. Bidirectional data flows through 6 total hops.
```

### .moor address format

```
base32( Ed25519_pk(32) || BLAKE2b_16( ML-KEM_pk(1184) || Falcon_pk(897) ) ) + ".moor"
```

The 16-byte BLAKE2b commit binds **both** post-quantum public keys into
the address. Clients reject any descriptor whose advertised ML-KEM pk or
Falcon pk does not match the commit. Even if Ed25519 falls to a future
quantum adversary, a forged descriptor still cannot match the address
because it would require BLAKE2b preimage resistance against both PQ keys.

### Descriptor signing

Each descriptor carries two signatures and is only accepted when both verify:

```
descriptor_body:
  revision   (u64, monotonic + wall-clock floored)
  intro_point_list
  ml_kem_pk (1184)
  falcon_pk (897)
  authorized_clients (optional, up to 16 curve25519 pks)

signature block:
  ed25519_sig  (64)
  falcon_sig   (~666, variable)
```

Verification is sequential-AND: Ed25519 first, then Falcon-512. A descriptor
carrying only an Ed25519 signature is rejected once Falcon is bound into
the address.

### PIR descriptor fetch

MOOR supports two private-information-retrieval modes for DHT descriptor
fetches. In both, the storing relay cannot learn which onion hash was
requested.

- **2-server XOR-PIR** (`RELAY_DHT_PIR_QUERY` / `RELAY_DHT_PIR_RESPONSE`):
  the client sends a 256-bit bitmask selecting a subset of the local
  descriptor set; the relay returns the XOR of all selected entries.
  The client XORs two paired responses (from two replicas) against queries
  whose XOR equals the indicator vector for the target.
- **DPF-PIR** (`RELAY_DHT_DPF_QUERY` / `RELAY_DHT_DPF_RESPONSE`): Boyle-
  Gilboa-Ishai distributed-point-function pair queries. Each replica
  evaluates its DPF share over the local table; XORing the two responses
  yields the target entry. Bandwidth cost scales better on larger tables.
