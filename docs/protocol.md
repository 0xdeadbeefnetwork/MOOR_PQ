# Protocol

## Cells

All data on the wire travels in fixed-size 514-byte cells:

```
circuit_id  (4 bytes, big-endian)
command     (1 byte)
payload     (509 bytes)
```

### Cell commands

| Command | Value | Direction | Description |
|---------|-------|-----------|-------------|
| PADDING | 0 | Both | Ignored, used for traffic shaping |
| CREATE | 1 | Client->Relay | Classical circuit handshake (first hop) |
| CREATED | 2 | Relay->Client | Classical handshake response |
| RELAY | 3 | Both | Encrypted relay payload |
| DESTROY | 4 | Both | Tear down circuit |
| NETINFO | 5 | Both | Link-level peer info exchange |
| CREATE_PQ | 6 | Client->Relay | PQ hybrid circuit handshake |
| CREATED_PQ | 7 | Relay->Client | PQ hybrid handshake response |
| KEM_CT | 8 | Both | KEM ciphertext fragment (PQ hybrid handshake) |
| RELAY_EARLY | 9 | Both | Like RELAY but allowed to carry EXTEND (max 8/circuit) |

### Relay commands (inside RELAY cells)

```
relay_command  (1 byte)
recognized     (2 bytes, zero when decrypted at correct hop)
stream_id      (2 bytes)
digest         (4 bytes, running BLAKE2b)
data_length    (2 bytes)
data           (up to 498 bytes)
```

| Relay command | Value | Description |
|---------------|-------|-------------|
| RELAY_BEGIN | 1 | Open stream to target host:port |
| RELAY_DATA | 2 | Stream data |
| RELAY_END | 3 | Close stream |
| RELAY_CONNECTED | 4 | Stream opened successfully |
| RELAY_SENDME | 5 | Flow control acknowledgment |
| RELAY_EXTEND | 6 | Extend circuit to next hop (classical) |
| RELAY_EXTENDED | 7 | Extension successful |
| RELAY_EXTEND2 | 8 | Extend via typed link specifiers (Tor-aligned) |
| RELAY_EXTENDED2 | 9 | EXTEND2 response |
| RELAY_DROP | 10 | Drop (padding/cover) |
| RELAY_RESOLVE | 11 | Remote DNS resolve request |
| RELAY_RESOLVED | 12 | DNS resolve response |
| RELAY_BEGIN_UDP | 28 | UDP stream begin |
| RELAY_ESTABLISH_INTRO | 32 | HS: establish introduction point |
| RELAY_INTRO_ESTABLISHED | 33 | HS: intro point ack |
| RELAY_INTRODUCE1 | 34 | HS: client -> intro point |
| RELAY_INTRODUCE2 | 35 | HS: intro point -> service |
| RELAY_RENDEZVOUS1 | 36 | HS: service -> rendezvous point |
| RELAY_RENDEZVOUS2 | 37 | HS: rendezvous point -> client |
| RELAY_ESTABLISH_RENDEZVOUS | 38 | HS: client establishes RP |
| RELAY_RENDEZVOUS_ESTABLISHED | 39 | HS: RP ack |
| RELAY_FRAGMENT | 40 | Multi-cell payload: more follows |
| RELAY_FRAGMENT_END | 41 | Multi-cell payload: last fragment |
| RELAY_EXTEND_PQ | 42 | PQ hybrid extend |
| RELAY_EXTENDED_PQ | 43 | PQ hybrid extend response |
| RELAY_KEM_OFFER | 44 | Kyber768 ciphertext (chunked) |
| RELAY_KEM_ACCEPT | 45 | Kyber768 KEM accept |
| RELAY_E2E_KEM_CT | 46 | PQ e2e: client sends KEM CT to HS |
| RELAY_E2E_KEM_ACK | 47 | PQ e2e: HS acks rekey complete |
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
| RELAY_DHT_PIR_QUERY | 66 | PIR: 256-bit bitmask query (legacy) |
| RELAY_DHT_PIR_RESPONSE | 67 | PIR: XOR-aggregated response |
| RELAY_DHT_DPF_QUERY | 68 | DPF-PIR: DPF key query |
| RELAY_DHT_DPF_RESPONSE | 69 | DPF-PIR: DPF-evaluated response |

## Link handshake

Noise_IK pattern over TCP, followed by Kyber768 KEM extension:

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
  kyber_pk (1184)                   Ephemeral Kyber768 public key

Server -> Client:
  kyber_ct (1088)                   KEM ciphertext

Both: mix KEM shared secret into link keys via HKDF
```

## Circuit handshake (PQ hybrid)

### First hop (CREATE_PQ)

```
Client -> Guard (CREATE_PQ cell):
  relay_identity_pk (32)
  client_eph_pk (32)

Guard -> Client (CREATED_PQ cell):
  guard_eph_pk (32)
  auth_tag (32)

Client -> Guard (raw bytes over link):
  kem_ct (1088)                     Kyber768 ciphertext (client encapsulated to guard's consensus kem_pk)

Both sides:
  dh1 = X25519(client_eph, guard_eph)           Forward secrecy
  dh2 = X25519(client_eph, guard_onion_pk)      Onion key binding (rotates every 28 days)
  key_seed = CKE_HKDF(dh1, dh2, identity_pk)   Identity in HKDF salt (authentication)
  kem_ss = KEM_Decap(kem_ct, guard_kem_sk)      PQ shared secret

  hybrid = BLAKE2b(key_seed || kem_ss)
  fwd_key = KDF(hybrid, 1, "moorFWD!")
  bwd_key = KDF(hybrid, 2, "moorBWD!")
```

### Subsequent hops (EXTEND_PQ)

```
Client -> Guard (RELAY_EXTEND_PQ, encrypted through circuit):
  next_addr (64) + port (2) + identity_pk (32) + eph_pk (32) = 130 bytes

Client -> Guard (RELAY_KEM_OFFER cells, chunked):
  kem_ct (1088 bytes, split across 3 relay cells)

Guard connects to middle, sends CREATE_PQ + CELL_KEM_CT cells
Middle responds CREATED_PQ

Guard -> Client (RELAY_EXTENDED_PQ):
  middle_eph_pk (32) + auth_tag (32) = 64 bytes

Client derives hybrid keys for this hop (same as first hop)
```

## Consensus document

Text format, one line per field:

```
moor-consensus 1
valid-after YYYY-MM-DD HH:MM:SS
fresh-until YYYY-MM-DD HH:MM:SS
valid-until YYYY-MM-DD HH:MM:SS
known-flags Authority BadExit Exit Fast Guard MiddleOnly Running Stable Valid
shared-rand-current-value <base64(32)>
shared-rand-previous-value <base64(32)>
```

Per relay:
```
n <nickname> <b64(identity_pk)> <published> <IP> <ORport> <DirPort>
o <b64(onion_pk)>
a <IPv6 address>                    (optional)
k <b64(kem_pk)>                     (if PQ-capable)
s Flag1 Flag2 ...                   (alphabetical)
w Bandwidth=N [Measured=M]
g CC ASN                            (if GeoIP available)
f <b64(family_id)>                  (if in a family)
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

## DA vote exchange

DAs exchange Ed25519 + ML-DSA-65 signatures over the consensus body hash:

```
Sender -> Peer DA:
  "VOTE_PQ\n" (8 bytes)
  identity_pk (32)
  ed25519_signature (64)
  mldsa_pk (1952)
  mldsa_signature (3309)
```

DA peers must be configured with each other's identity fingerprints for trust verification.

## Hidden service protocol

1. HS publishes descriptor to DAs and DHT (3 responsible relays per time period)
2. Client fetches descriptor via PIR (Private Information Retrieval)
3. Client builds rendezvous circuit (3 hops) and intro circuit (3 hops)
4. Client sends INTRODUCE1 to intro point, which forwards INTRODUCE2 to HS
5. HS builds circuit to rendezvous point, sends RENDEZVOUS1
6. Client receives RENDEZVOUS2, derives e2e keys
7. Bidirectional data flows through 6 total hops

HS addresses: base32(Ed25519_pk(32) + BLAKE2b_16(Kyber768_pk)(16)).moor

The 16-byte truncated hash of the Kyber768 public key is baked into the address. Clients verify the KEM pk from the descriptor matches the commitment in the address. Prevents service impersonation even if Ed25519 is broken.
