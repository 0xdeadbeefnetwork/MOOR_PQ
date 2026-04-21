# WebWTF Transport — Design Document (NOT IMPLEMENTED)

> **Status: design proposal only.** WebWTF is sketched here for reference.
> It is not compiled into the binary and not selectable via
> `--bridge-transport`. The six shipped transports are ShitStorm, Nether,
> Mirage, Shade, Scramble, and Speakeasy.

## MOOR Pluggable Transport: WebRTC Video Call Camouflage over UDP

### Summary

WebWTF makes MOOR traffic indistinguishable from a Chrome-to-Chrome WebRTC video call. Unlike ShitStorm (TCP/TLS), WebWTF operates over UDP and mimics STUN + DTLS + SRTP. A censor cannot block it without blocking Zoom, Google Meet, Discord, and Teams.

### Wire Phases

```
Phase 1: STUN Binding Request/Response (ICE connectivity check)
Phase 2: DTLS 1.2 handshake (Chrome WebRTC cipher fingerprint)
Phase 3: SRTP media — Opus audio (PT=111) + VP8 video (PT=96)
Phase 4: RTCP — Sender/Receiver Reports, REMB, SDES
```

### MOOR Data Inside SRTP

MOOR cells (514 bytes) are packed inside SRTP payloads with double encryption:
- Outer: SRTP AES-128-GCM (standard DTLS-SRTP key export)
- Inner: ChaCha20-Poly1305 (MOOR keys from DTLS + static-DH)

Audio stream: 50 pps, 80-120 byte payloads (~4 KB/s MOOR throughput)
Video stream: 30 fps, 200-1200 byte payloads (~60 KB/s MOOR throughput)
Combined: ~512 kbps effective MOOR bandwidth

### Traffic Shaping

- Audio: 20ms Opus cadence with DTX silence suppression
- Video: 30fps VP8 with keyframe bursts every 2-3 seconds
- RTCP: SR/RR every 5s, REMB every 1s
- Session rotation: hang up + redial every 10-30 minutes

### Probe Resistance

- STUN: MESSAGE-INTEGRITY (HMAC-SHA1) rejects unknown peers
- DTLS: Certificate fingerprint pre-shared, mismatch = alert + drop
- Elligator2: x25519 keys in DTLS are indistinguishable from random

### Bridge Line

```
Bridge webwtf 198.51.100.1:19302 <fingerprint> dtls_fp=sha-256:AB:CD:EF:...
```

ICE credentials derived deterministically from identity key.

### Dependencies

- libsodium (existing)
- elligator2.c (existing)
- Vendored: AES-128-GCM (~150 lines), HMAC-SHA1 (~100 lines), CRC-32 (~30 lines)

### Estimated Size

~3500 lines of C in transport_webwtf.c + ~80 lines header + ~200 lines vendored crypto.
