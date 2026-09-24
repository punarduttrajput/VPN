# SEC-004 — Permissive TLS verifier on QUIC/MASQUE

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M2 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR4 |
| **Area** | `ferrum-transport` (`quic.rs`, `masque.rs`, `quic_mesh.rs`) |

## Problem

`SkipServerVerification` accepts any server certificate
(`crates/transport/src/quic.rs` ~L135/185, `masque.rs` ~L71,
`quic_mesh.rs` ~L212). The design rationale — peer identity is the inner
WireGuard handshake — holds for *confidentiality*, but the outer transport
offers **zero server authentication**. An on-path adversary can MITM the
camouflage layer for metadata, active probing, and downgrade, undercutting the
Phase 2 anti-censorship value proposition.

## Acceptance criteria

- [x] Replace `SkipServerVerification` with a pinning verifier that checks the
      server cert against a coordinator-advertised fingerprint. *(Verifier +
      config pins: part 1. Coordinator-advertised per-peer pins: part 2.)*
- [x] The fingerprint is advertised in the network map alongside
      `relay`/`dns_servers`. *(Part 2 — as a per-peer `PeerInfo` field, since
      each mesh node is a QUIC server; see Resolution.)*
- [x] With no pinning material available, the client connects but emits a
      documented, visible "outer transport unauthenticated" warning — never a
      silent accept.
- [x] Residual on-path threat model documented in user-facing terms
      (README "Certificate pinning").
- [x] Test: a client rejects a server whose cert doesn't match the advertised
      fingerprint; the no-pin warning path is covered.

## Implementation notes

- The verifier still doesn't need a CA — pin to the advertised leaf
  fingerprint (SHA-256 of the DER).
- Coordinates with SEC-007 (rotation): advertise current + next fingerprint so
  a cert roll doesn't break pinning.
- Keep the self-signed cert generation; only the *verification* changes.

## Resolution

Split into two PRs, because the code has three separate QUIC trust
relationships and only one of them fits a single "network map" fingerprint:

| Path | Who is the TLS server | Pin source |
|---|---|---|
| Point-to-point `ferrum up`, `mode = "quic"` | the peer with `role = "server"` | `[transport] cert_pins` (part 1) |
| MASQUE (`up` and `up-mesh`) | the MASQUE proxy (third-party; no in-tree binary) | `[transport] cert_pins` / desktop `ConnectConfig.cert_pins` (part 1) |
| QUIC mesh (`up-mesh`, desktop) | **every** peer | published by each device at register, advertised **per peer** in the network map (part 2) |

**Part 1** (`crates/transport/src/tls.rs`):
- `PinnedVerifier` replaces `SkipServerVerification`. It accepts a server cert
  only if the SHA-256 of its **public key** (SubjectPublicKeyInfo, HPKP-style)
  is one of the pins. The ticket suggested hashing the whole cert DER; the key
  is used instead because it stays stable when the cert is re-issued or a
  dependency changes how certs are encoded. Several pins are allowed, so a
  current and a next key can overlap during a rotation (SEC-007).
- With no pins, it connects and logs the warning (once per destination).
- Pinning needs a **stable key**, but every start used to generate a throwaway
  one. `TlsIdentity::from_wireguard_key` fixes that: it derives an Ed25519 key
  from the WireGuard private key (HKDF-SHA256, one-way). The derived key
  material is zeroized.
- A dial that fails its pin (or can't connect) is a dropped datagram with a
  backed-off retry, never a mesh-fatal error, so one bad peer can't take the
  others down.
- `ferrum tls-fingerprint --config` prints a node's pin.
- `QuicMeshTransport::set_peer_pins` pins each mesh dial per destination; part 2
  feeds it.
- Follow-up (not in scope): every endpoint uses the fixed SNI `ferrum`, which a
  censor could match on.

**Part 2** (distributing the pins):
- **Proto.** `RegisterDeviceRequest.tls_cert_sha256` (the device's own pin),
  `PeerInfo.tls_cert_sha256` (handed to permitted peers) and
  `RotateKeyRequest.new_tls_cert_sha256` (the cert is derived from the
  WireGuard key, so a rotation carries the new pin or clears it, never the
  stale one).
- **Coordinator.** Validates the pin (64 hex digits, `:`-separated or not, any
  case), normalizes it and stores it on the device, persisted under `sqlite`
  with a column migration. The pin rides the same authenticated registration
  as the key (SEC-002), so nobody can publish a pin for a key they don't own.
- **Client.**
  - `FerrumClient::set_tls_fingerprint`, mirroring `set_token`, attaches the pin
    to every registration, and `PeerSpec` carries the peer's pin.
  - `build_mesh_peers` turns it into `MeshPeer::with_tls_pins`. A malformed pin
    is dropped, so that peer is dialed unpinned with the warning.
  - `run_mesh` pushes every peer's pins to the transport, keyed by its
    endpoint and every ICE candidate, through a new
    `MeshTransport::set_peer_pins` hook (default no-op; QUIC mesh acts on it).
- **Who publishes.** The CLI (`up-mesh`) and the desktop publish their derived
  pin only in QUIC mesh mode. UDP has no TLS, and a MASQUE node dials a proxy
  rather than being dialed.
