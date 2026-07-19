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

- [ ] Replace `SkipServerVerification` with a pinning verifier that checks the
      server cert against a coordinator-advertised fingerprint.
- [ ] The fingerprint is advertised in the network map alongside
      `relay`/`dns_servers`.
- [ ] With no pinning material available, the client connects but emits a
      documented, visible "outer transport unauthenticated" warning — never a
      silent accept.
- [ ] Residual on-path threat model documented in user-facing terms.
- [ ] Test: a client rejects a server whose cert doesn't match the advertised
      fingerprint; the no-pin warning path is covered.

## Implementation notes

- The verifier still doesn't need a CA — pin to the advertised leaf
  fingerprint (SHA-256 of the DER).
- Coordinates with SEC-007 (rotation): advertise current + next fingerprint so
  a cert roll doesn't break pinning.
- Keep the self-signed cert generation; only the *verification* changes.
