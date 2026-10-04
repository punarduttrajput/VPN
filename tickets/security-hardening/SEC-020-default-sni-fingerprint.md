# SEC-020 — Default TLS SNI `ferrum` names the product to on-path DPI

| Field | Value |
|---|---|
| **Severity** | Low |
| **Milestone** | M4 |
| **PRD** | [phase-2-transport-obfuscation.md](../../PRD/phase-2-transport-obfuscation.md) (FR3/NFR3) · [security-hardening.md](../../PRD/security-hardening.md) FR9 |
| **Area** | `ferrum-transport` (`tls.rs`, `quic_mesh.rs`), `ferrum-cli` |
| **Found by** | SEC-010 threat model ([docs/security/threat-model.md](../../docs/security/threat-model.md) §5) |

## Problem

QUIC and MASQUE are meant to look like ordinary web QUIC / HTTP-3. But the TLS
ClientHello, which is sent in the clear, carries an SNI that names the product:

- The QUIC mesh always dials with `tls::SERVER_NAME` (`"ferrum"`,
  `quic_mesh.rs` `connect_with(…, SERVER_NAME)`). There is no setting to
  change it.
- Point-to-point QUIC and MASQUE use `[transport] server_name`, which defaults
  to `"ferrum"` (`cli/src/main.rs`, `.unwrap_or("ferrum")`). The README and
  example configs also suggest `server_name = "ferrum"`.
- The self-signed certificate's SAN is also `ferrum`. That part is encrypted in
  TLS 1.3, so only an active prober that completes a handshake sees it.

A single DPI rule matching `SNI == "ferrum"` therefore identifies and blocks
Ferrum's "camouflaged" transports. Confidentiality isn't affected: the payload
is WireGuard, and the outer layer is pinned (SEC-004).

## Acceptance criteria

- [ ] The QUIC mesh's SNI is configurable, and its default doesn't name the
      product. Options: no SNI at all (an IP-literal dial; check this is
      common enough for QUIC to blend in), or an operator-chosen plausible
      hostname.
- [ ] The point-to-point QUIC and MASQUE defaults change the same way. The
      README and `config*.example.toml` stop recommending `ferrum`.
- [ ] Verification doesn't depend on the name. `PinnedVerifier` already ignores
      `server_name` (it pins the key), so add a test that a non-`ferrum` SNI
      still connects.
- [ ] The certificate SAN no longer names the product (or this is justified as
      only visible to active probers that already know to dial the node).
- [ ] Threat model §5 updated.

## Implementation notes

- Changing the dialed SNI doesn't break old servers: the pinned verifier
  ignores the name, and the server presents one fixed cert regardless of SNI.
- Pair with the Phase 2 nDPI/Wireshark DPI check (NFR3) once a Linux box is
  available.
