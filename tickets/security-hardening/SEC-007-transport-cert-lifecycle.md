# SEC-007 — Static self-signed transport certs: no rotation/revocation

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M3 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR7 |
| **Area** | `ferrum-transport`, `ferrum-coordinator` |

## Problem

The QUIC/MASQUE transports use static self-signed certs with (today) permissive
verification. Once SEC-004 pins them, there is no rotation or revocation story:
rolling a cert would break every pinned client. Fine for a research build; a gap
for production trust.

## Acceptance criteria

- [x] The coordinator can advertise a **set** of accepted transport cert
      fingerprints (current + next) so pinning survives a roll.
      *(`tls_next_pins` on `RegisterDeviceRequest`/`PeerInfo`,
      `new_tls_next_pins` on `RotateKeyRequest`; validated, deduplicated, at
      most 4; persisted in SQLite.)*
- [x] Clients accept any advertised fingerprint, enabling zero-downtime
      rotation. *(`build_mesh_peers` pins current ∪ next. Nodes announce via
      `transport.announce_next_pins` / `FerrumClient::set_tls_next_fingerprints`
      and complete the roll with `rotate_key_with_pins`.)*
- [ ] (Optional/stretch) Short-lived transport certs minted per coordinator
      config. *(Not done: mesh-node certs are derived from the WireGuard key, so
      their lifetime is the key's.)*
- [x] Test: a client mid-rotation (server presents the "next" cert) still
      connects; a fully-unlisted cert is rejected.
      *(`quic_mesh_accepts_a_peer_that_rolled_to_its_announced_next_key`.)*

**Runbook:** [deploy/transport-cert-rotation.md](../../deploy/transport-cert-rotation.md).
**Follow-ups:** a `ferrum rotate-key` CLI command (step 4 of the mesh runbook
is API-only today); coordinator-advertised pins for the MASQUE proxy (still
client-local `cert_pins`).

## Implementation notes

- Extends the SEC-004 network-map advertisement from a single fingerprint to a
  small list.
- Document the operational rotation runbook (advertise next → roll servers →
  drop old) in the deployment README.

## Dependencies

Depends on SEC-004 (pinning must exist before rotation is meaningful).
