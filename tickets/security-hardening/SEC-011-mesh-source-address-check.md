# SEC-011 — Decrypted inbound packets aren't checked against `allowed_ips`

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M4 (pre-audit gate) |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR9 · [audit plan](../../docs/security/audit-plan.md) P1 |
| **Area** | `ferrum-tunnel` (`mesh.rs` `handle_inbound`, `runner.rs`) |

## Problem

After a datagram decrypts under peer *i*'s WireGuard session, the plaintext is
written to the TUN as is. boringtun reports the inner packet's source address
(`Action::WriteToTun(pkt, ip)`), but both the mesh runner
(`mesh.rs:328`) and the point-to-point runner (`runner.rs:182`) discard it as
`_ip`.

WireGuard's crypto-routing rule is that a packet decrypted from peer *i* is
accepted only if its inner source is inside peer *i*'s `allowed_ips`. Without
it, any authenticated peer can send packets that claim another peer's tunnel
IP (or any address), which defeats IP-based trust on the receiving host and the
per-device intent of the coordinator's ACL.

## Acceptance criteria

- [ ] `handle_inbound` drops (and debug-logs, without addresses — NFR5) a
      decrypted packet whose source is not within the decrypting peer's
      `allowed_ips`. IPv4 and IPv6 are both covered.
- [ ] The point-to-point runner applies the same check against its configured
      peer's allowed IPs.
- [ ] Aggregate counter for dropped spoofed packets.
- [ ] Tests: peer A sending an inner packet with peer B's source is dropped;
      its own source is delivered; relay and direct underlays both covered.

## Implementation notes

- `MeshPeer::allowed_ips` is already present (used for outbound routing,
  `peer_for`); reuse `Cidr::contains`.
- Leave the roaming and path-state updates as they are. The packet did decrypt,
  so the path is genuinely alive; only the TUN write is refused.
