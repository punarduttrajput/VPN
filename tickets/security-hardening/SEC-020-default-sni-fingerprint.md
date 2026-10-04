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

- [x] The QUIC mesh's SNI is configurable, and its default doesn't name the
      product. Options: no SNI at all (an IP-literal dial; check this is
      common enough for QUIC to blend in), or an operator-chosen plausible
      hostname. *(Both: no SNI by default via `tls::dial_name`, which dials by
      the peer's IP literal so rustls omits the extension, and
      `QuicMeshTransport::with_server_name` for an operator hostname, wired from
      `[transport] server_name` in the CLI and desktop. No-SNI was chosen as the
      default because it names nothing; a fixed "plausible" hostname shipped by
      default would just be a new constant to match. A ClientHello without
      SNI is less common than one with it, which the threat model records.)*
- [x] The point-to-point QUIC and MASQUE defaults change the same way. The
      README and `config*.example.toml` stop recommending `ferrum`. *(MASQUE
      also brackets an IPv6 literal in the HTTP/3 `:authority` while dialing
      the bare address. README has a "TLS server name" note, including that a
      third-party MASQUE proxy usually needs its real hostname;
      `verify-linux.sh` now exercises the default.)*
- [x] Verification doesn't depend on the name. `PinnedVerifier` already ignores
      `server_name` (it pins the key), so add a test that a non-`ferrum` SNI
      still connects. *(`quic::sni_is_absent_by_default_and_configurable`
      reads the SNI the server actually received: `None` by default,
      `cdn.example.net` when configured. Mutation-checked: restoring the old
      default makes it fail with `Some("ferrum")`. The MASQUE tests now dial
      with an IPv4 literal, an IPv6 literal and a hostname.)*
- [x] The certificate SAN no longer names the product (or this is justified as
      only visible to active probers that already know to dial the node).
      *(Both cert builders now use an empty subject and no SAN. That also drops
      rcgen's default `CN=rcgen self signed cert`, a scanner-matchable string
      the ticket didn't mention. Pins hash only the public key, so existing
      pins are unchanged; `tls::certs_name_nothing` checks the DER.)*
- [x] Threat model §5 updated. *(Also records what's still distinguishable:
      plain/mesh QUIC offers no ALPN, unlike web QUIC's `h3`. Matching it
      would need the in-mesh server to behave plausibly to an `h3` prober too,
      so it's a follow-up, not part of this ticket.)*

## Implementation notes

- Changing the dialed SNI doesn't break old servers: the pinned verifier
  ignores the name, and the server presents one fixed cert regardless of SNI.
- Pair with the Phase 2 nDPI/Wireshark DPI check (NFR3) once a Linux box is
  available.
