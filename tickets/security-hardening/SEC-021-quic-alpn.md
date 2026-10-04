# SEC-021 — Plain and mesh QUIC offer no ALPN

| Field | Value |
|---|---|
| **Severity** | Low |
| **Milestone** | M4 |
| **PRD** | [phase-2-transport-obfuscation.md](../../PRD/phase-2-transport-obfuscation.md) (NFR3) · [security-hardening.md](../../PRD/security-hardening.md) FR9 |
| **Area** | `ferrum-transport` (`tls.rs`, `quic.rs`, `quic_mesh.rs`) |
| **Found by** | SEC-020 ([threat model](../../docs/security/threat-model.md) §5) |

## Problem

After SEC-020 the cleartext ClientHello no longer names the product, but
point-to-point QUIC and the QUIC mesh still offer **no ALPN at all**. Web QUIC
always offers `h3`, so an ALPN-less QUIC ClientHello is a cheap passive tell.
MASQUE already offers `h3` and is unaffected.

## Acceptance criteria

- [x] Point-to-point QUIC and the QUIC mesh offer and accept ALPN `h3` (one
      shared constant with MASQUE). *(`tls::QUIC_ALPN`, used by all six
      client/server config sites.)*
- [x] The wire incompatibility is pinned down by a test and documented. *(In
      QUIC mode rustls refuses any handshake where only one side uses ALPN
      (RFC 9001 §8.1): an upgraded server rejects an ALPN-less client, and an
      ALPN-less server rejects an upgraded client. No server setting accepts
      both. Rolled out as a **flag day**: upgrade all QUIC nodes together, as
      with SEC-003's relay change. `quic::client_without_alpn_is_refused`
      covers it. UDP and MASQUE are unaffected.)*
- [x] A test shows plain QUIC negotiates `h3`.
      *(`quic::quic_negotiates_h3_alpn` reads the protocol the server
      actually negotiated.)*
- [x] Threat model §5 updated.

## Out of scope (decided)

- **Active probing.** A prober that completes an `h3` handshake still gets no
  HTTP/3 SETTINGS or responses from a plain/mesh QUIC node, unlike a real
  HTTP/3 server. Making nodes answer plausibly would mean hand-rolled HTTP/3
  framing for the audit to review, so it stays a documented residual for now.
