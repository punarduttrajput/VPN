# SEC-015 — MASQUE proxy is an open UDP proxy

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M4 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR9 · [audit plan](../../docs/security/audit-plan.md) P9 |
| **Area** | `ferrum-transport` (`masque.rs`) |

## Problem

The built-in CONNECT-UDP proxy (RFC 9298) accepts any client and relays to any
`host:port` in the request path. There is no client authentication and no
target policy: loopback, RFC 1918, link-local and the proxy host's own
services are all reachable. Anyone who can reach the proxy can use it as an
SSRF hop into the proxy's network or as a UDP reflector. It also doesn't
validate the request method or `:protocol`, and binds outbound sockets to IPv4
only.

## Acceptance criteria

- [ ] Target policy, deny by default: loopback, unspecified, link-local,
      RFC 1918 / ULA, multicast and broadcast are refused unless explicitly
      allowed; an optional allowlist of CIDRs/ports.
- [ ] Client authentication option (a bearer token checked against the
      coordinator's verifier, or an mTLS client cert) and a documented stance
      for "open mode".
- [ ] The request method and `:protocol = connect-udp` are validated.
- [ ] Tests: a loopback target is refused; an allowed public target works; an
      unauthenticated client is refused when auth is on.
