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

- [x] Target policy, deny by default: loopback, unspecified, link-local,
      RFC 1918 / ULA, multicast and broadcast are refused unless explicitly
      allowed; an optional allowlist of CIDRs/ports. *(`TargetPolicy`:
      `public_only()` by default, which also refuses CGNAT, 0/8, 240/4 and
      IPv4-mapped forms; `allowlist([...])` opens exactly the listed CIDRs.
      Unspecified, multicast, broadcast and port 0 are never relayed. No
      per-port allowlist: CIDRs only.)*
- [x] Client authentication option (a bearer token checked against the
      coordinator's verifier, or an mTLS client cert) and a documented stance
      for "open mode". *(`ProxyAuthorizer` hook over the `authorization` bearer
      token, which can wrap the coordinator's verifier or a shared secret. Client
      side: `MasqueTransport::connect_with_token`,
      `MasqueMeshTransport::with_bearer_token`. Open mode is documented in the
      module docs and warned at `serve()` start.)*
- [x] The request method and `:protocol = connect-udp` are validated.
- [x] Tests: a loopback target is refused; an allowed public target works; an
      unauthenticated client is refused when auth is on. *("Allowed target
      works" is covered by the allowlisted loopback echo tests, since there's no
      public echo in CI; public acceptance by the default policy is unit-tested.)*

**Context found while implementing:** `MasqueProxy` has no production entry
point: nothing in the CLI or `deploy/` runs it, only tests. So no deployed
proxy was open; this hardens the type for anyone embedding it. Follow-up: a
`ferrum masque-proxy` command, plus CLI/config wiring for the client token,
when a production proxy is needed.
