# SEC-013 — Coordinator RPCs act on any caller-supplied key; revocation isn't durable

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M4 (pre-audit gate) |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR2/FR9 · [audit plan](../../docs/security/audit-plan.md) P4 |
| **Area** | `ferrum-coordinator` (`service.rs`, `registry.rs`, `admin.rs`) |

## Problem

SEC-002 binds an authenticated identity (`oidc:<sub>` / `mtls:<fp>`) to its
first public key, but only `RegisterDevice` and `RotateKey` enforce it. The
other RPCs trust the `public_key` in the request:

- `PublishCandidates`: any authenticated device can overwrite **another**
  device's ICE candidates, steering peers' probes to attacker addresses.
- `GetNetworkMap` / `WatchNetworkMap`: any authenticated device can read the
  ACL-filtered map of **another** device (its peers, endpoints, candidates).
- `RelayHeartbeat`: any authenticated caller, including an ordinary device,
  can announce a relay, which the coordinator advertises to the **whole
  mesh**. Payloads stay WireGuard-encrypted, but a rogue relay sees metadata
  and can drop traffic.
- Admin revoke (`Registry::remove`) drops the device but not its identity
  binding, and there is no denylist, so the same token re-registers at once.

## Acceptance criteria

- [x] When the caller is authenticated, `PublishCandidates`, `GetNetworkMap`
      and `WatchNetworkMap` require `public_key` to be the key bound to the
      caller's identity (`permission_denied` otherwise). Open mode is
      unchanged. *(`authorize_key`. A revoked key is refused in open mode too.)*
- [x] `RelayHeartbeat` requires a relay role (a verified `relay` tag/claim, or
      a dedicated relay mTLS identity). Ordinary device tokens are refused.
      *(`RELAY_TAG`, or an identity in `--relay-identity mtls:<fp>,oidc:<sub>`.)*
- [x] Revocation is durable: revoke removes the identity binding and records
      the key (and optionally the identity) in a persisted denylist that
      `RegisterDevice`/`RotateKey` consult. *(`Registry::revoke`: key **and**
      bound identity denylisted, persisted in SQLite; `unrevoke` /
      `POST /api/devices/unrevoke` lifts both. Also closes the revoked device's
      open watch stream: before this, an unregistered key's map fell back to
      empty tags, i.e. the full mesh under allow-all.)*
- [x] Tests for each: a second authenticated device cannot publish/read/watch
      as the first; a device token cannot heartbeat; a revoked device cannot
      re-register with the same token.

**Operator-visible change:** with auth on, a self-announcing relay
(`ferrum relay --coordinator … --token-file …`) needs a token tagged `relay`
(`mint-token.py mint --tags relay …`) or an allowlisted identity. A static
`--relay`, as in `deploy/oracle-vm`, is unaffected.

## Implementation notes

- `bound_identity()` already derives the identity; add a
  `Registry::key_for_identity` lookup.
- Coordinate with SEC-006 (rate limits) and SEC-014 (claim policy): the relay
  role is a claim-policy decision.
