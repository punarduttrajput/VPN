# SEC-002 — Bind auth token to WireGuard public key

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Milestone** | M1 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR2 |
| **Area** | `ferrum-coordinator` (registry + auth) |

## Problem

On the OIDC path, `register_device` derives tags from the verified token but
does not bind the token/identity to the presented `public_key`
(`crates/coordinator/src/service.rs` register flow + `registry.rs::register`).
A valid token — leaked, or belonging to a low-privilege device — can be replayed
to register an **attacker-chosen** public key with the token's tags. This is an
identity-substitution / privilege gap. Competitors bind node identity to the
auth session.

## Acceptance criteria

- [ ] First registration for a verified identity records the identity→public_key
      binding.
- [ ] A later registration for the same identity with a *different* key is
      rejected (`FailedPrecondition`) unless it goes through an authorized
      rotation path.
- [ ] Covers both the OIDC path and the mTLS path.
- [ ] Test: valid token cannot register a second/unbound key; a key swap is
      rejected; an authorized rotation succeeds.

## Implementation notes

- Add an identity→key map to the registry (persisted under the `sqlite`
  feature so the binding survives restart).
- Derive the identity from the verified claim (`sub`, or the mTLS cert subject).
- Define the "authorized rotation" path narrowly — a claim/flag, not just
  presenting a new key.

## Dependencies

Interacts with SEC-001 (authenticated mode). In open mode there is no identity
to bind to; document that open mode has no key-binding guarantee.
