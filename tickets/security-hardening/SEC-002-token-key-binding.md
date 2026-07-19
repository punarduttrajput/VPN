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

- [x] First registration for a verified identity records the identity→public_key
      binding.
- [x] A later registration for the same identity with a *different* key is
      rejected (`FailedPrecondition`) unless it goes through an authorized
      rotation path.
- [x] Covers both the OIDC path and the mTLS path.
- [x] Test: valid token cannot register a second/unbound key; a key swap is
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

## Resolution (2026-07-19)

`Registry` gained `identity_keys: HashMap<String, String>` (namespaced
`oidc:<sub>` / `mtls:<fingerprint>` → public key) plus `bind_identity` /
`rebind_identity`, persisted under `sqlite` via two new `Store` trait methods
(`load_bindings`/`upsert_binding`, default no-op for `MemoryStore`). The
identity for the mTLS path is the **SHA-256 fingerprint of the client's leaf
certificate DER** (via `tonic::Request::peer_certs()`, gated on the `mtls`
feature, which now also pulls `ring` for the digest) rather than a parsed
certificate *subject* — deliberately: it needs no X.509 parsing (no new
parsing dependency, no attack surface in getting subject-string handling
right) and is strictly more precise than a subject CN, which an operator's CA
could in principle reissue to a different key holder. mTLS carries no tags
claim, so tags remain self-declared under mTLS-only auth (unchanged
behavior) — only the key binding is enforced for that path.

The "authorized rotation path" is the existing `rotate_key` RPC:
`rebind_identity` requires the caller's identity to already own
`old_public_key` (rejecting a rotation of a key it doesn't hold, and — a
related gap fixed as part of this work — `rotate_key` previously trusted any
valid token to rotate *any* device's key, not just its own), with a
first-claim allowance for an identity that has never been bound before
(covers a pre-SEC-002 legacy device rotated for the first time).
