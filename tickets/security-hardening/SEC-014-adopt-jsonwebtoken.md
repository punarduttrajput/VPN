# SEC-014 — Replace hand-rolled JWT verification; tighten claim policy and admin audience

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M4 (pre-audit gate) |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR1/FR9 · [audit plan](../../docs/security/audit-plan.md) P5, P6 |
| **Area** | `ferrum-coordinator` (`auth.rs`, `admin.rs`, `main.rs`) |

## Problem

OIDC bearer tokens are verified by ~290 lines of hand-written code on `ring`
(RS256/ES256 against a static JWKS). It was written that way only because the
original dev host was offline; cargo is online now (CLAUDE.md env note). The
alg/key-type pairing is sound (no `none`/HS256 confusion), but:

- `exp` is optional, so a token without it **never expires**.
- A missing `sub` defaults to `""`, so all such tokens share one SEC-002
  identity (`oidc:`).
- `exp + LEEWAY_SECS` is unchecked `u64` arithmetic.
- No `iat`/max-age, `typ` or `crit` handling; JWK `use`/`alg`/`key_ops`
  ignored; no JWKS refresh.
- Untested: RS256, `nbf`, `kid` selection.
- Admin tokens share the device issuer/audience and differ only by an `admin`
  tag, and tags fall back to the IdP's `groups` claim, so an IdP group called
  `admin` grants the admin API. `authorize()` is called per handler rather than
  as middleware.

## Acceptance criteria

- [x] Signature and standard-claim validation use `jsonwebtoken` (algorithms
      pinned to RS256/ES256, `iss`/`aud`/`exp`/`nbf` validated, leeway kept at
      60 s). The hand-rolled verifier is deleted; Ferrum's tag/subject policy
      stays as a thin layer on top. *(**jsonwebtoken 9.3 on its `ring`
      backend**: 10+/11 have no ring backend, and 11's `rust_crypto` backend
      can't resolve next to boringtun 0.6's exact `x25519-dalek =2.0.0-rc.3` pin.
      Move to 11.x with a boringtun 0.7 upgrade. The algorithm is pinned by the
      selected key, not the token header. JWKS entries with `use: enc` or a
      mismatched `alg` are skipped.)*
- [x] `exp` required; non-empty `sub` required. *(`iss` and `aud` too.)*
- [x] Admin API requires a **separate** audience (e.g. `--admin-audience`,
      defaulting to `<audience>-admin`) *and* the admin role; the role comes
      only from the `tags` claim, never the `groups` fallback. Enforced by an
      axum middleware layer on every `/api` route. *(`resolve_admin_audience`
      refuses an admin audience equal to the device one; `verify_role`;
      `require_admin` route layer.)*
- [x] Existing auth tests pass unchanged, plus new ones: RS256, missing `exp`,
      missing `sub`, `nbf` in the future, `kid` selection, device token refused
      by the admin API.

**Operator-visible:** admin tokens minted for the device audience stop working;
re-mint them for the admin audience. `deploy/oracle-vm` gains
`OIDC_ADMIN_AUDIENCE=ferrum-panel` (README has an upgrade note).

## Implementation notes

- `jsonwebtoken` is not in the tree yet; check its current major version's
  crypto backend (ring vs aws-lc) against the workspace's `ring` usage before
  adding it.
- Keep `Jwks`/`OidcVerifier` as the public types so `main.rs` and tests change
  minimally.
