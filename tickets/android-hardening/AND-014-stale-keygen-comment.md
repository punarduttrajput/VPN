# AND-014 — Stale/misleading keygen comment

| Field | Value |
|---|---|
| **Severity** | Low |
| **Milestone** | M3 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) M3 (doc cleanup) |
| **Area** | `ui/SettingsScreen.kt` |

## Problem

`generateAndStoreKey` (`SettingsScreen.kt:169–179`) carries a comment block
describing a BouncyCastle/conscrypt "Curve25519 keygen shim" and "For now:
generate with a simple Curve25519 keygen shim" — but the code actually calls
`Curve25519Keygen.generate()`, which delegates to the Rust `generateKeypair()`
uniffi function (the correct, shared x25519-dalek path). The comment describes an
implementation that no longer exists and contradicts the code.

## Acceptance criteria

- [ ] The comment is corrected to describe the actual behavior (delegates to the
      Rust uniffi `generateKeypair`, shared crypto path across platforms).
- [ ] No stale "TODO/for now/shim" language remains.

## Implementation notes

- Trivial doc fix; bundle with another M3 change. Left as its own ticket so it
  isn't lost.
