# AND-012 — Private key usable with no device-auth gate

| Field | Value |
|---|---|
| **Severity** | Medium (stretch) |
| **Milestone** | M3 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR9 |
| **Area** | `KeystoreHelper.kt`, Settings UI |

## Problem

`KeystoreHelper` builds its master key with
`setUserAuthenticationRequired(false)` (`KeystoreHelper.kt:23`), so the WireGuard
private key and OIDC token are usable by anyone with access to an unlocked
device — including background service starts. Competitors offer an optional
"require biometric/device auth to connect." This is opt-in hardening, not a
default change.

## Acceptance criteria

- [ ] An opt-in Settings toggle "Require device authentication to connect".
- [ ] When enabled, the key/credentials require user authentication
      (`setUserAuthenticationRequired(true)` with an appropriate validity
      window), prompting biometric/device-credential before connect.
- [ ] Default remains off (no regression for existing users).

## Implementation notes

- StrongBox-backed where available; fall back gracefully on devices without it.
- Consider the always-on/system-start path (AND-001): a key requiring
  interactive auth can't be used by a background always-on start — document the
  interaction (this toggle likely disables silent always-on reconnect).
