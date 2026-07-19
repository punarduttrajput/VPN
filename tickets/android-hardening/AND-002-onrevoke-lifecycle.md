# AND-002 — `onRevoke()` not handled: zombie tunnel on revoke

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M1 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR2 |
| **Area** | `FerrumVpnService.kt` |

## Problem

`FerrumVpnService` never overrides `VpnService.onRevoke()`. Android calls
`onRevoke()` when the VPN is revoked out from under the app — another VPN app
starts, or the user disables it in system Settings. Without handling it, the
service keeps its coroutine scope, `FfiFerrumClient`, and TUN
`ParcelFileDescriptor` alive around a tunnel the OS has already torn down — a
resource leak and a confusing state (UI still says "Connected").

## Acceptance criteria

- [ ] `onRevoke()` stops the data plane, closes the TUN, cancels the scope, and
      sets state to `DISCONNECTED`.
- [ ] Teardown is a single idempotent path shared with `stopTunnel()`/
      `onDestroy()` (no double-free, no missed cleanup).
- [ ] AC2: toggling the OS VPN off tears down cleanly; logcat shows the revoke
      path.

## Implementation notes

- Extract the current `stopTunnel()` body into one `tearDown()` and call it from
  `onRevoke`, `onDestroy`, and the `ACTION_STOP` branch.
- `onRevoke` runs on the main thread — keep the teardown non-blocking (the
  coroutine cancel + `stop()`/`close()` are fine).
