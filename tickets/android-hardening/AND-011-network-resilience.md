# AND-011 — No underlying-network handling / MTU; poor Wi-Fi↔cellular handoff

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR7 |
| **Area** | `FerrumVpnService.kt` |

## Problem

`buildVpnInterface` never calls `setUnderlyingNetworks(...)` or `setMtu(...)`, and
the service doesn't observe connectivity changes. Two issues:

1. **Handoff.** When the device moves between Wi-Fi and cellular, the tunnel's
   underlying network isn't updated, degrading or stalling the connection until
   the core's reconnect kicks in — a visible drop mainstream VPNs avoid.
2. **MTU.** The interface uses the default MTU. With QUIC/MASQUE framing overhead
   (the CLI/desktop clamp the inner TUN to 1100), an unset MTU risks
   fragmentation/black-holing on those transports.

## Acceptance criteria

- [ ] The service registers a `ConnectivityManager.NetworkCallback` and calls
      `setUnderlyingNetworks(...)` as the active network changes.
- [ ] `setMtu(...)` is set to match the transport (1100 for QUIC/MASQUE, the
      UDP default otherwise), consistent with the CLI/desktop.
- [ ] Wi-Fi↔cellular handoff keeps the session alive without a full reconnect
      where possible.

## Implementation notes

- Reuse the transport-mode signal already threaded for DNS/relay to pick the MTU.
- Unregister the network callback in the shared teardown (AND-002).
