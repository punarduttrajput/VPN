# AND-003 — Kill-switch toggle is a silent no-op

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M1 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR3 |
| **Area** | `FerrumVpnService.kt`, `ui/SettingsScreen.kt`, `VpnViewModel.kt` |

## Problem

`SettingsScreen` renders a **Kill switch** toggle ("Block traffic when tunnel is
down"), persisted to prefs and shown as a real control. But the service handles
`ClientEvent.TrafficBlocked` as a no-op
(`FerrumVpnService.kt:145` — `/* no OS-level enforcement on Android */`). A
security control that silently does nothing is worse than not offering it —
users believe they're protected when they aren't.

Android's actual mechanism is system **always-on VPN + "Block connections
without VPN" (lockdown)**, which an app cannot toggle programmatically but can
guide the user to.

## Acceptance criteria

- [ ] The kill-switch UI no longer implies an enforcement the app doesn't
      provide.
- [ ] Chosen resolution (pick one, document why):
      - replace the toggle with a link/CTA to Android's always-on + lockdown
        settings and explanatory copy; **or**
      - implement a real in-tunnel enforcement and keep the toggle.
- [ ] AC3: the control either enforces or accurately describes lockdown.

## Implementation notes

- Recommended: deep-link to `Settings.ACTION_VPN_SETTINGS` and explain that
  lockdown is the OS-level kill-switch; keep the app's own toggle only if it
  drives a real behavior.
- Coordinate copy with the desktop's honest leak-protection chips so the product
  story is consistent.
