# AND-009 — No per-app split tunneling / own-app exclusion

| Field | Value |
|---|---|
| **Severity** | Medium (stretch) |
| **Milestone** | M3 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) Non-Goals / stretch |
| **Area** | `FerrumVpnService.kt`, Settings UI |

## Problem

`buildVpnInterface` routes everything (`0.0.0.0/0`, optionally `::/0`) with no
`addAllowedApplication`/`addDisallowedApplication`. Two consequences:

1. No per-app split tunneling — a feature users expect from mainstream VPNs
   (route only certain apps, or exclude some).
2. The app doesn't exclude **itself** from the tunnel; for a mesh client this is
   usually fine, but it should be a deliberate decision (avoids potential
   routing loops for the control/data sockets).

## Acceptance criteria

- [ ] A Settings surface to include/exclude specific apps (allow-list or
      deny-list mode).
- [ ] The selection is applied via `addAllowedApplication`/
      `addDisallowedApplication` and persisted.
- [ ] A documented decision on whether the Ferrum app itself is excluded.

## Implementation notes

- Stretch/optional this cycle (PRD non-goal as a gate). Land the own-app
  exclusion decision even if the full per-app UI is deferred.
- Enumerate installed apps with the package manager; guard against the empty
  allow-list footgun (empty allow-list = nothing tunneled).
