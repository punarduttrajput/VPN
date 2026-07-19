# DASH-007 — Status banner persists across navigation; no dismiss

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Type** | UX |
| **Milestone** | M2 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR5 |
| **Area** | `shell/shell.component.*`, `core/status.service.ts` |

## Repro

1. On the Dashboard, cause a load failure → error banner shows.
2. Navigate to Devices, then Policy.

**Expected:** the stale Dashboard error doesn't follow you; you can dismiss it.
**Actual:** `StatusService.message` is a root signal only cleared on **sign-out**
(`shell.component.ts:22`, `status.service.ts:19`). The banner has no auto-dismiss
and no close button (`shell.component.html:7–9`), so a Dashboard error persists
verbatim across every route until sign-out — showing an irrelevant message on
unrelated screens.

## Acceptance criteria

- [ ] The banner auto-dismisses after a timeout **and/or** clears on route
      change (AC5).
- [ ] A manual dismiss (×) control.
- [ ] Success and error may differ (e.g. success auto-dismisses faster; errors
      stay until dismissed or navigation) — document the chosen policy.

## Implementation notes

- Clear on `NavigationEnd` in the shell, or add a `show(text, kind, ttlMs?)` with
  an auto-clear timer in `StatusService` (cancel on a newer message).
- Don't clear a banner that a destination screen just set — order the
  navigation-clear before the new screen's own `status.show`.
