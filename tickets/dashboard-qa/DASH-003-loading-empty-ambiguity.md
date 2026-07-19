# DASH-003 — Loading and empty states are indistinguishable

| Field | Value |
|---|---|
| **Severity** | High |
| **Type** | UX / Correctness |
| **Milestone** | M1 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR3 |
| **Area** | `dashboard/dashboard.component.html`, `.ts` |

## Repro

1. Throttle the network (slow `/api/devices`).
2. Load or Refresh the Dashboard and watch during the in-flight window.

**Expected:** a loading indicator; no "empty" messaging until data actually
arrives.
**Actual:** `loading` only disables the Refresh button
(`dashboard.component.html:2`); the template has no spinner/skeleton. While
loading, `deviceCount()` is `0` and the four cards show `0`, and
"No devices registered." renders (`dashboard.component.html:33–34`) — identical
to a genuinely empty coordinator. Every load flashes a false "empty" state.

## Acceptance criteria

- [ ] A loading indicator (skeleton or spinner) shows while data is in flight,
      visually distinct from the empty state.
- [ ] "No devices registered." appears only **after** a successful load returns
      zero devices — never during loading (AC3).
- [ ] Stat values show a loading placeholder (not `0`) until data arrives.

## Implementation notes

- Gate the empty message on `!loading() && recentDevices().length === 0`.
- Show `—`/skeleton for stat values while `loading()`.
- Distinguish "never loaded yet" from "loaded, empty" (a `loaded` flag or
  nullable signals) so the first paint isn't a false empty.
