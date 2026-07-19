# DASH-001 — Dashboard never auto-refreshes; data goes stale

| Field | Value |
|---|---|
| **Severity** | High |
| **Type** | Functional |
| **Milestone** | M1 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR1 |
| **Area** | `dashboard/dashboard.component.ts` |

## Repro

1. Open the Dashboard; note the device count.
2. From another client, register (or revoke) a device with the coordinator.
3. Watch the Dashboard.

**Expected:** the counts and recent-devices list update to reflect the change
within a short interval.
**Actual:** nothing changes. The Dashboard loads once in the constructor
(`refresh()` at `dashboard.component.ts:38–40`) and only reloads on a manual
**Refresh** click. An operator watching the overview sees stale numbers with no
indication they're stale.

## Acceptance criteria

- [ ] The Dashboard refreshes on a sensible interval while the view is active.
- [ ] Polling pauses when the route/tab is not visible (no needless load).
- [ ] Reflected within the interval without a manual reload (AC1).
- [ ] Paired with DASH-009 (a visible last-updated time).

## Implementation notes

- An RxJS `timer(...)`/`interval(...)` piped into the same `forkJoin`, torn down
  with `takeUntilDestroyed` and gated on document visibility / router-active.
- Keep the manual Refresh button as an override.
- Confirm interval with the coordinator owner; `/api/devices` + `/api/policy` are
  cheap at admin scale.
